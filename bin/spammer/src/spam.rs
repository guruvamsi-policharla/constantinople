use crate::shared::{
    TransactionState, accept_transaction, build_signed_transaction_bytes,
    fetch_transaction_statuses, transaction_hash_hex, tx_url,
};
use commonware_cryptography::{Sha256, Signer, ed25519};
use commonware_utils::hex;
use constantinople_primitives::Address;
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, VecDeque},
    future::Future,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{task::JoinSet, time};

const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const INITIAL_RETRY_BACKOFF: Duration = Duration::from_millis(100);
const MEMPOOL_FULL_RETRY_BACKOFF: Duration = Duration::from_secs(1);
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(5);
const STATUS_POLL_INTERVAL: Duration = Duration::from_secs(1);
const STATUS_POLL_BATCH_SIZE: usize = 32_768;
const MAX_SUBMISSION_TASKS_PER_ENDPOINT: usize = 256;

#[derive(Debug)]
pub struct Args {
    count: NonZeroUsize,
    endpoints: Vec<String>,
    seed_start: u64,
    nonce: u64,
}

impl Args {
    pub(crate) fn new(
        count: usize,
        endpoints: Vec<String>,
        seed_start: u64,
        nonce: u64,
    ) -> Result<Self, String> {
        let count = NonZeroUsize::new(count).ok_or_else(|| "count must be non-zero".to_string())?;
        if endpoints.is_empty() {
            return Err("at least one endpoint is required".to_string());
        }

        Ok(Self {
            count,
            endpoints,
            seed_start,
            nonce,
        })
    }

    #[cfg(test)]
    pub(crate) fn endpoints(&self) -> &[String] {
        &self.endpoints
    }

    #[cfg(test)]
    pub(crate) const fn count(&self) -> NonZeroUsize {
        self.count
    }

    #[cfg(test)]
    pub(crate) const fn seed_start(&self) -> u64 {
        self.seed_start
    }

    #[cfg(test)]
    pub(crate) const fn nonce(&self) -> u64 {
        self.nonce
    }
}

#[derive(Debug, Clone)]
struct RingAccount {
    seed: u64,
    from: Address,
    to: Address,
    endpoint_index: usize,
}

#[derive(Debug, Clone)]
struct SenderState {
    account: RingAccount,
    next_nonce: u64,
    pending_tx_hash: Option<String>,
    retry_backoff: Duration,
    queued_ready: bool,
}

#[derive(Debug)]
struct EndpointState {
    endpoint: String,
    sender_indices: Vec<usize>,
    ready: VecDeque<usize>,
    delayed: BinaryHeap<Reverse<(time::Instant, usize)>>,
    submission_tasks: usize,
    completed: usize,
    failed: usize,
}

impl EndpointState {
    fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            sender_indices: Vec::new(),
            ready: VecDeque::new(),
            delayed: BinaryHeap::new(),
            submission_tasks: 0,
            completed: 0,
            failed: 0,
        }
    }
}

#[derive(Debug)]
struct SubmissionOutcome {
    sender_index: usize,
    tx_hash: String,
    nonce: u64,
    result: Result<(), String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubmissionErrorKind {
    RetryRejected,
    RetryCheckStatus,
    Fatal,
}

fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .timeout(HTTP_REQUEST_TIMEOUT)
        .pool_max_idle_per_host(MAX_SUBMISSION_TASKS_PER_ENDPOINT)
        .build()
        .expect("spammer HTTP client should build")
}

fn build_ring_accounts(
    count: NonZeroUsize,
    seed_start: u64,
    endpoint_count: usize,
) -> Vec<RingAccount> {
    let count = count.get();

    let keys = (0..count)
        .map(|index| {
            let seed = seed_start + u64::try_from(index).expect("ring size exceeded u64");
            ed25519::PrivateKey::from_seed(seed)
        })
        .collect::<Vec<_>>();
    let addresses = keys
        .iter()
        .map(|key| Address::from_public_key(&mut Sha256::default(), &key.public_key()))
        .collect::<Vec<_>>();

    let mut accounts = Vec::with_capacity(count);
    for (index, _key) in keys.iter().enumerate() {
        let seed = seed_start + u64::try_from(index).expect("ring size exceeded u64");
        accounts.push(RingAccount {
            seed,
            from: addresses[index],
            to: addresses[(index + 1) % count],
            endpoint_index: index % endpoint_count,
        });
    }

    accounts
}

fn build_sender_states(accounts: Vec<RingAccount>, nonce: u64) -> Vec<SenderState> {
    accounts
        .into_iter()
        .map(|account| SenderState {
            account,
            next_nonce: nonce,
            pending_tx_hash: None,
            retry_backoff: INITIAL_RETRY_BACKOFF,
            queued_ready: false,
        })
        .collect()
}

fn build_sender_transaction_bytes(sender: &SenderState) -> Vec<u8> {
    let key = ed25519::PrivateKey::from_seed(sender.account.seed);
    build_signed_transaction_bytes(&key, sender.account.to, 1, sender.next_nonce)
}

fn build_endpoint_states(
    endpoints: Vec<String>,
    senders: &mut [SenderState],
) -> Vec<EndpointState> {
    let mut endpoint_states = endpoints
        .into_iter()
        .map(EndpointState::new)
        .collect::<Vec<_>>();

    for (sender_index, sender) in senders.iter_mut().enumerate() {
        let endpoint = &mut endpoint_states[sender.account.endpoint_index];
        endpoint.sender_indices.push(sender_index);
        endpoint.ready.push_back(sender_index);
        sender.queued_ready = true;
    }

    endpoint_states
}

fn next_retry_backoff(current: Duration, err: &str) -> Duration {
    let mut next = current.saturating_mul(2).min(MAX_RETRY_BACKOFF);
    if err.contains("error (503)")
        && err.contains("mempool full")
        && next < MEMPOOL_FULL_RETRY_BACKOFF
    {
        next = MEMPOOL_FULL_RETRY_BACKOFF;
    }
    next
}

fn classify_submission_error(err: &str) -> SubmissionErrorKind {
    if err.starts_with("request failed:") || err.starts_with("response body failed:") {
        return SubmissionErrorKind::RetryCheckStatus;
    }

    if ["408", "429", "500", "502", "503", "504"]
        .into_iter()
        .any(|code| err.contains(&format!("error ({code})")))
    {
        if err.contains("error (503)") && err.contains("mempool full") {
            return SubmissionErrorKind::RetryRejected;
        }

        return SubmissionErrorKind::RetryCheckStatus;
    }

    SubmissionErrorKind::Fatal
}

fn format_sender_failure(endpoint: &str, sender: &SenderState, nonce: u64, err: &str) -> String {
    let from = hex(sender.account.from.as_ref());
    let to = hex(sender.account.to.as_ref());
    format!("{endpoint} {from} -> {to} nonce={nonce}: {err}")
}

fn sender_is_ready(sender: &SenderState) -> bool {
    !sender.queued_ready && sender.pending_tx_hash.is_none()
}

fn schedule_sender_retry(
    endpoints: &mut [EndpointState],
    senders: &mut [SenderState],
    sender_index: usize,
    ready_at: time::Instant,
) {
    let endpoint_index = senders[sender_index].account.endpoint_index;
    senders[sender_index].queued_ready = true;
    endpoints[endpoint_index]
        .delayed
        .push(Reverse((ready_at, sender_index)));
}

fn activate_ready_senders(
    endpoints: &mut [EndpointState],
    senders: &mut [SenderState],
    now: time::Instant,
) {
    for endpoint in endpoints {
        while let Some(Reverse((ready_at, sender_index))) = endpoint.delayed.peek().copied() {
            if ready_at > now {
                break;
            }

            endpoint.delayed.pop();
            if senders[sender_index].pending_tx_hash.is_some() {
                senders[sender_index].queued_ready = false;
                continue;
            }

            endpoint.ready.push_back(sender_index);
        }
    }
}

fn spawn_submissions<Submit, SubmitFuture>(
    endpoints: &mut [EndpointState],
    senders: &mut [SenderState],
    tasks: &mut JoinSet<SubmissionOutcome>,
    client: &reqwest::Client,
    submit: &Submit,
) where
    Submit: Fn(reqwest::Client, String, Vec<u8>) -> SubmitFuture + Send + Sync + Clone + 'static,
    SubmitFuture: Future<Output = Result<String, String>> + Send + 'static,
{
    for endpoint in endpoints {
        while endpoint.submission_tasks < MAX_SUBMISSION_TASKS_PER_ENDPOINT {
            let Some(sender_index) = endpoint.ready.pop_front() else {
                break;
            };
            senders[sender_index].queued_ready = false;
            if senders[sender_index].pending_tx_hash.is_some() {
                continue;
            }

            let sender = &senders[sender_index];
            let nonce = sender.next_nonce;
            let tx_bytes = build_sender_transaction_bytes(sender);
            let tx_hash =
                transaction_hash_hex(&tx_bytes).expect("generated tx bytes should decode");
            let endpoint_url = endpoint.endpoint.clone();
            let client = client.clone();
            let submit = submit.clone();

            endpoint.submission_tasks += 1;
            tasks.spawn(async move {
                let result = submit(client, endpoint_url, tx_bytes)
                    .await
                    .map(|returned_hash| {
                        if returned_hash == tx_hash {
                            returned_hash
                        } else {
                            tx_hash.clone()
                        }
                    });
                SubmissionOutcome {
                    sender_index,
                    tx_hash,
                    nonce,
                    result: result.map(|_| ()),
                }
            });
        }
    }
}

fn handle_submission_completion(
    endpoints: &mut [EndpointState],
    senders: &mut [SenderState],
    outcome: SubmissionOutcome,
    now: time::Instant,
) -> Result<(), String> {
    let SubmissionOutcome {
        sender_index,
        tx_hash,
        nonce,
        result,
    } = outcome;
    let endpoint_index = senders[sender_index].account.endpoint_index;
    endpoints[endpoint_index].submission_tasks = endpoints[endpoint_index]
        .submission_tasks
        .checked_sub(1)
        .expect("submission task counter underflowed");

    match result {
        Ok(()) => {
            senders[sender_index].pending_tx_hash = Some(tx_hash);
            senders[sender_index].retry_backoff = INITIAL_RETRY_BACKOFF;
            Ok(())
        }
        Err(err) => match classify_submission_error(&err) {
            SubmissionErrorKind::Fatal => {
                endpoints[endpoint_index].failed += 1;
                Err(format_sender_failure(
                    &endpoints[endpoint_index].endpoint,
                    &senders[sender_index],
                    nonce,
                    &err,
                ))
            }
            SubmissionErrorKind::RetryRejected => {
                let retry_backoff = next_retry_backoff(senders[sender_index].retry_backoff, &err);
                senders[sender_index].retry_backoff = retry_backoff;
                schedule_sender_retry(endpoints, senders, sender_index, now + retry_backoff);
                Ok(())
            }
            SubmissionErrorKind::RetryCheckStatus => {
                let retry_backoff = next_retry_backoff(senders[sender_index].retry_backoff, &err);
                senders[sender_index].retry_backoff = retry_backoff;
                senders[sender_index].pending_tx_hash = Some(tx_hash);
                schedule_sender_retry(endpoints, senders, sender_index, now + retry_backoff);
                Ok(())
            }
        },
    }
}

async fn poll_pending_statuses(
    endpoints: &mut [EndpointState],
    senders: &mut [SenderState],
    client: reqwest::Client,
    fetch_statuses: impl Fn(reqwest::Client, String, Vec<String>) -> FetchStatusesFuture + Clone,
    now: time::Instant,
) -> Result<(), String> {
    let mut retries = Vec::new();

    for endpoint in endpoints.iter_mut() {
        let pending_senders = endpoint
            .sender_indices
            .iter()
            .copied()
            .filter(|sender_index| senders[*sender_index].pending_tx_hash.is_some())
            .collect::<Vec<_>>();

        for chunk in pending_senders.chunks(STATUS_POLL_BATCH_SIZE) {
            let tx_hashes = chunk
                .iter()
                .map(|sender_index| {
                    senders[*sender_index]
                        .pending_tx_hash
                        .clone()
                        .expect("pending sender must carry a tx hash")
                })
                .collect::<Vec<_>>();
            let statuses =
                fetch_statuses(client.clone(), endpoint.endpoint.clone(), tx_hashes).await?;
            if statuses.len() != chunk.len() {
                return Err(format!(
                    "{} returned {} statuses for {} requested hashes",
                    endpoint.endpoint,
                    statuses.len(),
                    chunk.len()
                ));
            }

            for (sender_index, status) in chunk.iter().copied().zip(statuses) {
                let Some(current_hash) = senders[sender_index].pending_tx_hash.clone() else {
                    continue;
                };
                if current_hash != status.tx_hash {
                    return Err(format!(
                        "{} returned mismatched tx hash {} for sender {}",
                        endpoint.endpoint, status.tx_hash, sender_index
                    ));
                }

                match status.state {
                    TransactionState::Pending => {}
                    TransactionState::Included => {
                        senders[sender_index].pending_tx_hash = None;
                        senders[sender_index].next_nonce = senders[sender_index]
                            .next_nonce
                            .checked_add(1)
                            .expect("sender nonce overflowed");
                        senders[sender_index].retry_backoff = INITIAL_RETRY_BACKOFF;
                        endpoint.completed += 1;
                        if sender_is_ready(&senders[sender_index]) {
                            senders[sender_index].queued_ready = true;
                            endpoint.ready.push_back(sender_index);
                        }
                    }
                    TransactionState::Rejected => {
                        endpoint.failed += 1;
                        return Err(format_sender_failure(
                            &endpoint.endpoint,
                            &senders[sender_index],
                            senders[sender_index].next_nonce,
                            "transaction rejected before inclusion",
                        ));
                    }
                    TransactionState::Unknown => {
                        let retry_backoff = senders[sender_index].retry_backoff;
                        senders[sender_index].pending_tx_hash = None;
                        retries.push((sender_index, now + retry_backoff));
                    }
                }
            }
        }
    }

    for (sender_index, ready_at) in retries {
        schedule_sender_retry(endpoints, senders, sender_index, ready_at);
    }

    Ok(())
}

fn print_startup(endpoints: &[EndpointState], sender_count: usize) {
    if endpoints.len() == 1 {
        println!(
            "running ring spammer with {sender_count} senders against {}. Press Ctrl-C to stop.",
            tx_url(&endpoints[0].endpoint)
        );
    } else {
        println!(
            "running ring spammer with {sender_count} senders across {} validators. Press Ctrl-C to stop.",
            endpoints.len()
        );
    }

    for (index, endpoint) in endpoints.iter().enumerate() {
        println!(
            "endpoint[{index}] {} senders={}",
            tx_url(&endpoint.endpoint),
            endpoint.sender_indices.len()
        );
    }
}

fn print_summary(endpoints: &[EndpointState]) -> Result<(), String> {
    let completed = endpoints
        .iter()
        .map(|endpoint| endpoint.completed)
        .sum::<usize>();
    let failed = endpoints
        .iter()
        .map(|endpoint| endpoint.failed)
        .sum::<usize>();

    println!("completed: {completed}");
    println!("failed: {failed}");
    for (index, endpoint) in endpoints.iter().enumerate() {
        println!(
            "endpoint[{index}] {} senders={} completed={} failed={}",
            tx_url(&endpoint.endpoint),
            endpoint.sender_indices.len(),
            endpoint.completed,
            endpoint.failed
        );
    }

    if failed == 0 {
        return Ok(());
    }

    Err(format!("failed: {failed}"))
}

async fn stop_spammer(tasks: &mut JoinSet<SubmissionOutcome>) {
    println!("stopping spammer...");
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

async fn run_with_stop_flag<Submit, SubmitFuture>(
    args: Args,
    should_stop: Arc<AtomicBool>,
    submit: Submit,
    fetch_statuses: impl Fn(reqwest::Client, String, Vec<String>) -> FetchStatusesFuture
    + Send
    + Sync
    + Clone
    + 'static,
) -> Result<(), String>
where
    Submit: Fn(reqwest::Client, String, Vec<u8>) -> SubmitFuture + Send + Sync + Clone + 'static,
    SubmitFuture: Future<Output = Result<String, String>> + Send + 'static,
{
    let accounts = build_ring_accounts(args.count, args.seed_start, args.endpoints.len());
    let mut senders = build_sender_states(accounts, args.nonce);
    let mut endpoints = build_endpoint_states(args.endpoints, &mut senders);
    let client = build_http_client();
    let mut tasks = JoinSet::new();
    let mut next_status_poll = time::Instant::now();

    print_startup(&endpoints, args.count.get());

    loop {
        while let Some(result) = tasks.try_join_next() {
            let outcome = result.expect("submission task panicked");
            let now = time::Instant::now();
            handle_submission_completion(&mut endpoints, &mut senders, outcome, now)?;
        }

        let now = time::Instant::now();
        activate_ready_senders(&mut endpoints, &mut senders, now);

        if now >= next_status_poll {
            poll_pending_statuses(
                &mut endpoints,
                &mut senders,
                client.clone(),
                fetch_statuses.clone(),
                now,
            )
            .await?;
            next_status_poll = now + STATUS_POLL_INTERVAL;
        }

        spawn_submissions(&mut endpoints, &mut senders, &mut tasks, &client, &submit);

        if should_stop.load(Ordering::Relaxed) {
            stop_spammer(&mut tasks).await;
            break;
        }

        tokio::select! {
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                let outcome = result.expect("submission task panicked");
                let now = time::Instant::now();
                handle_submission_completion(&mut endpoints, &mut senders, outcome, now)?;
            }
            _ = time::sleep(Duration::from_millis(10)) => {}
        }
    }

    print_summary(&endpoints)
}

type FetchStatusesFuture = std::pin::Pin<
    Box<dyn Future<Output = Result<Vec<crate::shared::TransactionStatus>, String>> + Send>,
>;

async fn run_with_default_status_fetch<Submit, SubmitFuture>(
    args: Args,
    should_stop: Arc<AtomicBool>,
    submit: Submit,
) -> Result<(), String>
where
    Submit: Fn(reqwest::Client, String, Vec<u8>) -> SubmitFuture + Send + Sync + Clone + 'static,
    SubmitFuture: Future<Output = Result<String, String>> + Send + 'static,
{
    run_with_stop_flag(args, should_stop, submit, |client, endpoint, tx_hashes| {
        Box::pin(async move { fetch_transaction_statuses(&client, &endpoint, &tx_hashes).await })
    })
    .await
}

pub async fn run(args: Args) -> Result<(), String> {
    let should_stop = Arc::new(AtomicBool::new(false));
    let signal = should_stop.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        signal.store(true, Ordering::Relaxed);
    });

    run_with_default_status_fetch(args, should_stop, |client, endpoint, tx_bytes| async move {
        accept_transaction(&client, &endpoint, tx_bytes).await
    })
    .await
}

#[cfg(test)]
async fn run_until_stopped<Submit, SubmitFuture>(
    args: Args,
    should_stop: Arc<AtomicBool>,
    submit: Submit,
) -> Result<(), String>
where
    Submit: Fn(reqwest::Client, String, Vec<u8>) -> SubmitFuture + Send + Sync + Clone + 'static,
    SubmitFuture: Future<Output = Result<String, String>> + Send + 'static,
{
    run_with_default_status_fetch(args, should_stop, submit).await
}

#[cfg(test)]
async fn run_until_stopped_with_statuses<Submit, SubmitFuture, Fetch>(
    args: Args,
    should_stop: Arc<AtomicBool>,
    submit: Submit,
    fetch_statuses: Fetch,
) -> Result<(), String>
where
    Submit: Fn(reqwest::Client, String, Vec<u8>) -> SubmitFuture + Send + Sync + Clone + 'static,
    SubmitFuture: Future<Output = Result<String, String>> + Send + 'static,
    Fetch: Fn(reqwest::Client, String, Vec<String>) -> FetchStatusesFuture
        + Send
        + Sync
        + Clone
        + 'static,
{
    run_with_stop_flag(args, should_stop, submit, fetch_statuses).await
}

#[cfg(test)]
fn start_stop_timer(delay: Duration, should_stop: Arc<AtomicBool>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        time::sleep(delay).await;
        should_stop.store(true, Ordering::Relaxed);
    })
}

#[cfg(test)]
fn test_args(count: usize) -> Args {
    Args::new(count, vec!["http://127.0.0.1:8080".to_string()], 0, 0)
        .expect("test args should be valid")
}

#[cfg(test)]
mod tests {
    use super::{
        Args, MAX_SUBMISSION_TASKS_PER_ENDPOINT, build_ring_accounts, build_sender_states,
        classify_submission_error, next_retry_backoff, run_until_stopped,
        run_until_stopped_with_statuses, start_stop_timer, test_args,
    };
    use crate::shared::{TransactionState, TransactionStatus, transaction_hash_hex};
    use commonware_codec::{Encode, ReadExt};
    use commonware_cryptography::{Sha256, ed25519};
    use commonware_utils::hex;
    use constantinople_primitives::{Signed, Transaction};
    use std::{
        collections::{HashSet, VecDeque},
        num::NonZeroUsize,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::time;

    fn decode_sender_and_nonce(tx_bytes: &[u8]) -> (String, u64) {
        let decoded: Signed<
            Transaction<crate::shared::Digest, ed25519::PublicKey>,
            Sha256,
            ed25519::Signature,
        > = Signed::read(&mut &tx_bytes[..]).expect("ring transfer should decode");
        (hex(&decoded.value().sender.encode()), decoded.value().nonce)
    }

    fn is_retryable_submission_error(err: &str) -> bool {
        !matches!(
            classify_submission_error(err),
            super::SubmissionErrorKind::Fatal
        )
    }

    #[test]
    fn ring_accounts_wrap_back_to_the_first_account() {
        let accounts = build_ring_accounts(NonZeroUsize::new(3).unwrap(), 11, 2);

        assert_eq!(accounts.len(), 3);
        assert_eq!(accounts[0].to, accounts[1].from);
        assert_eq!(accounts[1].to, accounts[2].from);
        assert_eq!(accounts[2].to, accounts[0].from);
    }

    #[test]
    fn ring_accounts_are_sharded_across_endpoints() {
        let accounts = build_ring_accounts(NonZeroUsize::new(5).unwrap(), 11, 2);

        assert_eq!(accounts[0].endpoint_index, 0);
        assert_eq!(accounts[1].endpoint_index, 1);
        assert_eq!(accounts[2].endpoint_index, 0);
        assert_eq!(accounts[3].endpoint_index, 1);
        assert_eq!(accounts[4].endpoint_index, 0);
    }

    #[test]
    fn transaction_hash_matches_generated_bytes() {
        let senders =
            build_sender_states(build_ring_accounts(NonZeroUsize::new(1).unwrap(), 11, 1), 7);
        let sender = &senders[0];
        let tx_bytes = super::build_sender_transaction_bytes(sender);
        let tx_hash = transaction_hash_hex(&tx_bytes).expect("tx hash should decode");
        let (_sender, nonce) = decode_sender_and_nonce(&tx_bytes);

        assert!(!tx_hash.is_empty());
        assert_eq!(nonce, 7);
    }

    #[test]
    fn retries_network_and_server_overload_errors() {
        assert!(is_retryable_submission_error("request failed: timed out"));
        assert!(is_retryable_submission_error("error (503): mempool full"));
        assert!(!is_retryable_submission_error(
            "error (400): bad transaction"
        ));
    }

    #[test]
    fn mempool_full_backoff_has_minimum_floor() {
        assert_eq!(
            next_retry_backoff(Duration::from_millis(100), "error (503): mempool full"),
            Duration::from_secs(1)
        );
    }

    #[tokio::test]
    async fn run_stops_promptly_while_submitting() {
        let should_stop = Arc::new(AtomicBool::new(false));
        let stopper = start_stop_timer(Duration::from_millis(10), should_stop.clone());
        let result = time::timeout(
            Duration::from_millis(200),
            run_until_stopped(
                test_args(4),
                should_stop,
                |_client, _endpoint, _tx_bytes| async {
                    time::sleep(Duration::from_secs(60)).await;
                    Ok(String::new())
                },
            ),
        )
        .await;

        stopper.await.expect("shutdown task should finish");

        assert!(result.is_ok(), "spammer should observe shutdown promptly");
        assert!(
            result
                .expect("spammer should finish before the timeout")
                .is_ok(),
            "spammer should stop cleanly"
        );
    }

    #[tokio::test]
    async fn run_submits_to_multiple_endpoints() {
        let should_stop = Arc::new(AtomicBool::new(false));
        let seen_endpoints = Arc::new(Mutex::new(HashSet::new()));
        let seen = seen_endpoints.clone();
        let signal = should_stop.clone();
        let args = Args::new(
            4,
            vec![
                "http://127.0.0.1:8080".to_string(),
                "http://127.0.0.1:8081".to_string(),
            ],
            0,
            0,
        )
        .expect("args should be valid");

        let result = time::timeout(
            Duration::from_millis(500),
            run_until_stopped(args, should_stop, move |_client, endpoint, tx_bytes| {
                let seen = seen.clone();
                let signal = signal.clone();
                async move {
                    let _ = tx_bytes;
                    let count = {
                        let mut seen = seen.lock().expect("endpoint set lock should succeed");
                        seen.insert(endpoint);
                        seen.len()
                    };
                    if count == 2 {
                        signal.store(true, Ordering::Relaxed);
                    }
                    Ok("hash".to_string())
                }
            }),
        )
        .await;

        assert!(result.is_ok(), "spammer should finish before the timeout");
        assert_eq!(
            seen_endpoints
                .lock()
                .expect("endpoint set lock should succeed")
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn run_reuses_sender_after_inclusion_status() {
        let should_stop = Arc::new(AtomicBool::new(false));
        let submissions = Arc::new(AtomicUsize::new(0));
        let pending_hashes = Arc::new(Mutex::new(VecDeque::<String>::new()));
        let pending_for_submit = pending_hashes.clone();
        let pending_for_status = pending_hashes.clone();
        let submit_count = submissions.clone();
        let signal = should_stop.clone();

        let result = time::timeout(
            Duration::from_secs(2),
            run_until_stopped_with_statuses(
                test_args(1),
                should_stop,
                move |_client, _endpoint, tx_bytes| {
                    let submit_count = submit_count.clone();
                    let pending = pending_for_submit.clone();
                    let signal = signal.clone();
                    async move {
                        let count = submit_count.fetch_add(1, Ordering::SeqCst) + 1;
                        let hash = transaction_hash_hex(&tx_bytes).expect("tx hash should decode");
                        pending
                            .lock()
                            .expect("pending hash lock should succeed")
                            .push_back(hash.clone());
                        if count >= 2 {
                            signal.store(true, Ordering::Relaxed);
                        }
                        Ok(hash)
                    }
                },
                move |_client, _endpoint, tx_hashes| {
                    let pending = pending_for_status.clone();
                    Box::pin(async move {
                        let mut pending = pending.lock().expect("pending hash lock should succeed");
                        let statuses = tx_hashes
                            .into_iter()
                            .map(|tx_hash| {
                                let state = if pending.front().is_some_and(|next| next == &tx_hash)
                                {
                                    pending.pop_front();
                                    TransactionState::Included
                                } else {
                                    TransactionState::Pending
                                };

                                TransactionStatus {
                                    tx_hash,
                                    state,
                                    height: 1,
                                }
                            })
                            .collect::<Vec<_>>();

                        Ok(statuses)
                    })
                },
            ),
        )
        .await;

        assert!(result.is_ok(), "spammer should finish");
        assert!(submissions.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn run_bounds_concurrent_submissions_per_endpoint() {
        let should_stop = Arc::new(AtomicBool::new(false));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicBool::new(false));
        let signal = should_stop.clone();
        let max_in_flight_for_submit = max_in_flight.clone();

        let result = time::timeout(
            Duration::from_secs(2),
            run_until_stopped(
                test_args(MAX_SUBMISSION_TASKS_PER_ENDPOINT * 4),
                should_stop,
                move |_client, _endpoint, _tx_bytes| {
                    let in_flight = in_flight.clone();
                    let max_in_flight = max_in_flight_for_submit.clone();
                    let released = released.clone();
                    let signal = signal.clone();
                    async move {
                        let current = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        max_in_flight.fetch_max(current, Ordering::SeqCst);

                        if current >= MAX_SUBMISSION_TASKS_PER_ENDPOINT {
                            released.store(true, Ordering::SeqCst);
                            signal.store(true, Ordering::Relaxed);
                        }

                        while !released.load(Ordering::SeqCst) {
                            time::sleep(Duration::from_millis(5)).await;
                        }

                        in_flight.fetch_sub(1, Ordering::SeqCst);
                        Ok("hash".to_string())
                    }
                },
            ),
        )
        .await;

        assert!(result.is_ok(), "spammer should finish");
        assert_eq!(
            max_in_flight.load(Ordering::SeqCst),
            MAX_SUBMISSION_TASKS_PER_ENDPOINT
        );
    }
}
