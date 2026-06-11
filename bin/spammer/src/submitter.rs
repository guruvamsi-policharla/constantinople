//! Async submission engine.
//!
//! Each relayer stream submits one pre-signed batch at a time. Public batches
//! keep the historical fire-and-forget semantics (plus bounded retries on
//! transport errors). Private batches are commitment-chained, so a lost batch
//! would permanently desynchronize every later transaction from on-chain
//! state; instead of advancing past failures, the submitter reports them to
//! the presigner, which rolls its state back to what actually landed and
//! re-signs.

use crate::{
    chain_api::{AccountError, ChainApi, POLL_INTERVAL, commitment_hex},
    signer::{BatchMeta, Tx},
};
use commonware_codec::Encode;
use commonware_cryptography::ed25519;
use constantinople_mempool::webserver::client::SubmitError;
use std::{
    collections::{BTreeMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Shared counters for progress reporting.
pub struct Stats {
    pub finalized: AtomicU64,
    pub filtered: AtomicU64,
    pub dropped: AtomicU64,
    pub errors: AtomicU64,
    pub halted: AtomicU64,
}

impl Stats {
    pub const fn new() -> Self {
        Self {
            finalized: AtomicU64::new(0),
            filtered: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            halted: AtomicU64::new(0),
        }
    }
}

/// One pre-signed batch flowing from the presigner to the submitter.
///
/// `epoch` increments every time the presigner rolls back; envelopes from a
/// superseded epoch were signed against state that no longer exists and are
/// discarded by the submitter. Private envelopes carry the [`BatchMeta`]
/// needed to map a failure back onto presigner state.
pub struct Envelope {
    pub seq: u64,
    pub epoch: u64,
    pub txs: Vec<Tx>,
    pub meta: Option<BatchMeta>,
}

/// Outcome report from the submitter back to the presigner.
pub enum Feedback {
    /// The batch fully resolved; its rollback metadata can be discarded.
    Resolved { seq: u64 },
    /// The batch failed. `landed` holds the indices (into the batch) of
    /// transactions confirmed on-chain; everything else must be unwound.
    Failed { seq: u64, landed: Vec<usize> },
}

/// Base backoff after a failed submission attempt.
const SUBMIT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Cap for the exponential submission backoff.
const SUBMIT_ERROR_BACKOFF_CAP: Duration = Duration::from_secs(1);

/// Pause after reporting a failed private batch, so instant `dropped`
/// responses cannot spin the rollback/resign loop hot.
const FAILURE_BACKOFF: Duration = Duration::from_millis(500);

/// Same-bytes retry budget for submissions that never reached the chain
/// (connection refused, public-mode transport errors).
const MAX_SAME_BATCH_RETRIES: u32 = 300;

/// Consecutive fully-failed private batches tolerated before the submitter
/// halts: repeated total drops mean the chain is rejecting everything we sign
/// and retrying would only produce garbage.
const MAX_CONSECUTIVE_FAILURES: u32 = 5;

/// A `dropped` response faster than this cannot be a real proposed-then-
/// dropped outcome (that takes at least the mempool's drop-grace horizon of
/// `2 x validators` finalized blocks): it is the pool-full fast path, which
/// resolves immediately without pooling. Such backpressure is retried with
/// the same bytes (the pool-full path caches no status) instead of counting
/// toward the consecutive-failure halt.
const INSTANT_DROP_THRESHOLD: Duration = Duration::from_millis(900);

/// Same-bytes retry budget for instant (pool-full) drops before falling back
/// to the rollback path.
const MAX_INSTANT_DROP_RETRIES: u32 = 20;

/// How long reconciliation waits for an unresolved batch's effects to show up
/// in committed state before concluding it did not land.
///
/// This is a heuristic horizon, not a guarantee: the mempool's drop-grace
/// clock is counted in finalized blocks and only starts once a batch is
/// proposed, so a batch sitting pooled at a slow or briefly-partitioned
/// leader can in principle land after this deadline; the relayer's account
/// view can also lag finalization. If that race is lost, the re-signed
/// transactions conflict with the late-landing originals and the submitter
/// fails closed — subsequent batches are filtered until the commitment
/// cross-check or the consecutive-failure threshold halts it. The deadline
/// trades that fail-stop tail risk against stalling every unknown outcome
/// forever.
const RECONCILE_TIMEOUT: Duration = Duration::from_secs(60);

/// Submits batches through a relayer and records each batch outcome.
pub struct RelayerSubmitter {
    url: String,
    http: reqwest::Client,
    stats: Arc<Stats>,
    index: usize,
    target_leader: Option<String>,
    leader_fanout: usize,
    chain: ChainApi,
    reconcile_timeout: Duration,
    instant_drop_retries: u32,
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum RelayerBatchStatus {
    Finalized {
        height: u64,
    },
    PartiallyFinalized {
        height: u64,
        included: Vec<String>,
        filtered: Vec<String>,
    },
    Dropped,
}

/// Disposition of one private envelope.
enum PrivateOutcome {
    /// Every transaction landed; the presigner state is correct as-is.
    Advance,
    /// Some or none landed; the presigner must roll back everything else.
    Rollback { landed: Vec<usize> },
    /// Unrecoverable; stop this submitter.
    Halt(String),
}

impl RelayerSubmitter {
    pub fn new(
        url: String,
        stats: Arc<Stats>,
        index: usize,
        target_leader: Option<String>,
        chain: ChainApi,
    ) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
            stats,
            index,
            target_leader,
            leader_fanout: 1,
            chain,
            reconcile_timeout: RECONCILE_TIMEOUT,
            instant_drop_retries: MAX_INSTANT_DROP_RETRIES,
        }
    }

    /// Overrides the reconciliation deadline (tests).
    #[cfg(test)]
    pub const fn with_reconcile_timeout(mut self, timeout: Duration) -> Self {
        self.reconcile_timeout = timeout;
        self
    }

    /// Overrides the instant-drop retry budget (tests).
    #[cfg(test)]
    pub const fn with_instant_drop_retries(mut self, retries: u32) -> Self {
        self.instant_drop_retries = retries;
        self
    }

    /// Consumes envelopes until the presigner finishes or this submitter
    /// halts on an unrecoverable failure.
    pub async fn run(
        self,
        mut batches: mpsc::Receiver<Envelope>,
        feedback: mpsc::UnboundedSender<Feedback>,
        keys: Arc<Vec<ed25519::PublicKey>>,
    ) {
        let mut expected_epoch = 0u64;
        let mut consecutive_failures = 0u32;

        while let Some(envelope) = batches.recv().await {
            if envelope.epoch < expected_epoch || envelope.txs.is_empty() {
                continue;
            }

            let Some(meta) = &envelope.meta else {
                self.submit_public(&envelope.txs).await;
                continue;
            };

            match self.submit_private(&envelope.txs, meta, &keys).await {
                PrivateOutcome::Advance => {
                    consecutive_failures = 0;
                    let _ = feedback.send(Feedback::Resolved { seq: envelope.seq });
                }
                PrivateOutcome::Rollback { landed } => {
                    if landed.is_empty() {
                        consecutive_failures += 1;
                    } else {
                        consecutive_failures = 0;
                    }
                    if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                        self.halt(format!(
                            "{MAX_CONSECUTIVE_FAILURES} consecutive batches fully failed; \
                             the chain is rejecting everything this submitter signs"
                        ));
                        return;
                    }
                    let _ = feedback.send(Feedback::Failed {
                        seq: envelope.seq,
                        landed,
                    });
                    expected_epoch = envelope.epoch + 1;
                    tokio::time::sleep(FAILURE_BACKOFF).await;
                }
                PrivateOutcome::Halt(reason) => {
                    self.halt(reason);
                    return;
                }
            }
        }
        info!(
            submitter = self.index,
            "presigner finished, submitter exiting"
        );
    }

    fn halt(&self, reason: String) {
        self.stats.halted.fetch_add(1, Ordering::Relaxed);
        error!(submitter = self.index, %reason, "submitter halted");
    }

    /// Submits a private batch and classifies the outcome.
    ///
    /// Connection-refused errors mean the request never left this process, so
    /// the identical bytes are retried. Any other failure leaves the batch's
    /// fate unknown and is settled by [`Self::reconcile`] against committed
    /// account state.
    async fn submit_private(
        &self,
        txs: &[Tx],
        meta: &BatchMeta,
        keys: &[ed25519::PublicKey],
    ) -> PrivateOutcome {
        let count = txs.len() as u64;
        let body = txs.encode();
        let mut attempts = 0u32;
        let mut instant_drops = 0u32;
        loop {
            let submitted_at = tokio::time::Instant::now();
            match self.submit_encoded(body.clone()).await {
                Ok(RelayerBatchStatus::Finalized { height }) => {
                    self.stats.finalized.fetch_add(count, Ordering::Relaxed);
                    debug!(height, count, "relayed batch finalized");
                    return PrivateOutcome::Advance;
                }
                Ok(RelayerBatchStatus::PartiallyFinalized {
                    height,
                    included,
                    filtered,
                }) => {
                    self.stats
                        .finalized
                        .fetch_add(included.len() as u64, Ordering::Relaxed);
                    self.stats
                        .filtered
                        .fetch_add(filtered.len() as u64, Ordering::Relaxed);
                    let included: HashSet<&str> = included.iter().map(String::as_str).collect();
                    let landed = meta
                        .txs
                        .iter()
                        .enumerate()
                        .filter(|(_, tx)| included.contains(tx.digest.as_str()))
                        .map(|(index, _)| index)
                        .collect();
                    warn!(
                        height,
                        included = included.len(),
                        filtered = filtered.len(),
                        "private batch partially finalized, rolling back the rest"
                    );
                    return PrivateOutcome::Rollback { landed };
                }
                Ok(RelayerBatchStatus::Dropped) => {
                    // An instant drop is the pool-full fast path (a genuine
                    // proposed-then-dropped outcome takes the block-counted
                    // drop-grace horizon to resolve): transient backpressure,
                    // not rejection. The pool-full path caches no status, so
                    // the same bytes are safe to retry.
                    if submitted_at.elapsed() < INSTANT_DROP_THRESHOLD
                        && instant_drops < self.instant_drop_retries
                    {
                        instant_drops += 1;
                        warn!(
                            instant_drops,
                            "instant drop (pool backpressure), retrying same batch"
                        );
                        tokio::time::sleep(submit_backoff(instant_drops)).await;
                        continue;
                    }
                    self.stats.dropped.fetch_add(count, Ordering::Relaxed);
                    debug!(count, "private batch dropped, rolling back");
                    return PrivateOutcome::Rollback { landed: Vec::new() };
                }
                Err(SubmitError::BadRequest | SubmitError::PayloadTooLarge) => {
                    return PrivateOutcome::Halt(
                        "relayer rejected the batch as malformed (bad request / too large); \
                         this indicates a bug or misconfiguration"
                            .to_string(),
                    );
                }
                Err(error) if is_connect_error(&error) => {
                    // Never reached the relayer: the same bytes are safe to retry.
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    attempts += 1;
                    if attempts >= MAX_SAME_BATCH_RETRIES {
                        return PrivateOutcome::Halt(format!(
                            "relayer unreachable after {attempts} attempts: {error}"
                        ));
                    }
                    warn!(%error, attempts, "relayer unreachable, retrying same batch");
                    tokio::time::sleep(submit_backoff(attempts)).await;
                }
                Err(error) => {
                    // The batch may or may not have reached a leader; settle
                    // its fate against committed state.
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    warn!(%error, "submission outcome unknown, reconciling against chain state");
                    return self.reconcile(meta, keys).await;
                }
            }
        }
    }

    /// Settles an unresolved batch by polling committed account state.
    ///
    /// Waits until every transaction's effects are visible (all landed) or
    /// the deadline passes, then classifies each transaction by comparing the
    /// account's committed nonce against the batch's pre-signed nonces.
    /// Snapshots older than the batch's own confirmed history are detected
    /// and never classified. The deadline is a heuristic horizon (see
    /// [`RECONCILE_TIMEOUT`]); if a batch judged not-landed resolves later
    /// anyway, the conflict surfaces as filtered batches and the submitter
    /// fails closed instead of corrupting its bookkeeping.
    async fn reconcile(&self, meta: &BatchMeta, keys: &[ed25519::PublicKey]) -> PrivateOutcome {
        // Batch order is ascending nonce order per account.
        let mut touched: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for (index, tx) in meta.txs.iter().enumerate() {
            touched.entry(tx.account).or_default().push(index);
        }

        let deadline = tokio::time::Instant::now() + self.reconcile_timeout;
        loop {
            let mut bases: BTreeMap<usize, (u64, Option<String>)> = BTreeMap::new();
            let mut unavailable = false;
            let mut stale = false;
            for (&account, indices) in &touched {
                match self.chain.account(&keys[account]).await {
                    Ok(info) => {
                        let (base, bitmap, private) = info
                            .map(|info| (info.nonce.base, info.nonce.bitmap, Some(info.private)))
                            .unwrap_or((0, 0, None));
                        if bitmap != 0 {
                            return PrivateOutcome::Halt(format!(
                                "account {account} has a non-contiguous nonce bitmap on-chain; \
                                 local state cannot be reconciled"
                            ));
                        }
                        // Every nonce below this batch's first was confirmed
                        // before the batch was submitted, so a lower observed
                        // base proves the node served a stale snapshot (e.g.
                        // a secondary still catching up) — keep polling
                        // rather than misclassify confirmed history as lost.
                        if base < meta.txs[indices[0]].nonce {
                            stale = true;
                            continue;
                        }
                        bases.insert(account, (base, private));
                    }
                    Err(AccountError::NotReady | AccountError::Unavailable(_)) => {
                        unavailable = true;
                    }
                }
            }

            let all_landed = !unavailable
                && !stale
                && touched.iter().all(|(account, indices)| {
                    let last_nonce = meta.txs[*indices.last().expect("non-empty")].nonce;
                    bases
                        .get(account)
                        .is_some_and(|(base, _)| *base > last_nonce)
                });
            let timed_out = tokio::time::Instant::now() >= deadline;
            if !all_landed && !timed_out {
                tokio::time::sleep(POLL_INTERVAL).await;
                continue;
            }
            if timed_out && (unavailable || stale) {
                return PrivateOutcome::Halt(
                    "account state unavailable or lagging throughout reconciliation; \
                     cannot determine the fate of an in-flight batch"
                        .to_string(),
                );
            }

            // Classify each transaction and cross-check the commitment chain.
            let mut landed = Vec::new();
            for (account, indices) in &touched {
                let (base, private) = &bases[account];
                let account_landed: Vec<usize> = indices
                    .iter()
                    .copied()
                    .filter(|&index| meta.txs[index].nonce < *base)
                    .collect();
                let expected = match account_landed.last() {
                    Some(&index) => meta.txs[index].post_balance.commitment(),
                    None => meta.txs[indices[0]].pre_balance.commitment(),
                };
                let actual = private
                    .clone()
                    .unwrap_or_else(|| commitment_hex(&Default::default()));
                if actual != commitment_hex(&expected) {
                    return PrivateOutcome::Halt(format!(
                        "account {account} commitment diverged from local bookkeeping \
                         during reconciliation"
                    ));
                }
                landed.extend(account_landed);
            }
            landed.sort_unstable();

            let total = meta.txs.len() as u64;
            let landed_count = landed.len() as u64;
            self.stats
                .finalized
                .fetch_add(landed_count, Ordering::Relaxed);
            if landed_count == total {
                info!(count = total, "reconciliation: batch fully landed");
                return PrivateOutcome::Advance;
            }
            self.stats
                .dropped
                .fetch_add(total - landed_count, Ordering::Relaxed);
            info!(
                landed = landed_count,
                lost = total - landed_count,
                "reconciliation settled an unresolved batch"
            );
            return PrivateOutcome::Rollback { landed };
        }
    }

    /// Submits a public batch with the historical advance-on-failure
    /// semantics, hardened with same-bytes retries on transport errors
    /// (public nonces tolerate later gaps via the on-chain run-ahead window,
    /// so advancing after persistent failure is acceptable there).
    async fn submit_public(&self, txs: &[Tx]) {
        let count = txs.len() as u64;
        let body = txs.encode();
        let mut attempts = 0u32;
        loop {
            match self.submit_encoded(body.clone()).await {
                Ok(RelayerBatchStatus::Finalized { height }) => {
                    self.stats.finalized.fetch_add(count, Ordering::Relaxed);
                    debug!(height, count, "relayed batch finalized");
                    return;
                }
                Ok(RelayerBatchStatus::PartiallyFinalized {
                    height,
                    included,
                    filtered,
                }) => {
                    self.stats
                        .finalized
                        .fetch_add(included.len() as u64, Ordering::Relaxed);
                    self.stats
                        .filtered
                        .fetch_add(filtered.len() as u64, Ordering::Relaxed);
                    info!(
                        height,
                        included = included.len(),
                        filtered = filtered.len(),
                        "relayed batch partially finalized, advancing"
                    );
                    return;
                }
                Ok(RelayerBatchStatus::Dropped) => {
                    self.stats.dropped.fetch_add(count, Ordering::Relaxed);
                    debug!(count, "relayed batch dropped, advancing");
                    return;
                }
                Err(error @ (SubmitError::BadRequest | SubmitError::PayloadTooLarge)) => {
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    warn!(%error, "relayer rejected batch as malformed, advancing");
                    return;
                }
                Err(error) => {
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    attempts += 1;
                    if attempts >= MAX_SAME_BATCH_RETRIES {
                        warn!(%error, attempts, "abandoning batch after repeated errors");
                        return;
                    }
                    warn!(%error, attempts, "relayer submit error, retrying same batch");
                    tokio::time::sleep(submit_backoff(attempts)).await;
                }
            }
        }
    }

    async fn submit_encoded(&self, body: bytes::Bytes) -> Result<RelayerBatchStatus, SubmitError> {
        let mut request = self
            .http
            .post(format!("{}/transactions", self.url))
            .header("content-type", "application/octet-stream")
            .header(
                "x-constantinople-relayer-leader-fanout",
                self.leader_fanout.to_string(),
            );
        if let Some(target_leader) = &self.target_leader {
            request = request.header("x-constantinople-relayer-target-leader", target_leader);
        }
        let response = request.body(body).send().await?;

        match response.status().as_u16() {
            200 => {
                let bytes = response.bytes().await?;
                serde_json::from_slice(&bytes).map_err(SubmitError::InvalidResponse)
            }
            400 => Err(SubmitError::BadRequest),
            413 => Err(SubmitError::PayloadTooLarge),
            500 => Err(SubmitError::InternalServerError),
            503 => Err(SubmitError::ServiceUnavailable),
            other => Err(SubmitError::Unexpected(other)),
        }
    }
}

fn is_connect_error(error: &SubmitError) -> bool {
    matches!(error, SubmitError::Http(http) if http.is_connect())
}

fn submit_backoff(attempts: u32) -> Duration {
    SUBMIT_ERROR_BACKOFF
        .saturating_mul(1u32 << attempts.min(4))
        .min(SUBMIT_ERROR_BACKOFF_CAP)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        accounts::generate_accounts,
        chain_api::ChainApi,
        signer::{PrivateChains, sign_batch, sign_batch_private},
    };
    use commonware_parallel::Sequential;
    use std::{
        num::NonZeroU64,
        sync::{Arc, Mutex},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    const VALUE: u64 = 2;

    fn test_submitter(url: &str, stats: Arc<Stats>) -> RelayerSubmitter {
        // Mock servers answer instantly, so disable the instant-drop
        // (pool backpressure) heuristic except where a test opts back in.
        RelayerSubmitter::new(url.to_string(), stats, 0, None, ChainApi::new(url))
            .with_reconcile_timeout(Duration::from_millis(200))
            .with_instant_drop_retries(0)
    }

    /// Signs one private batch over fresh accounts, returning everything a
    /// test needs to drive the submitter.
    fn private_envelope(accounts: u32) -> (Envelope, Vec<ed25519::PublicKey>) {
        let accounts = generate_accounts(accounts, 31_000);
        let value = NonZeroU64::new(VALUE).expect("non-zero");
        let mut nonces = vec![0; accounts.len()];
        let mut chains = PrivateChains::new(accounts.len(), 100);
        let mut cursor = 0;
        let (txs, meta) = sign_batch_private(
            &Sequential,
            &accounts,
            value,
            &mut nonces,
            &mut chains,
            &mut cursor,
            accounts.len(),
            0,
        );
        let keys = accounts
            .iter()
            .map(|account| account.public_key.clone())
            .collect();
        (
            Envelope {
                seq: 0,
                epoch: 0,
                txs,
                meta: Some(meta),
            },
            keys,
        )
    }

    async fn drive(
        submitter: RelayerSubmitter,
        envelope: Envelope,
        keys: Vec<ed25519::PublicKey>,
    ) -> Vec<Feedback> {
        let (batch_tx, batch_rx) = mpsc::channel(1);
        let (feedback_tx, mut feedback_rx) = mpsc::unbounded_channel();
        batch_tx.send(envelope).await.expect("send envelope");
        drop(batch_tx);
        tokio::time::timeout(
            Duration::from_secs(10),
            submitter.run(batch_rx, feedback_tx, Arc::new(keys)),
        )
        .await
        .expect("submitter should finish");
        let mut feedback = Vec::new();
        while let Ok(item) = feedback_rx.try_recv() {
            feedback.push(item);
        }
        feedback
    }

    /// Scripted HTTP server. Each accepted connection reads one request and
    /// answers via `respond(method_path, request_count)`; requests (with
    /// bodies) are logged for assertions.
    async fn spawn_server(
        respond: impl Fn(&str, usize) -> String + Send + Sync + 'static,
    ) -> (String, Arc<Mutex<Vec<(String, Vec<u8>)>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let log = Arc::new(Mutex::new(Vec::new()));
        let request_log = log.clone();

        tokio::spawn(async move {
            let mut count = 0usize;
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let (method_path, body) = read_request(&mut stream).await;
                request_log
                    .lock()
                    .expect("lock")
                    .push((method_path.clone(), body));
                let response = respond(&method_path, count);
                count += 1;
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        (format!("http://{addr}"), log)
    }

    /// Reads one HTTP request, returning "METHOD /path" and the body.
    async fn read_request(stream: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut chunk).await.expect("read request");
            if read == 0 {
                break buffer.len();
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };

        let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
        let method_path = head
            .lines()
            .next()
            .and_then(|line| {
                let mut parts = line.split_whitespace();
                Some(format!("{} {}", parts.next()?, parts.next()?))
            })
            .unwrap_or_default();

        let content_length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        let mut body = buffer[header_end..].to_vec();
        while body.len() < content_length {
            let read = stream.read(&mut chunk).await.expect("read body");
            if read == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..read]);
        }
        (method_path, body)
    }

    fn json_response(body: &str) -> String {
        response("200 OK", "application/json", body)
    }

    fn empty_response(status: &str) -> String {
        response(status, "text/plain", "")
    }

    fn response(status: &str, content_type: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn finalized_private_batch_resolves_without_rollback() {
        let stats = Arc::new(Stats::new());
        let (url, _) =
            spawn_server(|_, _| json_response(r#"{"status":"finalized","height":3}"#)).await;
        let (envelope, keys) = private_envelope(3);
        let count = envelope.txs.len() as u64;

        let feedback = drive(test_submitter(&url, stats.clone()), envelope, keys).await;

        assert_eq!(stats.finalized.load(Ordering::Relaxed), count);
        assert!(matches!(
            feedback.as_slice(),
            [Feedback::Resolved { seq: 0 }]
        ));
    }

    #[tokio::test]
    async fn dropped_private_batch_requests_full_rollback() {
        let stats = Arc::new(Stats::new());
        let (url, _) = spawn_server(|_, _| json_response(r#"{"status":"dropped"}"#)).await;
        let (envelope, keys) = private_envelope(3);
        let count = envelope.txs.len() as u64;

        let feedback = drive(test_submitter(&url, stats.clone()), envelope, keys).await;

        assert_eq!(stats.dropped.load(Ordering::Relaxed), count);
        assert!(
            matches!(feedback.as_slice(), [Feedback::Failed { seq: 0, landed }] if landed.is_empty())
        );
    }

    #[tokio::test]
    async fn partially_finalized_private_batch_rolls_back_only_filtered() {
        let stats = Arc::new(Stats::new());
        let (envelope, keys) = private_envelope(3);
        let meta = envelope.meta.as_ref().expect("private envelope has meta");
        let included = meta.txs[1].digest.clone();
        let filtered: Vec<String> = [0, 2]
            .iter()
            .map(|&index| meta.txs[index].digest.clone())
            .collect();
        let body = format!(
            r#"{{"status":"partially_finalized","height":7,"included":["{included}"],"filtered":["{}","{}"]}}"#,
            filtered[0], filtered[1]
        );
        let (url, _) = spawn_server(move |_, _| json_response(&body)).await;

        let feedback = drive(test_submitter(&url, stats.clone()), envelope, keys).await;

        assert_eq!(stats.finalized.load(Ordering::Relaxed), 1);
        assert_eq!(stats.filtered.load(Ordering::Relaxed), 2);
        assert!(
            matches!(feedback.as_slice(), [Feedback::Failed { seq: 0, landed }] if landed == &[1])
        );
    }

    /// An instantly-answered `dropped` is pool backpressure, not a chain
    /// rejection: the same bytes are retried and nothing rolls back.
    #[tokio::test]
    async fn instant_drop_retries_same_bytes_then_finalizes() {
        let stats = Arc::new(Stats::new());
        let (url, log) = spawn_server(|_, count| {
            if count < 2 {
                json_response(r#"{"status":"dropped"}"#)
            } else {
                json_response(r#"{"status":"finalized","height":4}"#)
            }
        })
        .await;
        let (envelope, keys) = private_envelope(3);
        let count = envelope.txs.len() as u64;

        let submitter = test_submitter(&url, stats.clone()).with_instant_drop_retries(5);
        let feedback = drive(submitter, envelope, keys).await;

        assert_eq!(stats.finalized.load(Ordering::Relaxed), count);
        assert_eq!(stats.dropped.load(Ordering::Relaxed), 0);
        assert!(matches!(
            feedback.as_slice(),
            [Feedback::Resolved { seq: 0 }]
        ));
        let log = log.lock().expect("lock");
        assert_eq!(log.len(), 3);
        assert_eq!(log[0].1, log[1].1, "retry must resend identical bytes");
        assert_eq!(log[1].1, log[2].1, "retry must resend identical bytes");
    }

    #[tokio::test]
    async fn malformed_batch_halts_the_submitter() {
        let stats = Arc::new(Stats::new());
        let (url, _) = spawn_server(|_, _| empty_response("400 Bad Request")).await;
        let (envelope, keys) = private_envelope(3);

        let feedback = drive(test_submitter(&url, stats.clone()), envelope, keys).await;

        assert_eq!(stats.halted.load(Ordering::Relaxed), 1);
        assert!(feedback.is_empty(), "halt must not request a rollback");
    }

    #[tokio::test]
    async fn unknown_outcome_reconciles_as_landed_when_state_reflects_batch() {
        let stats = Arc::new(Stats::new());
        let (envelope, keys) = private_envelope(2);
        let meta = envelope.meta.as_ref().expect("meta");
        // Account responses claiming every transaction landed: nonce base
        // advanced past each batch nonce, commitment at the post state.
        let accounts: Vec<String> = meta
            .txs
            .iter()
            .map(|tx| {
                format!(
                    r#"{{"balance":92,"nonce":{{"base":{},"bitmap":0}},"private":"{}","pending":"{}"}}"#,
                    tx.nonce + 1,
                    commitment_hex(&tx.post_balance.commitment()),
                    commitment_hex(&Default::default()),
                )
            })
            .collect();
        let count = envelope.txs.len() as u64;

        let (url, log) = spawn_server(move |method_path, _| {
            if method_path.starts_with("POST /transactions") {
                empty_response("500 Internal Server Error")
            } else {
                // GET /account/{hex}: identify the account by request order;
                // both accounts produce one tx in batch order, so requests
                // arrive in `touched` (account index) order.
                static NEXT: std::sync::atomic::AtomicUsize =
                    std::sync::atomic::AtomicUsize::new(0);
                let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                json_response(&accounts[index % accounts.len()])
            }
        })
        .await;

        let feedback = drive(test_submitter(&url, stats.clone()), envelope, keys).await;

        assert_eq!(stats.finalized.load(Ordering::Relaxed), count);
        assert_eq!(stats.errors.load(Ordering::Relaxed), 1);
        assert!(matches!(
            feedback.as_slice(),
            [Feedback::Resolved { seq: 0 }]
        ));
        let log = log.lock().expect("lock");
        assert!(
            log.iter()
                .any(|(path, _)| path.starts_with("GET /account/")),
            "reconciliation must consult account state"
        );
    }

    #[tokio::test]
    async fn unknown_outcome_reconciles_as_lost_when_state_is_untouched() {
        let stats = Arc::new(Stats::new());
        let (envelope, keys) = private_envelope(2);
        let count = envelope.txs.len() as u64;

        // POST fails with 500; accounts were never written (404), so after
        // the (shortened) reconcile deadline the batch settles as lost.
        let (url, _) = spawn_server(|method_path, _| {
            if method_path.starts_with("POST /transactions") {
                empty_response("500 Internal Server Error")
            } else {
                empty_response("404 Not Found")
            }
        })
        .await;

        let feedback = drive(test_submitter(&url, stats.clone()), envelope, keys).await;

        assert_eq!(stats.dropped.load(Ordering::Relaxed), count);
        assert!(
            matches!(feedback.as_slice(), [Feedback::Failed { seq: 0, landed }] if landed.is_empty())
        );
    }

    #[tokio::test]
    async fn stale_epoch_envelopes_are_discarded() {
        let stats = Arc::new(Stats::new());
        // Server that drops everything: first envelope fails (rollback to
        // epoch 1), so the second (still epoch 0) must be skipped without a
        // request.
        let (url, log) = spawn_server(|_, _| json_response(r#"{"status":"dropped"}"#)).await;
        let (first, keys) = private_envelope(3);
        let (mut second, _) = private_envelope(3);
        second.seq = 1;

        let (batch_tx, batch_rx) = mpsc::channel(2);
        let (feedback_tx, mut feedback_rx) = mpsc::unbounded_channel();
        batch_tx.send(first).await.expect("send first");
        batch_tx.send(second).await.expect("send second");
        drop(batch_tx);
        tokio::time::timeout(
            Duration::from_secs(10),
            test_submitter(&url, stats.clone()).run(batch_rx, feedback_tx, Arc::new(keys)),
        )
        .await
        .expect("submitter should finish");

        let mut feedback = Vec::new();
        while let Ok(item) = feedback_rx.try_recv() {
            feedback.push(item);
        }
        assert_eq!(feedback.len(), 1, "only the first envelope is submitted");
        assert_eq!(log.lock().expect("lock").len(), 1);
    }

    #[tokio::test]
    async fn public_batch_retries_same_bytes_on_server_errors() {
        let stats = Arc::new(Stats::new());
        let (url, log) = spawn_server(|_, count| {
            if count == 0 {
                empty_response("503 Service Unavailable")
            } else {
                json_response(r#"{"status":"finalized","height":2}"#)
            }
        })
        .await;

        let accounts = generate_accounts(4, 32_000);
        let value = NonZeroU64::new(1).expect("non-zero");
        let mut nonces = vec![0; accounts.len()];
        let mut cursor = 0;
        let txs = sign_batch(&Sequential, &accounts, value, &mut nonces, &mut cursor, 4);
        let count = txs.len() as u64;
        let envelope = Envelope {
            seq: 0,
            epoch: 0,
            txs,
            meta: None,
        };

        let feedback = drive(test_submitter(&url, stats.clone()), envelope, Vec::new()).await;

        assert_eq!(stats.finalized.load(Ordering::Relaxed), count);
        assert_eq!(stats.errors.load(Ordering::Relaxed), 1);
        assert!(feedback.is_empty(), "public mode sends no feedback");
        let log = log.lock().expect("lock");
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].1, log[1].1, "retry must resend identical bytes");
    }
}
