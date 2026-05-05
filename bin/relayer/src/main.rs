//! HTTP relayer for transaction ingestion.

use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{Method, StatusCode, header::CONTENT_TYPE},
    routing::{get, post},
};
use clap::Parser;
use commonware_cryptography::{Hasher, sha256};
use commonware_formatting::from_hex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{RwLock, mpsc};
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, info, warn};

const DEFAULT_LISTEN: &str = "0.0.0.0:8080";
const DEFAULT_ACK_TIMEOUT_MS: u64 = 1_500;
const DEFAULT_ROUND_POLL_MS: u64 = 200;
const DEFAULT_MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_MAX_TRACKED_BATCHES: usize = 1_000_000;
const MAX_BATCH_LENGTH_PREFIX_BYTES: usize = 5;

#[derive(Debug, Parser)]
#[command(name = "constantinople-relayer")]
struct Cli {
    /// Path to relayer YAML config.
    #[arg(long)]
    config: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
struct RelayerConfig {
    #[serde(default = "default_listen")]
    listen: SocketAddr,
    #[serde(default)]
    leader_fanout: Option<usize>,
    #[serde(default = "default_ack_timeout_ms")]
    ack_timeout_ms: u64,
    #[serde(default = "default_round_poll_ms")]
    round_poll_ms: u64,
    #[serde(default = "default_max_batch_bytes")]
    max_batch_bytes: usize,
    #[serde(default = "default_max_tracked_batches")]
    max_tracked_batches: usize,
    leaders: Vec<LeaderConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct LeaderConfig {
    public_key: String,
    url: String,
}

#[derive(Debug, Clone)]
struct Leader {
    public_key: String,
    sort_key: Vec<u8>,
    url: String,
}

#[derive(Clone)]
struct AppState {
    leaders: Arc<Vec<Leader>>,
    leader_fanout: usize,
    ack_timeout: Duration,
    round_poll: Duration,
    max_batch_bytes: usize,
    batches: Arc<RwLock<TrackedBatches>>,
    observed_round: Arc<AtomicU64>,
    http: reqwest::Client,
    listen: SocketAddr,
}

#[derive(Debug, Clone, Serialize)]
struct SubmitResponse {
    batch_id: String,
    digests: Vec<String>,
    acknowledged_leaders: Vec<String>,
}

#[derive(Debug, Clone)]
struct BatchRecord {
    acknowledged_leaders: Vec<String>,
}

#[derive(Debug)]
struct TrackedBatches {
    records: HashMap<String, BatchRecord>,
    order: VecDeque<String>,
    max_records: usize,
}

impl TrackedBatches {
    fn new(max_records: usize) -> Self {
        Self {
            records: HashMap::new(),
            order: VecDeque::new(),
            max_records: max_records.max(1),
        }
    }

    fn remember(&mut self, batch_id: String, record: BatchRecord) {
        if !self.records.contains_key(&batch_id) {
            self.order.push_back(batch_id.clone());
        }
        self.records.insert(batch_id, record);

        while self.records.len() > self.max_records {
            let Some(expired) = self.order.pop_front() else {
                break;
            };
            self.records.remove(&expired);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "status")]
enum BatchStatus {
    Accepted {
        digests: Vec<String>,
    },
    Finalized {
        height: u64,
        included: Vec<String>,
    },
    PartiallyFinalized {
        height: u64,
        included: Vec<String>,
        filtered: Vec<String>,
    },
    Dropped {
        filtered: Vec<String>,
    },
}

#[derive(Debug)]
enum ForwardResult {
    Accepted {
        leader: Leader,
        digests: Vec<String>,
    },
    Deterministic(StatusCode),
    Transient,
}

#[derive(Debug, Deserialize, Serialize)]
struct IngestResponse {
    digests: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ConsensusRoundResponse {
    round: u64,
}

fn main() {
    let cli = Cli::parse();
    let config = load_config(&cli.config);

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    let runtime = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    runtime.block_on(async move {
        let state = build_state(config);
        let listen = state.listen_addr();
        tokio::spawn(poll_consensus_rounds(state.clone()));
        let app = router(state);
        info!(%listen, "relayer listening");
        let listener = tokio::net::TcpListener::bind(listen)
            .await
            .expect("failed to bind relayer listener");
        axum::serve(listener, app)
            .await
            .expect("relayer HTTP server exited");
    });
}

fn router(state: AppState) -> Router {
    let max_request_bytes = state
        .max_batch_bytes
        .saturating_add(MAX_BATCH_LENGTH_PREFIX_BYTES);
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE]);

    Router::new()
        .route("/transactions", post(submit_transactions))
        .route("/transactions/{batch_id}", get(transaction_status))
        .route("/account/{public_key}", get(account))
        .route("/health", get(health))
        .route("/ready", get(ready))
        .layer(DefaultBodyLimit::max(max_request_bytes))
        .layer(cors)
        .with_state(state)
}

async fn submit_transactions(State(state): State<AppState>, body: Bytes) -> (StatusCode, String) {
    if body.len()
        > state
            .max_batch_bytes
            .saturating_add(MAX_BATCH_LENGTH_PREFIX_BYTES)
    {
        return (StatusCode::PAYLOAD_TOO_LARGE, String::new());
    }

    let batch_id = sha256::Sha256::hash(&body).to_string();
    let next_round = state.observed_round.load(Ordering::Relaxed).wrapping_add(1);
    let targets = leader_targets(&state.leaders, state.leader_fanout, next_round);
    if targets.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
    }

    let (tx, mut rx) = mpsc::channel(targets.len());
    for leader in targets {
        let tx = tx.clone();
        let http = state.http.clone();
        let body = body.clone();
        tokio::spawn(async move {
            let result = forward_to_leader(http, leader, body).await;
            let _ = tx.send(result).await;
        });
    }
    drop(tx);

    let mut deterministic = None;
    let mut transient_failures = 0;
    let mut acknowledged = Vec::new();
    let mut digests = Vec::new();
    let timeout = tokio::time::sleep(state.ack_timeout);
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => break,
            Some(result) = rx.recv() => match result {
                ForwardResult::Accepted { leader, digests: accepted_digests } => {
                    acknowledged.push(leader);
                    digests = accepted_digests;
                    break;
                }
                ForwardResult::Deterministic(status) => deterministic = Some(status),
                ForwardResult::Transient => transient_failures += 1,
            },
            else => break,
        }
    }

    if acknowledged.is_empty() {
        let status = deterministic.unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
        warn!(
            batch_id,
            status = status.as_u16(),
            transient_failures,
            "relayer submission failed before acknowledgement"
        );
        return (status, String::new());
    }

    let acknowledged_leaders = acknowledged
        .iter()
        .map(|leader| leader.public_key.clone())
        .collect::<Vec<_>>();
    record_batch(&state, batch_id.clone(), acknowledged_leaders.clone()).await;
    tokio::spawn(collect_late_acknowledgements(
        state.batches.clone(),
        batch_id.clone(),
        rx,
    ));
    let response = SubmitResponse {
        batch_id,
        digests,
        acknowledged_leaders,
    };
    (
        StatusCode::ACCEPTED,
        serde_json::to_string(&response).expect("submit response serialization cannot fail"),
    )
}

async fn transaction_status(
    State(state): State<AppState>,
    Path(batch_id): Path<String>,
) -> (StatusCode, String) {
    let Some(record) = state.batches.read().await.records.get(&batch_id).cloned() else {
        return (StatusCode::NOT_FOUND, String::new());
    };

    fetch_leader_status(&state, &batch_id, &record)
        .await
        .map_or_else(
            || (StatusCode::SERVICE_UNAVAILABLE, String::new()),
            |status| {
                (
                    StatusCode::OK,
                    serde_json::to_string(&status)
                        .expect("status response serialization cannot fail"),
                )
            },
        )
}

async fn account(
    State(state): State<AppState>,
    Path(public_key): Path<String>,
) -> (StatusCode, String) {
    let Some(leader) = state.leaders.first() else {
        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
    };
    if from_hex(&public_key).is_none() {
        return (StatusCode::BAD_REQUEST, String::new());
    }

    match state
        .http
        .get(format!("{}/account/{public_key}", leader.url))
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            (status, body)
        }
        Err(error) => {
            warn!(%error, "account proxy failed");
            (StatusCode::SERVICE_UNAVAILABLE, String::new())
        }
    }
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn ready(State(state): State<AppState>) -> StatusCode {
    if state.leaders.is_empty() {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    StatusCode::OK
}

async fn forward_to_leader(http: reqwest::Client, leader: Leader, body: Bytes) -> ForwardResult {
    let mut backoff = Duration::from_millis(50);
    for attempt in 0..3 {
        match http
            .post(format!("{}/transactions/ingest", leader.url))
            .header("content-type", "application/octet-stream")
            .body(body.clone())
            .send()
            .await
        {
            Ok(response) if response.status() == StatusCode::ACCEPTED => {
                let bytes = match response.bytes().await {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        debug!(
                            leader = %leader.public_key,
                            %error,
                            attempt,
                            "leader ingest acknowledgement unreadable"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff *= 2;
                        continue;
                    }
                };
                let ack = match serde_json::from_slice::<IngestResponse>(&bytes) {
                    Ok(ack) => ack,
                    Err(error) => {
                        debug!(
                            leader = %leader.public_key,
                            %error,
                            attempt,
                            "leader ingest acknowledgement malformed"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff *= 2;
                        continue;
                    }
                };
                return ForwardResult::Accepted {
                    leader,
                    digests: ack.digests,
                };
            }
            Ok(response)
                if response.status() == StatusCode::BAD_REQUEST
                    || response.status() == StatusCode::PAYLOAD_TOO_LARGE =>
            {
                return ForwardResult::Deterministic(response.status());
            }
            Ok(response) => debug!(
                leader = %leader.public_key,
                status = response.status().as_u16(),
                attempt,
                "leader ingest failed"
            ),
            Err(error) => debug!(
                leader = %leader.public_key,
                %error,
                attempt,
                "leader ingest request failed"
            ),
        }
        tokio::time::sleep(backoff).await;
        backoff *= 2;
    }
    ForwardResult::Transient
}

async fn record_batch(state: &AppState, batch_id: String, acknowledged_leaders: Vec<String>) {
    let record = BatchRecord {
        acknowledged_leaders,
    };
    state.batches.write().await.remember(batch_id, record);
}

async fn collect_late_acknowledgements(
    batches: Arc<RwLock<TrackedBatches>>,
    batch_id: String,
    mut rx: mpsc::Receiver<ForwardResult>,
) {
    while let Some(result) = rx.recv().await {
        let ForwardResult::Accepted { leader, .. } = result else {
            continue;
        };
        let mut batches = batches.write().await;
        let Some(record) = batches.records.get_mut(&batch_id) else {
            return;
        };
        if record
            .acknowledged_leaders
            .iter()
            .any(|existing| existing == &leader.public_key)
        {
            continue;
        }
        record.acknowledged_leaders.push(leader.public_key);
    }
}

async fn fetch_leader_status(
    state: &AppState,
    batch_id: &str,
    record: &BatchRecord,
) -> Option<BatchStatus> {
    let mut accepted = None;
    let mut terminal = Vec::new();
    for leader_id in &record.acknowledged_leaders {
        let Some(leader) = leader_by_id(&state.leaders, leader_id) else {
            continue;
        };
        let Some(status) = fetch_status_from_leader(&state.http, leader, batch_id).await else {
            continue;
        };
        match status {
            BatchStatus::Accepted { .. } => accepted = Some(status),
            BatchStatus::Finalized { .. } => return Some(status),
            BatchStatus::PartiallyFinalized { .. } | BatchStatus::Dropped { .. } => {
                terminal.push(status);
            }
        }
    }
    merge_terminal_statuses(&terminal).or(accepted)
}

fn merge_terminal_statuses(statuses: &[BatchStatus]) -> Option<BatchStatus> {
    let mut height = 0;
    let mut included = Vec::new();
    let mut included_set = HashSet::new();
    let mut filtered = Vec::new();
    let mut filtered_set = HashSet::new();

    for status in statuses {
        match status {
            BatchStatus::Accepted { .. } => {}
            BatchStatus::Finalized {
                height: finalized_height,
                included: finalized,
            } => {
                return Some(BatchStatus::Finalized {
                    height: *finalized_height,
                    included: finalized.clone(),
                });
            }
            BatchStatus::PartiallyFinalized {
                height: finalized_height,
                included: leader_included,
                filtered: leader_filtered,
            } => {
                height = height.max(*finalized_height);
                push_unique(leader_included, &mut included, &mut included_set);
                push_unique(leader_filtered, &mut filtered, &mut filtered_set);
            }
            BatchStatus::Dropped {
                filtered: leader_filtered,
            } => push_unique(leader_filtered, &mut filtered, &mut filtered_set),
        }
    }

    if included.is_empty() && filtered.is_empty() {
        return None;
    }

    filtered.retain(|digest| !included_set.contains(digest));
    if included.is_empty() {
        return Some(BatchStatus::Dropped { filtered });
    }
    if filtered.is_empty() {
        return Some(BatchStatus::Finalized { height, included });
    }
    Some(BatchStatus::PartiallyFinalized {
        height,
        included,
        filtered,
    })
}

fn push_unique(values: &[String], ordered: &mut Vec<String>, known: &mut HashSet<String>) {
    for value in values {
        if known.insert(value.clone()) {
            ordered.push(value.clone());
        }
    }
}

async fn fetch_status_from_leader(
    http: &reqwest::Client,
    leader: &Leader,
    batch_id: &str,
) -> Option<BatchStatus> {
    let response = http
        .get(format!("{}/transactions/{batch_id}", leader.url))
        .send()
        .await
        .ok()?;
    if response.status() == StatusCode::NOT_FOUND {
        return None;
    }
    if response.status() != StatusCode::OK {
        return None;
    }
    let bytes = response.bytes().await.ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn leader_by_id<'a>(leaders: &'a [Leader], leader_id: &str) -> Option<&'a Leader> {
    leaders.iter().find(|leader| leader.public_key == leader_id)
}

async fn poll_consensus_rounds(state: AppState) {
    let mut interval = tokio::time::interval(state.round_poll);
    loop {
        interval.tick().await;
        for leader in state.leaders.iter() {
            let Some(round) = fetch_consensus_round(&state.http, leader).await else {
                continue;
            };
            let mut current = state.observed_round.load(Ordering::Relaxed);
            while round > current {
                match state.observed_round.compare_exchange_weak(
                    current,
                    round,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(next) => current = next,
                }
            }
        }
    }
}

async fn fetch_consensus_round(http: &reqwest::Client, leader: &Leader) -> Option<u64> {
    let response = http
        .get(format!("{}/consensus/round", leader.url))
        .send()
        .await
        .ok()?;
    if response.status() != StatusCode::OK {
        return None;
    }
    let bytes = response.bytes().await.ok()?;
    serde_json::from_slice::<ConsensusRoundResponse>(&bytes)
        .ok()
        .map(|response| response.round)
}

fn leader_targets(leaders: &[Leader], leader_fanout: usize, next_round: u64) -> Vec<Leader> {
    if leaders.is_empty() {
        return Vec::new();
    }
    let count = leader_fanout.min(leaders.len());
    let start = next_round as usize % leaders.len();
    (0..count)
        .map(|offset| leaders[(start + offset) % leaders.len()].clone())
        .collect()
}

fn build_state(config: RelayerConfig) -> AppState {
    let listen = config.listen;
    let ack_timeout_ms = config.ack_timeout_ms;
    let round_poll_ms = config.round_poll_ms;
    let max_batch_bytes = config.max_batch_bytes;
    let max_tracked_batches = config.max_tracked_batches;
    let configured_fanout = config.leader_fanout;
    let mut leaders = config
        .leaders
        .into_iter()
        .map(|leader| Leader {
            sort_key: leader_sort_key(&leader.public_key),
            public_key: leader.public_key.to_lowercase(),
            url: trim_trailing_slash(leader.url),
        })
        .collect::<Vec<_>>();
    leaders.sort_by(|left, right| {
        left.sort_key
            .cmp(&right.sort_key)
            .then_with(|| left.public_key.cmp(&right.public_key))
    });
    reject_duplicate_leaders(&leaders);
    let leader_count = leaders.len();
    let leader_fanout = configured_fanout
        .unwrap_or_else(|| 3.min(leader_count))
        .max(1);

    AppState {
        leaders: Arc::new(leaders),
        leader_fanout,
        ack_timeout: Duration::from_millis(ack_timeout_ms),
        round_poll: Duration::from_millis(round_poll_ms),
        max_batch_bytes,
        batches: Arc::new(RwLock::new(TrackedBatches::new(max_tracked_batches))),
        observed_round: Arc::new(AtomicU64::new(0)),
        http: reqwest::Client::new(),
        listen,
    }
}

impl AppState {
    const fn listen_addr(&self) -> SocketAddr {
        self.listen
    }
}

fn load_config(path: &PathBuf) -> RelayerConfig {
    let raw = std::fs::read_to_string(path).expect("failed to read relayer config");
    serde_yaml::from_str(&raw).expect("failed to parse relayer config")
}

fn trim_trailing_slash(url: String) -> String {
    url.trim_end_matches('/').to_string()
}

fn leader_sort_key(public_key: &str) -> Vec<u8> {
    from_hex(public_key)
        .unwrap_or_else(|| panic!("leader public_key must be hex-encoded: {public_key}"))
}

fn reject_duplicate_leaders(leaders: &[Leader]) {
    for pair in leaders.windows(2) {
        if pair[0].sort_key == pair[1].sort_key {
            panic!("duplicate leader public_key: {}", pair[1].public_key);
        }
    }
}

fn default_listen() -> SocketAddr {
    DEFAULT_LISTEN.parse().expect("default listen is valid")
}

const fn default_ack_timeout_ms() -> u64 {
    DEFAULT_ACK_TIMEOUT_MS
}

const fn default_round_poll_ms() -> u64 {
    DEFAULT_ROUND_POLL_MS
}

const fn default_max_batch_bytes() -> usize {
    DEFAULT_MAX_BATCH_BYTES
}

const fn default_max_tracked_batches() -> usize {
    DEFAULT_MAX_TRACKED_BATCHES
}

#[cfg(test)]
mod tests {
    use super::{
        AppState, BatchStatus, DEFAULT_ACK_TIMEOUT_MS, DEFAULT_MAX_BATCH_BYTES,
        DEFAULT_MAX_TRACKED_BATCHES, DEFAULT_ROUND_POLL_MS, Leader, TrackedBatches, leader_targets,
        merge_terminal_statuses,
    };
    use std::{
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    };
    use tokio::sync::RwLock;

    fn leader(key: &str) -> Leader {
        Leader {
            public_key: key.to_string(),
            sort_key: commonware_formatting::from_hex(key).expect("test key is hex"),
            url: format!("http://{key}"),
        }
    }

    #[test]
    fn leader_targets_rotate_from_next_round_and_deduplicate() {
        let leaders = ["01", "02", "00"]
            .into_iter()
            .map(leader)
            .collect::<Vec<_>>();
        let mut sorted = leaders;
        sorted.sort_by(|left, right| left.sort_key.cmp(&right.sort_key));

        let targets = leader_targets(&sorted, 3, 1)
            .into_iter()
            .map(|leader| leader.public_key)
            .collect::<Vec<_>>();

        assert_eq!(targets, vec!["01", "02", "00"]);
    }

    #[test]
    fn leader_targets_caps_fanout_at_unique_leaders() {
        let leaders = ["00", "01"].into_iter().map(leader).collect::<Vec<_>>();

        let targets = leader_targets(&leaders, 5, 0);

        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn default_fanout_includes_multiple_leaders() {
        let state = AppState {
            leaders: Arc::new(vec![leader("00"), leader("01"), leader("02"), leader("03")]),
            leader_fanout: 3,
            ack_timeout: Duration::from_millis(DEFAULT_ACK_TIMEOUT_MS),
            round_poll: Duration::from_millis(DEFAULT_ROUND_POLL_MS),
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            batches: Arc::new(RwLock::new(TrackedBatches::new(
                DEFAULT_MAX_TRACKED_BATCHES,
            ))),
            observed_round: Arc::new(AtomicU64::new(0)),
            http: reqwest::Client::new(),
            listen: "127.0.0.1:0".parse().expect("listen address parses"),
        };

        let next_round = state.observed_round.load(Ordering::Relaxed).wrapping_add(1);
        let targets = leader_targets(&state.leaders, state.leader_fanout, next_round);

        assert_eq!(targets.len(), 3);
        assert_eq!(
            targets
                .into_iter()
                .map(|leader| leader.public_key)
                .collect::<Vec<_>>(),
            vec!["01", "02", "03"],
        );
    }

    #[test]
    fn status_merge_prefers_finalized_over_dropped() {
        let statuses = vec![
            BatchStatus::Dropped {
                filtered: vec!["aa".to_string()],
            },
            BatchStatus::Finalized {
                height: 9,
                included: vec!["aa".to_string()],
            },
        ];

        let status = merge_terminal_statuses(&statuses);

        assert_eq!(
            status,
            Some(BatchStatus::Finalized {
                height: 9,
                included: vec!["aa".to_string()],
            }),
        );
    }

    #[test]
    fn status_merge_combines_partial_inclusion() {
        let statuses = vec![
            BatchStatus::PartiallyFinalized {
                height: 7,
                included: vec!["aa".to_string()],
                filtered: vec!["bb".to_string()],
            },
            BatchStatus::PartiallyFinalized {
                height: 8,
                included: vec!["bb".to_string()],
                filtered: vec!["aa".to_string()],
            },
        ];

        let status = merge_terminal_statuses(&statuses);

        assert_eq!(
            status,
            Some(BatchStatus::Finalized {
                height: 8,
                included: vec!["aa".to_string(), "bb".to_string()],
            }),
        );
    }
}
