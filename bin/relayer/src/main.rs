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
const UNHEALTHY_FAILURES: u32 = 3;

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
    leader_health: Arc<RwLock<HashMap<String, LeaderHealth>>>,
    observed_round: Arc<AtomicU64>,
    http: reqwest::Client,
    listen: SocketAddr,
}

#[derive(Debug, Clone, Serialize)]
struct SubmitResponse {
    batch_id: String,
    digests: Vec<String>,
    acknowledged_leaders: Vec<String>,
    targeted_leaders: Vec<String>,
}

#[derive(Debug, Clone)]
struct BatchRecord {
    acknowledged_leaders: Vec<String>,
    targeted_leaders: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct LeaderHealth {
    consecutive_failures: u32,
    healthy: bool,
}

impl LeaderHealth {
    const fn new() -> Self {
        Self {
            consecutive_failures: 0,
            healthy: true,
        }
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.healthy = true;
    }

    fn record_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= UNHEALTHY_FAILURES {
            self.healthy = false;
        }
    }
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
    Transient {
        leader: Leader,
    },
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
    let observed_round = state.observed_round.load(Ordering::Relaxed);
    let health = state.leader_health.read().await.clone();
    let targets = leader_targets(&state.leaders, &health, state.leader_fanout, observed_round);
    if targets.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
    }
    let targeted_leaders = targets
        .iter()
        .map(|leader| leader.public_key.clone())
        .collect::<Vec<_>>();

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
                    record_leader_success(&state, &leader.public_key).await;
                    acknowledged.push(leader);
                    digests = accepted_digests;
                    break;
                }
                ForwardResult::Deterministic(status) => deterministic = Some(status),
                ForwardResult::Transient { leader } => {
                    record_leader_failure(&state, &leader.public_key).await;
                    transient_failures += 1;
                }
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
    record_batch(
        &state,
        batch_id.clone(),
        acknowledged_leaders.clone(),
        targeted_leaders.clone(),
    )
    .await;
    tokio::spawn(collect_late_acknowledgements(
        state.leader_health.clone(),
        state.batches.clone(),
        batch_id.clone(),
        rx,
    ));
    let response = SubmitResponse {
        batch_id,
        digests,
        acknowledged_leaders,
        targeted_leaders,
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
    ForwardResult::Transient { leader }
}

async fn record_batch(
    state: &AppState,
    batch_id: String,
    acknowledged_leaders: Vec<String>,
    targeted_leaders: Vec<String>,
) {
    let record = BatchRecord {
        acknowledged_leaders,
        targeted_leaders,
    };
    state.batches.write().await.remember(batch_id, record);
}

async fn collect_late_acknowledgements(
    leader_health: Arc<RwLock<HashMap<String, LeaderHealth>>>,
    batches: Arc<RwLock<TrackedBatches>>,
    batch_id: String,
    mut rx: mpsc::Receiver<ForwardResult>,
) {
    while let Some(result) = rx.recv().await {
        match result {
            ForwardResult::Accepted { leader, .. } => {
                record_leader_success_map(&leader_health, &leader.public_key).await;
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
            ForwardResult::Transient { leader } => {
                record_leader_failure_map(&leader_health, &leader.public_key).await;
            }
            ForwardResult::Deterministic(_) => {}
        };
    }
}

async fn fetch_leader_status(
    state: &AppState,
    batch_id: &str,
    record: &BatchRecord,
) -> Option<BatchStatus> {
    let mut accepted = None;
    let mut terminal = Vec::new();
    for leader_id in status_leaders(record) {
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
    accepted.or_else(|| merge_terminal_statuses(&terminal))
}

fn status_leaders(record: &BatchRecord) -> Vec<&String> {
    let mut seen = HashSet::new();
    let mut leaders = Vec::new();
    for leader in record
        .targeted_leaders
        .iter()
        .chain(record.acknowledged_leaders.iter())
    {
        if seen.insert(leader) {
            leaders.push(leader);
        }
    }
    leaders
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
            record_leader_success(&state, &leader.public_key).await;
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

async fn record_leader_success(state: &AppState, leader_id: &str) {
    record_leader_success_map(&state.leader_health, leader_id).await;
}

async fn record_leader_failure(state: &AppState, leader_id: &str) {
    record_leader_failure_map(&state.leader_health, leader_id).await;
}

async fn record_leader_success_map(
    health: &RwLock<HashMap<String, LeaderHealth>>,
    leader_id: &str,
) {
    let mut health = health.write().await;
    health
        .entry(leader_id.to_string())
        .or_insert_with(LeaderHealth::new)
        .record_success();
}

async fn record_leader_failure_map(
    health: &RwLock<HashMap<String, LeaderHealth>>,
    leader_id: &str,
) {
    let mut health = health.write().await;
    health
        .entry(leader_id.to_string())
        .or_insert_with(LeaderHealth::new)
        .record_failure();
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

fn leader_targets(
    leaders: &[Leader],
    health: &HashMap<String, LeaderHealth>,
    leader_fanout: usize,
    round: u64,
) -> Vec<Leader> {
    if leaders.is_empty() {
        return Vec::new();
    }
    let count = leader_fanout.min(leaders.len());
    let ordered = leader_window(leaders, round);
    if count == leaders.len() {
        return ordered;
    }

    let mut targets = Vec::with_capacity(count);
    let mut fallback = Vec::new();
    for leader in ordered {
        if is_healthy(&leader, health) {
            targets.push(leader);
        } else {
            fallback.push(leader);
        }
        if targets.len() == count {
            return targets;
        }
    }

    for leader in fallback {
        targets.push(leader);
        if targets.len() == count {
            break;
        }
    }
    targets
}

fn leader_window(leaders: &[Leader], round: u64) -> Vec<Leader> {
    let start = round as usize % leaders.len();
    (0..leaders.len())
        .map(|offset| leaders[(start + offset) % leaders.len()].clone())
        .collect()
}

fn is_healthy(leader: &Leader, health: &HashMap<String, LeaderHealth>) -> bool {
    match health.get(&leader.public_key) {
        Some(health) => health.healthy,
        None => true,
    }
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
        .unwrap_or(leader_count)
        .max(usize::from(leader_count > 0));
    let leader_health = leaders
        .iter()
        .map(|leader| (leader.public_key.clone(), LeaderHealth::new()))
        .collect();

    AppState {
        leaders: Arc::new(leaders),
        leader_fanout,
        ack_timeout: Duration::from_millis(ack_timeout_ms),
        round_poll: Duration::from_millis(round_poll_ms),
        max_batch_bytes,
        batches: Arc::new(RwLock::new(TrackedBatches::new(max_tracked_batches))),
        leader_health: Arc::new(RwLock::new(leader_health)),
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
        DEFAULT_MAX_TRACKED_BATCHES, DEFAULT_ROUND_POLL_MS, Leader, LeaderHealth, TrackedBatches,
        leader_targets, merge_terminal_statuses, status_leaders,
    };
    use commonware_codec::Encode;
    use commonware_consensus::{
        simplex::{
            elector::{Config as ElectorConfig, Elector, RoundRobin, RoundRobinElector},
            scheme::ed25519 as consensus_ed25519,
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{Signer, ed25519, sha256};
    use commonware_formatting::hex;
    use commonware_utils::ordered::Set;
    use std::{
        collections::HashMap,
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
    fn leader_targets_rotate_from_current_round_and_deduplicate() {
        let leaders = ["01", "02", "00"]
            .into_iter()
            .map(leader)
            .collect::<Vec<_>>();
        let mut sorted = leaders;
        sorted.sort_by(|left, right| left.sort_key.cmp(&right.sort_key));

        let targets = leader_targets(&sorted, &HashMap::new(), 3, 1)
            .into_iter()
            .map(|leader| leader.public_key)
            .collect::<Vec<_>>();

        assert_eq!(targets, vec!["01", "02", "00"]);
    }

    #[test]
    fn leader_targets_caps_fanout_at_unique_leaders() {
        let leaders = ["00", "01"].into_iter().map(leader).collect::<Vec<_>>();

        let targets = leader_targets(&leaders, &HashMap::new(), 5, 0);

        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn default_fanout_includes_all_leaders() {
        let state = AppState {
            leaders: Arc::new(vec![leader("00"), leader("01"), leader("02"), leader("03")]),
            leader_fanout: 4,
            ack_timeout: Duration::from_millis(DEFAULT_ACK_TIMEOUT_MS),
            round_poll: Duration::from_millis(DEFAULT_ROUND_POLL_MS),
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            batches: Arc::new(RwLock::new(TrackedBatches::new(
                DEFAULT_MAX_TRACKED_BATCHES,
            ))),
            leader_health: Arc::new(RwLock::new(HashMap::new())),
            observed_round: Arc::new(AtomicU64::new(0)),
            http: reqwest::Client::new(),
            listen: "127.0.0.1:0".parse().expect("listen address parses"),
        };

        let round = state.observed_round.load(Ordering::Relaxed);
        let targets = leader_targets(&state.leaders, &HashMap::new(), state.leader_fanout, round);

        assert_eq!(targets.len(), 4);
        assert_eq!(
            targets
                .into_iter()
                .map(|leader| leader.public_key)
                .collect::<Vec<_>>(),
            vec!["00", "01", "02", "03"],
        );
    }

    #[test]
    fn leader_targets_scan_past_unhealthy_leaders_for_partial_fanout() {
        let leaders = ["00", "01", "02", "03"]
            .into_iter()
            .map(leader)
            .collect::<Vec<_>>();
        let mut health = HashMap::new();
        health.insert(
            "01".to_string(),
            LeaderHealth {
                consecutive_failures: 3,
                healthy: false,
            },
        );

        let targets = leader_targets(&leaders, &health, 2, 1)
            .into_iter()
            .map(|leader| leader.public_key)
            .collect::<Vec<_>>();

        assert_eq!(targets, vec!["02", "03"]);
    }

    #[test]
    fn leader_targets_include_unhealthy_leaders_for_all_primary_fanout() {
        let leaders = ["00", "01", "02"]
            .into_iter()
            .map(leader)
            .collect::<Vec<_>>();
        let mut health = HashMap::new();
        health.insert(
            "01".to_string(),
            LeaderHealth {
                consecutive_failures: 3,
                healthy: false,
            },
        );

        let targets = leader_targets(&leaders, &health, 3, 1)
            .into_iter()
            .map(|leader| leader.public_key)
            .collect::<Vec<_>>();

        assert_eq!(targets, vec!["01", "02", "00"]);
    }

    #[test]
    fn leader_targets_match_commonware_round_robin_order() {
        let keys = [7, 3, 11, 5]
            .into_iter()
            .map(|seed| ed25519::PrivateKey::from_seed(seed).public_key())
            .collect::<Vec<_>>();
        let participants = Set::from_iter_dedup(keys.clone());
        let elector: RoundRobinElector<consensus_ed25519::Scheme> =
            RoundRobin::<sha256::Sha256>::default().build(&participants);
        let mut leaders = keys
            .into_iter()
            .map(|key| leader(&hex(&key.encode())))
            .collect::<Vec<_>>();
        leaders.sort_by(|left, right| left.sort_key.cmp(&right.sort_key));

        for view in 0..12 {
            let round = Round::new(Epoch::new(0), View::new(view));
            let elected = elector.elect(round, None);
            let expected = hex(&participants
                .get(usize::from(elected))
                .expect("elected participant exists")
                .encode());
            let target = leader_targets(&leaders, &HashMap::new(), 1, view)
                .pop()
                .expect("target exists");

            assert_eq!(target.public_key, expected);
        }
    }

    #[test]
    fn status_targets_query_targeted_before_late_acknowledged_leaders() {
        let record = super::BatchRecord {
            targeted_leaders: vec!["00".to_string(), "01".to_string()],
            acknowledged_leaders: vec!["01".to_string(), "02".to_string()],
        };
        let leaders = status_leaders(&record)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();

        assert_eq!(leaders, vec!["00", "01", "02"]);
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
