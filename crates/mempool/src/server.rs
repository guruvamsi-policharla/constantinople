//! HTTP mempool server and `TransactionSource` implementation.

use crate::{Finalized, PendingTransaction, SignedTransaction, TransactionSource};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::post,
};
use commonware_codec::{EncodeSize, ReadExt};
use commonware_consensus::{Reporter, simplex::types::Context};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_utils::{from_hex, hex};
use constantinople_primitives::Header;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{Mutex, oneshot},
    time::Instant,
};
use tracing::warn;

const MAX_HTTP_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECENT_STATUSES: usize = 1_000_000;
const RECENT_STATUS_TTL: Duration = Duration::from_secs(300);

fn decode_body_hex(body: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    from_hex(body.trim()).ok_or((StatusCode::BAD_REQUEST, "bad hex".to_string()))
}

/// Inclusion confirmation returned to HTTP callers.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InclusionReceipt {
    pub tx_hash: String,
    pub included: bool,
    pub height: u64,
}

/// Immediate submission confirmation returned to HTTP callers.
#[derive(Debug, serde::Serialize)]
pub struct SubmissionReceipt {
    pub tx_hash: String,
}

/// Transaction states returned to HTTP callers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    Pending,
    Included,
    Rejected,
    Unknown,
}

/// Status returned for a known transaction hash.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransactionStatus {
    pub tx_hash: String,
    pub state: TransactionState,
    pub height: u64,
}

/// Batch transaction status request body.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TransactionStatusRequest {
    pub tx_hashes: Vec<String>,
}

/// Batch transaction status response body.
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransactionStatusResponse {
    pub statuses: Vec<TransactionStatus>,
}

/// Mempool size limits.
#[derive(Debug, Clone, Copy)]
pub struct MempoolConfig {
    /// Maximum bytes of transactions to return in a single `propose()` call.
    pub max_propose_bytes: usize,
    /// Maximum bytes of pending transactions before rejecting new submissions.
    pub max_pool_bytes: usize,
    /// How long a proposed transaction stays leased before it may be reproposed.
    pub proposal_lease_duration: Duration,
}

#[derive(Debug)]
struct TrackedTransaction<H: Hasher, P: PublicKey> {
    tx: PendingTransaction<P, H>,
    leased_until: Option<Instant>,
}

impl<H: Hasher, P: PublicKey> TrackedTransaction<H, P> {
    fn new(tx: PendingTransaction<P, H>) -> Self {
        Self {
            tx,
            leased_until: None,
        }
    }

    fn expire_lease(&mut self, now: Instant) {
        if let Some(leased_until) = self.leased_until
            && leased_until <= now
        {
            self.leased_until = None;
        }
    }

    fn is_leased(&self) -> bool {
        self.leased_until.is_some()
    }
}

#[derive(Debug, Clone)]
struct RecentTransactionStatus {
    status: TransactionStatus,
    recorded_at: Instant,
}

/// Shared mempool state between HTTP handlers and the TransactionSource.
struct MempoolInner<H: Hasher, P: PublicKey> {
    order: VecDeque<Vec<u8>>,
    transactions: HashMap<Vec<u8>, TrackedTransaction<H, P>>,
    pending_bytes: usize,
    waiters: HashMap<Vec<u8>, Vec<oneshot::Sender<InclusionReceipt>>>,
    recent_order: VecDeque<Vec<u8>>,
    recent_statuses: HashMap<Vec<u8>, RecentTransactionStatus>,
}

/// HTTP mempool that implements `TransactionSource`.
pub struct Mempool<C, P, H>
where
    H: Hasher,
    P: PublicKey,
{
    inner: Arc<Mutex<MempoolInner<H, P>>>,
    config: MempoolConfig,
    transaction_namespace: &'static [u8],
    _marker: std::marker::PhantomData<C>,
}

impl<C, P, H> Clone for Mempool<C, P, H>
where
    H: Hasher,
    P: PublicKey,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            config: self.config,
            transaction_namespace: self.transaction_namespace,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<C, P, H> Mempool<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    pub fn new(transaction_namespace: &'static [u8], config: MempoolConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MempoolInner {
                order: VecDeque::new(),
                transactions: HashMap::new(),
                pending_bytes: 0,
                waiters: HashMap::new(),
                recent_order: VecDeque::new(),
                recent_statuses: HashMap::new(),
            })),
            config,
            transaction_namespace,
            _marker: std::marker::PhantomData,
        }
    }

    /// Notifies waiters that their transactions were included in a block.
    pub async fn notify_included(&self, height: u64, transaction_hashes: &[H::Digest]) {
        let mut inner = self.inner.lock().await;
        for hash in transaction_hashes {
            resolve_transaction(
                &mut inner,
                hash.as_ref().to_vec(),
                InclusionReceipt {
                    tx_hash: hex(hash.as_ref()),
                    included: true,
                    height,
                },
            );
        }
    }

    /// Notifies waiters that their transactions were rejected.
    pub async fn notify_rejected(&self, rejected_hashes: &[H::Digest]) {
        let mut inner = self.inner.lock().await;
        for hash in rejected_hashes {
            let hash_bytes = hash.as_ref().to_vec();
            resolve_transaction(
                &mut inner,
                hash_bytes.clone(),
                InclusionReceipt {
                    tx_hash: hex(&hash_bytes),
                    included: false,
                    height: 0,
                },
            );
        }
    }
}

impl<C, P, H> Reporter for Mempool<C, P, H>
where
    C: Digest + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    H: Hasher + Send + Sync + 'static,
{
    type Activity = Finalized<C, P, H>;

    async fn report(&mut self, finalized: Self::Activity) {
        let height = finalized.block.header.height;
        let transaction_hashes = finalized
            .block
            .body
            .iter()
            .map(|transaction| *transaction.message_digest())
            .collect::<Vec<_>>();
        self.notify_included(height, &transaction_hashes).await;
    }
}

impl<C, P, H> TransactionSource<C, P, H> for Mempool<C, P, H>
where
    C: Digest + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    H: Hasher + Send + Sync + 'static,
{
    fn propose(
        &mut self,
        _parent: &Header<C, H::Digest, P>,
        _context: &Context<C, P>,
    ) -> impl std::future::Future<Output = Vec<PendingTransaction<P, H>>> + Send {
        let inner = self.inner.clone();
        let max_bytes = self.config.max_propose_bytes;
        let proposal_lease_duration = self.config.proposal_lease_duration;
        async move {
            let mut guard = inner.lock().await;
            let mut batch = Vec::new();
            let mut batch_bytes = 0;
            let now = Instant::now();
            let queued_hashes = guard.order.iter().cloned().collect::<Vec<_>>();

            for hash in queued_hashes {
                let Some(tracked) = guard.transactions.get_mut(&hash) else {
                    continue;
                };

                tracked.expire_lease(now);
                if tracked.is_leased() {
                    continue;
                }

                let tx_bytes = tracked.tx.encode_size();
                if batch_bytes + tx_bytes > max_bytes && !batch.is_empty() {
                    break;
                }

                tracked.leased_until = Some(now + proposal_lease_duration);
                batch_bytes += tx_bytes;
                batch.push(tracked.tx.clone());
            }

            batch
        }
    }
}

async fn submit_tx<C, P, H>(
    State(state): State<Arc<RouterState<C, P, H>>>,
    body: String,
) -> Result<Json<InclusionReceipt>, (StatusCode, String)>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let tx = decode_transaction(&state, &body)?;
    let (_hash, _tx_hash_hex, receiver) = enqueue_transaction(&state, tx, true).await?;

    match tokio::time::timeout(Duration::from_secs(30), receiver).await {
        Ok(Ok(receipt)) => Ok(Json(receipt)),
        Ok(Err(_)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "waiter dropped".to_string(),
        )),
        Err(_) => Err((StatusCode::REQUEST_TIMEOUT, "inclusion timeout".to_string())),
    }
}

async fn accept_tx<C, P, H>(
    State(state): State<Arc<RouterState<C, P, H>>>,
    body: String,
) -> Result<(StatusCode, Json<SubmissionReceipt>), (StatusCode, String)>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let tx = decode_transaction(&state, &body)?;
    let (_hash, tx_hash_hex, _) = enqueue_transaction(&state, tx, false).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(SubmissionReceipt {
            tx_hash: tx_hash_hex,
        }),
    ))
}

fn decode_transaction<C, P, H>(
    state: &RouterState<C, P, H>,
    body: &str,
) -> Result<PendingTransaction<P, H>, (StatusCode, String)>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let bytes = decode_body_hex(body)?;
    let tx = SignedTransaction::<P, H>::read(&mut &bytes[..])
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad transaction: {e}")))?;

    tx.into_verified(state.namespace)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid signature".to_string()))
}

fn decode_transaction_hash(hash: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    decode_body_hex(hash).map_err(|_| (StatusCode::BAD_REQUEST, "bad tx_hash".to_string()))
}

async fn enqueue_transaction<C, P, H>(
    state: &RouterState<C, P, H>,
    tx: PendingTransaction<P, H>,
    wait_for_inclusion: bool,
) -> Result<(Vec<u8>, String, oneshot::Receiver<InclusionReceipt>), (StatusCode, String)>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let tx_bytes = tx.encode_size();
    let hash = tx.message_digest().as_ref().to_vec();
    let tx_hash_hex = hex(&hash);
    let (sender, receiver) = oneshot::channel();

    {
        let mut inner = state.inner.lock().await;
        if inner.pending_bytes + tx_bytes > state.max_pool_bytes {
            warn!(tx_hash = %tx_hash_hex, "mempool full, rejecting transaction");
            return Err((StatusCode::SERVICE_UNAVAILABLE, "mempool full".to_string()));
        }

        if wait_for_inclusion {
            inner.waiters.entry(hash.clone()).or_default().push(sender);
        }

        if inner.transactions.contains_key(&hash) {
            return Ok((hash, tx_hash_hex, receiver));
        }

        inner.pending_bytes += tx_bytes;
        inner.order.push_back(hash.clone());
        inner
            .transactions
            .insert(hash.clone(), TrackedTransaction::new(tx));
    }
    Ok((hash, tx_hash_hex, receiver))
}

async fn transaction_status<C, P, H>(
    State(state): State<Arc<RouterState<C, P, H>>>,
    Json(request): Json<TransactionStatusRequest>,
) -> Result<Json<TransactionStatusResponse>, (StatusCode, String)>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let requested_hashes = request
        .tx_hashes
        .iter()
        .map(|hash| decode_transaction_hash(hash))
        .collect::<Result<Vec<_>, _>>()?;
    let mut inner = state.inner.lock().await;
    cleanup_recent_statuses(&mut inner, Instant::now());

    let statuses = requested_hashes
        .iter()
        .zip(request.tx_hashes.iter())
        .map(|(hash, hash_hex)| status_for_hash(&inner, hash, hash_hex.clone()))
        .collect();

    Ok(Json(TransactionStatusResponse { statuses }))
}

fn resolve_transaction<H: Hasher, P: PublicKey>(
    inner: &mut MempoolInner<H, P>,
    hash: Vec<u8>,
    receipt: InclusionReceipt,
) {
    if let Some(tracked) = inner.transactions.remove(&hash) {
        inner.pending_bytes -= tracked.tx.encode_size();
    }
    inner.order.retain(|queued_hash| queued_hash != &hash);
    store_recent_status(
        inner,
        hash.clone(),
        transaction_status_from_receipt(&receipt),
    );

    let Some(waiters) = inner.waiters.remove(&hash) else {
        return;
    };

    for waiter in waiters {
        let _ = waiter.send(receipt.clone());
    }
}

fn transaction_status_from_receipt(receipt: &InclusionReceipt) -> TransactionStatus {
    TransactionStatus {
        tx_hash: receipt.tx_hash.clone(),
        state: if receipt.included {
            TransactionState::Included
        } else {
            TransactionState::Rejected
        },
        height: receipt.height,
    }
}

fn cleanup_recent_statuses<H: Hasher, P: PublicKey>(inner: &mut MempoolInner<H, P>, now: Instant) {
    loop {
        let Some(hash) = inner.recent_order.front().cloned() else {
            return;
        };

        let remove = match inner.recent_statuses.get(&hash) {
            Some(recent) if now.duration_since(recent.recorded_at) > RECENT_STATUS_TTL => true,
            Some(_) if inner.recent_statuses.len() > MAX_RECENT_STATUSES => true,
            None => true,
            _ => false,
        };

        if !remove {
            return;
        }

        inner.recent_order.pop_front();
        inner.recent_statuses.remove(&hash);
    }
}

fn store_recent_status<H: Hasher, P: PublicKey>(
    inner: &mut MempoolInner<H, P>,
    hash: Vec<u8>,
    status: TransactionStatus,
) {
    inner.recent_order.push_back(hash.clone());
    inner.recent_statuses.insert(
        hash,
        RecentTransactionStatus {
            status,
            recorded_at: Instant::now(),
        },
    );
    cleanup_recent_statuses(inner, Instant::now());
}

fn status_for_hash<H: Hasher, P: PublicKey>(
    inner: &MempoolInner<H, P>,
    hash: &[u8],
    tx_hash: String,
) -> TransactionStatus {
    if inner.transactions.contains_key(hash) {
        return TransactionStatus {
            tx_hash,
            state: TransactionState::Pending,
            height: 0,
        };
    }

    if let Some(recent) = inner.recent_statuses.get(hash) {
        return recent.status.clone();
    }

    TransactionStatus {
        tx_hash,
        state: TransactionState::Unknown,
        height: 0,
    }
}

struct RouterState<C, P, H>
where
    H: Hasher,
    P: PublicKey,
{
    inner: Arc<Mutex<MempoolInner<H, P>>>,
    namespace: &'static [u8],
    max_pool_bytes: usize,
    _marker: std::marker::PhantomData<C>,
}

/// Creates the axum router for the mempool HTTP API.
pub fn router<C, P, H>(mempool: &Mempool<C, P, H>) -> Router
where
    C: Digest + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    H: Hasher + Send + Sync + 'static,
{
    let state = Arc::new(RouterState {
        inner: mempool.inner.clone(),
        namespace: mempool.transaction_namespace,
        max_pool_bytes: mempool.config.max_pool_bytes,
        _marker: std::marker::PhantomData::<C>,
    });

    Router::new()
        .route("/tx", post(submit_tx::<C, P, H>))
        .route("/tx/accept", post(accept_tx::<C, P, H>))
        .route("/tx/status", post(transaction_status::<C, P, H>))
        .layer(DefaultBodyLimit::max(MAX_HTTP_BODY_BYTES))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::{
        MempoolConfig, MempoolInner, RouterState, SubmissionReceipt, TransactionState,
        TransactionStatusRequest, TransactionStatusResponse, accept_tx, router,
    };
    use axum::{
        Json,
        body::Body,
        extract::State,
        http::{Request, StatusCode},
    };
    use commonware_codec::Encode;
    use commonware_consensus::{
        simplex::types::Context,
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{Digest, Signer, blake3, ed25519};
    use commonware_utils::hex;
    use constantinople_primitives::{Address, Header, Transaction};
    use core::{marker::PhantomData, num::NonZeroU64};
    use std::{sync::Arc, time::Duration};
    use tokio::sync::Mutex;

    const NAMESPACE: &[u8] = b"mempool-test";

    fn test_context() -> Context<blake3::Digest, ed25519::PublicKey> {
        Context {
            round: Round::new(Epoch::zero(), View::zero()),
            leader: ed25519::PrivateKey::from_seed(13).public_key(),
            parent: (View::zero(), blake3::Digest::EMPTY),
        }
    }

    fn test_parent() -> Header<blake3::Digest, blake3::Digest, ed25519::PublicKey> {
        Header {
            context: test_context(),
            parent: blake3::Digest::EMPTY,
            height: 0,
            timestamp: 0,
            state_root: blake3::Digest::EMPTY,
            state_range: commonware_utils::non_empty_range!(0, 1),
            transactions_root: blake3::Digest::EMPTY,
            transactions_range: commonware_utils::non_empty_range!(0, 1),
        }
    }

    fn signed_bytes(nonce: u64) -> Vec<u8> {
        let key = ed25519::PrivateKey::from_seed(7);
        Transaction {
            sender: key.public_key(),
            to: Address::EMPTY,
            value: NonZeroU64::new(1).expect("test value should be non-zero"),
            nonce,
            _digest: PhantomData::<blake3::Digest>,
        }
        .seal_and_sign_verified(&key, NAMESPACE, &mut blake3::Blake3::default())
        .encode()
        .to_vec()
    }

    #[tokio::test]
    async fn accept_tx_enqueues_without_registering_waiter() {
        let state = Arc::new(
            RouterState::<blake3::Digest, ed25519::PublicKey, blake3::Blake3> {
                inner: Arc::new(Mutex::new(MempoolInner {
                    order: Default::default(),
                    transactions: Default::default(),
                    pending_bytes: 0,
                    waiters: Default::default(),
                    recent_order: Default::default(),
                    recent_statuses: Default::default(),
                })),
                namespace: NAMESPACE,
                max_pool_bytes: 1024 * 1024,
                _marker: PhantomData,
            },
        );
        let body = hex(&signed_bytes(0));

        let result = accept_tx::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>(
            State(state.clone()),
            body,
        )
        .await;

        let (status, Json(SubmissionReceipt { tx_hash })) = result.expect("accept should succeed");
        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(!tx_hash.is_empty());

        let inner = state.inner.lock().await;
        assert_eq!(inner.transactions.len(), 1);
        assert!(inner.waiters.is_empty());
    }

    #[tokio::test]
    async fn accept_route_returns_immediately() {
        let mempool = super::Mempool::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>::new(
            NAMESPACE,
            MempoolConfig {
                max_propose_bytes: 1024 * 1024,
                max_pool_bytes: 1024 * 1024,
                proposal_lease_duration: Duration::from_secs(30),
            },
        );
        let app = router(&mempool);
        let request = Request::post("/tx/accept")
            .body(Body::from(hex(&signed_bytes(0))))
            .expect("request should build");

        use tower::ServiceExt;

        let response = app
            .oneshot(request)
            .await
            .expect("accept route should respond");

        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn accept_tx_deduplicates_known_transactions() {
        let state = Arc::new(
            RouterState::<blake3::Digest, ed25519::PublicKey, blake3::Blake3> {
                inner: Arc::new(Mutex::new(MempoolInner {
                    order: Default::default(),
                    transactions: Default::default(),
                    pending_bytes: 0,
                    waiters: Default::default(),
                    recent_order: Default::default(),
                    recent_statuses: Default::default(),
                })),
                namespace: NAMESPACE,
                max_pool_bytes: 1024 * 1024,
                _marker: PhantomData,
            },
        );
        let body = hex(&signed_bytes(0));

        let _ = accept_tx::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>(
            State(state.clone()),
            body.clone(),
        )
        .await
        .expect("first accept should succeed");
        let _ = accept_tx::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>(
            State(state.clone()),
            body,
        )
        .await
        .expect("duplicate accept should succeed");

        let inner = state.inner.lock().await;
        assert_eq!(inner.transactions.len(), 1);
        assert_eq!(inner.order.len(), 1);
    }

    #[tokio::test]
    async fn status_route_reports_pending_and_included_transactions() {
        let mempool = super::Mempool::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>::new(
            NAMESPACE,
            MempoolConfig {
                max_propose_bytes: 1024 * 1024,
                max_pool_bytes: 1024 * 1024,
                proposal_lease_duration: Duration::from_secs(30),
            },
        );
        let pending_hash = {
            let bytes = signed_bytes(0);
            let tx =
                super::decode_transaction::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>(
                    &RouterState {
                        inner: mempool.inner.clone(),
                        namespace: NAMESPACE,
                        max_pool_bytes: 1024 * 1024,
                        _marker: PhantomData::<blake3::Digest>,
                    },
                    &hex(&bytes),
                )
                .expect("transaction should decode");
            let hash = hex(tx.message_digest().as_ref());
            let state = Arc::new(RouterState {
                inner: mempool.inner.clone(),
                namespace: NAMESPACE,
                max_pool_bytes: 1024 * 1024,
                _marker: PhantomData::<blake3::Digest>,
            });
            let _ = accept_tx::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>(
                State(state),
                hex(&bytes),
            )
            .await
            .expect("accept should succeed");
            hash
        };
        let included_digest =
            *super::decode_transaction::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>(
                &RouterState {
                    inner: mempool.inner.clone(),
                    namespace: NAMESPACE,
                    max_pool_bytes: 1024 * 1024,
                    _marker: PhantomData::<blake3::Digest>,
                },
                &hex(&signed_bytes(1)),
            )
            .expect("transaction should decode")
            .message_digest();
        let included_hash = hex(included_digest.as_ref());

        let app = router(&mempool);
        mempool.notify_included(7, &[included_digest]).await;

        let request = Request::post("/tx/status")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&TransactionStatusRequest {
                    tx_hashes: vec![pending_hash.clone(), included_hash.clone()],
                })
                .expect("request should serialize"),
            ))
            .expect("request should build");

        use tower::ServiceExt;

        let response = app
            .oneshot(request)
            .await
            .expect("status route should respond");
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should decode");
        let TransactionStatusResponse { statuses } =
            serde_json::from_slice(&body).expect("response should deserialize");

        assert_eq!(statuses.len(), 2);
        assert_eq!(statuses[0].tx_hash, pending_hash);
        assert_eq!(statuses[0].state, TransactionState::Pending);
        assert_eq!(statuses[1].tx_hash, included_hash);
        assert_eq!(statuses[1].state, TransactionState::Included);
        assert_eq!(statuses[1].height, 7);
    }

    #[tokio::test]
    async fn propose_leases_and_requeues_transactions() {
        use crate::TransactionSource;

        let mut mempool = super::Mempool::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>::new(
            NAMESPACE,
            MempoolConfig {
                max_propose_bytes: 1024 * 1024,
                max_pool_bytes: 1024 * 1024,
                proposal_lease_duration: Duration::from_millis(10),
            },
        );
        let state = Arc::new(RouterState {
            inner: mempool.inner.clone(),
            namespace: NAMESPACE,
            max_pool_bytes: 1024 * 1024,
            _marker: PhantomData::<blake3::Digest>,
        });

        let _ = accept_tx::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>(
            State(state),
            hex(&signed_bytes(0)),
        )
        .await
        .expect("accept should succeed");

        let first = mempool.propose(&test_parent(), &test_context()).await;
        let second = mempool.propose(&test_parent(), &test_context()).await;
        tokio::time::sleep(Duration::from_millis(15)).await;
        let third = mempool.propose(&test_parent(), &test_context()).await;

        assert_eq!(first.len(), 1);
        assert!(second.is_empty());
        assert_eq!(third.len(), 1);
    }

    #[tokio::test]
    async fn notify_included_removes_known_transaction() {
        use crate::TransactionSource;

        let mut mempool = super::Mempool::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>::new(
            NAMESPACE,
            MempoolConfig {
                max_propose_bytes: 1024 * 1024,
                max_pool_bytes: 1024 * 1024,
                proposal_lease_duration: Duration::from_secs(30),
            },
        );
        let state = Arc::new(RouterState {
            inner: mempool.inner.clone(),
            namespace: NAMESPACE,
            max_pool_bytes: 1024 * 1024,
            _marker: PhantomData::<blake3::Digest>,
        });

        let _ = accept_tx::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>(
            State(state),
            hex(&signed_bytes(0)),
        )
        .await
        .expect("accept should succeed");

        let proposed = mempool.propose(&test_parent(), &test_context()).await;
        let hashes = proposed
            .iter()
            .map(|transaction| *transaction.message_digest())
            .collect::<Vec<_>>();
        mempool.notify_included(1, &hashes).await;

        let next = mempool.propose(&test_parent(), &test_context()).await;
        assert!(next.is_empty());
    }
}
