//! HTTP handlers for the mempool webserver.

use super::{
    Mailbox,
    actor::{AccountReaderCell, IngestStatus},
};
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{Method, StatusCode, header::CONTENT_TYPE},
    routing::{get, post},
};
use commonware_codec::{Decode, DecodeExt, Encode, EncodeSize, FixedSize, RangeCfg};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_formatting::{from_hex, hex};
use commonware_parallel::Strategy;
use commonware_runtime::telemetry::traces::TracedExt as _;
use commonware_utils::sys_rng;
use constantinople_primitives::{
    Account, LazySignedTransaction, Nonce, PublicKeyCache, SignedTransaction, TransactionPublicKey,
    TransactionSignature, VerifiedTransaction, verify_transaction_chunks,
};
use std::{fmt::Display, sync::Arc};
use tokio::sync::Semaphore;
use tower_http::cors::{Any, CorsLayer};
use tracing::info_span;

/// Maximum bytes needed to encode the batch-length prefix.
///
/// `commonware-codec` encodes `Vec` lengths as `u32` varints, which fit in at
/// most 5 bytes.
const MAX_BATCH_LENGTH_PREFIX_BYTES: usize = 5;

/// Minimum bytes needed to encode the batch-length prefix.
const MIN_BATCH_LENGTH_PREFIX_BYTES: usize = 1;

/// Minimum bytes needed to encode a `u64` varint.
const MIN_U64_VARINT_BYTES: usize = 1;

/// Maximum ingress batches admitted to CPU verification concurrently, shared
/// across both POST endpoints.
///
/// Ingress decode and verification run on the strategy's worker pool, which
/// consensus execution and block verification also share. Admitting one
/// batch at a time keeps a burst of relayer posts from queueing CPU bursts
/// ahead of consensus-critical work; excess requests wait cheaply on the
/// semaphore in the async layer instead. The owned permit is acquired in
/// `verify_body` -- after the request body is buffered, before the pool job
/// dispatches -- and moves into the job itself, so slow uploads and mailbox
/// waits never hold it and a client disconnect cannot release it while the
/// job runs.
pub(super) const MAX_CONCURRENT_INGRESS: usize = 1;

/// Shared state for HTTP handlers.
pub(super) struct AppState<C, P, H, St>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    pub mailbox: Mailbox<C, P, H>,
    pub namespace: &'static [u8],
    pub max_batch_bytes: usize,
    pub strategy: St,
    pub public_key_cache: PublicKeyCache,
    pub account_reader: AccountReaderCell,
    pub ingress_permits: Arc<Semaphore>,
}

type SharedState<C, P, H, St> = Arc<AppState<C, P, H, St>>;

/// Builds the axum [`Router`] for the mempool HTTP API.
pub(super) fn router<C, P, H, St>(state: SharedState<C, P, H, St>) -> Router
where
    C: Digest + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Display + Send + Sync,
    St: Strategy + Send + Sync + 'static,
{
    let max_request_bytes = max_request_bytes(state.max_batch_bytes);
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE]);

    Router::new()
        .route("/transactions", post(submit_batch::<C, P, H, St>))
        .route("/transactions/ingest", post(ingest_batch::<C, P, H, St>))
        .route("/transactions/{batch_id}", get(fetch_status::<C, P, H, St>))
        .route("/account/{public_key}", get(fetch_account::<C, P, H, St>))
        .layer(DefaultBodyLimit::max(max_request_bytes))
        .layer(cors)
        .with_state(state)
}

const fn max_request_bytes(max_batch_bytes: usize) -> usize {
    max_batch_bytes.saturating_add(MAX_BATCH_LENGTH_PREFIX_BYTES)
}

/// Smallest encoded payload: a one-byte tag (private rollover).
const MIN_PAYLOAD_TAG_BYTES: usize = 1;

const fn min_signed_transaction_bytes() -> usize {
    TransactionPublicKey::SIZE
        + MIN_PAYLOAD_TAG_BYTES
        + MIN_U64_VARINT_BYTES
        + TransactionSignature::MIN_SIZE
}

fn max_transaction_count(body_len: usize) -> Option<usize> {
    let payload_len = body_len.saturating_sub(MIN_BATCH_LENGTH_PREFIX_BYTES);
    let max_transactions = payload_len / min_signed_transaction_bytes();
    (max_transactions > 0).then_some(max_transactions)
}

/// Serializes a JSON response body, mapping the (practically impossible)
/// serialization failure to a 500 instead of panicking.
fn ok_json<T: serde::Serialize>(value: &T) -> (StatusCode, String) {
    serde_json::to_string(value)
        .map_or((StatusCode::INTERNAL_SERVER_ERROR, String::new()), |body| {
            (StatusCode::OK, body)
        })
}

/// Accepts a batch of signed transactions as a commonware-codec length-prefixed
/// vector.
///
/// Signatures are verified in parallel using the configured [`Strategy`].
/// Blocks until the batch is fully finalized, partially finalized, or dropped.
///
/// Returns:
/// - `200 OK` with JSON status on finalization or drop.
/// - `400 Bad Request` if the body is empty, any transaction fails to decode,
///   or any signature is invalid.
/// - `413 Payload Too Large` if the batch exceeds `max_propose_bytes`.
/// - `503 Service Unavailable` if the pool is full.
async fn submit_batch<C, P, H, St>(
    State(state): State<SharedState<C, P, H, St>>,
    body: Bytes,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    let batch = match verify_body::<P, H, _>(&state, body).await {
        Ok(batch) => batch,
        Err(status) => return (status, String::new()),
    };

    // Phase 3: Submit to actor and await result.
    let Some(result_rx) = state.mailbox.try_submit(
        batch.batch_id,
        batch.digests,
        batch.transactions,
        batch.total_bytes,
    ) else {
        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
    };

    result_rx.await.map_or_else(
        |_| (StatusCode::INTERNAL_SERVER_ERROR, String::new()),
        |status| ok_json(&status),
    )
}

/// Accepts a verified transaction batch without waiting for finalization.
///
/// This endpoint is intended for relayers. It uses the same body format and
/// validation path as [`submit_batch`], but returns an empty `202 Accepted`
/// as soon as the actor has accepted the batch for proposal; callers derive
/// transaction digests locally from the batch they signed.
async fn ingest_batch<C, P, H, St>(
    State(state): State<SharedState<C, P, H, St>>,
    body: Bytes,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    let batch = match verify_body::<P, H, _>(&state, body).await {
        Ok(batch) => batch,
        Err(status) => return (status, String::new()),
    };

    let Some(result_rx) = state.mailbox.try_ingest(
        batch.batch_id,
        batch.digests,
        batch.transactions,
        batch.total_bytes,
    ) else {
        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
    };

    match result_rx.await {
        Ok(IngestStatus::Accepted) => (StatusCode::ACCEPTED, String::new()),
        Ok(IngestStatus::Dropped) => (StatusCode::SERVICE_UNAVAILABLE, String::new()),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, String::new()),
    }
}

struct VerifiedBatch<H>
where
    H: Hasher,
{
    batch_id: String,
    transactions: Vec<VerifiedTransaction<H>>,
    digests: Vec<H::Digest>,
    total_bytes: usize,
}

async fn verify_body<P, H, St>(
    state: &AppState<impl Digest, P, H, St>,
    body: Bytes,
) -> Result<VerifiedBatch<H>, StatusCode>
where
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    if body.len() > max_request_bytes(state.max_batch_bytes) {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let Some(max_transactions) = max_transaction_count(body.len()) else {
        return Err(StatusCode::BAD_REQUEST);
    };

    // Admission control: the owned permit moves into the pool job below, so
    // it is held for exactly the job's lifetime -- a client disconnect drops
    // the handler future but cannot release the permit while the
    // (uncancellable) job still occupies the pool.
    let Ok(permit) = state.ingress_permits.clone().acquire_owned().await else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    // Hashing, decoding, and verifying a relayer batch is a ~470 core-ms
    // burst at production sizes, so it runs on the strategy pool; a pool
    // member (unlike a blocking thread) work-steals during the nested
    // parallel signature verification. Pool threads have an empty tracing
    // context, so capture the caller's span explicitly.
    let parent = tracing::Span::current();
    let max_batch_bytes = state.max_batch_bytes;
    let namespace = state.namespace;
    let public_key_cache = state.public_key_cache.clone();
    let verified = state.strategy.spawn(move |strategy| {
        let _permit = permit;
        let batch_id = H::hash(&body).to_string();

        let decode = info_span!(
            parent: &parent,
            "mempool.ingress.decode",
            bytes = body.len().traced(),
            txs = tracing::field::Empty,
        )
        .entered();
        let cfg = (RangeCfg::new(1..=max_transactions), ());
        let signed = Vec::<SignedTransaction<H>>::decode_cfg(body.as_ref(), &cfg)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        decode.record("txs", signed.len().traced());
        drop(decode);

        let total_bytes: usize = signed.iter().map(EncodeSize::encode_size).sum();
        if total_bytes > max_batch_bytes {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }

        let verify = info_span!(
            parent: &parent,
            "mempool.ingress.verify",
            txs = signed.len().traced(),
            bytes = total_bytes.traced(),
        )
        .entered();
        let signed_lazy = signed
            .into_iter()
            .map(LazySignedTransaction::new)
            .collect::<Vec<_>>();
        let transactions = verify_transaction_chunks::<H, _, _>(
            namespace,
            &mut sys_rng(),
            &public_key_cache,
            signed_lazy,
            &strategy,
        )
        .ok_or(StatusCode::BAD_REQUEST)?;
        drop(verify);

        let digests = transactions
            .iter()
            .map(|transaction| *transaction.message_digest())
            .collect();

        Ok(VerifiedBatch {
            batch_id,
            transactions,
            digests,
            total_bytes,
        })
    });
    verified.await
}

/// Returns the latest known status for a submitted batch.
async fn fetch_status<C, P, H, St>(
    State(state): State<SharedState<C, P, H, St>>,
    Path(batch_id): Path<String>,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    let Some(status) = state.mailbox.query_status(batch_id).await else {
        return (StatusCode::NOT_FOUND, String::new());
    };

    // Hex-encoding digest lists (partially finalized batches only) is O(txs)
    // formatting, so it runs on the strategy's pool; every other status is
    // constant-size.
    if status.has_digest_lists() {
        return state
            .strategy
            .spawn(move |_| ok_json(&status.to_wire()))
            .await;
    }
    ok_json(&status.to_wire())
}

/// Returns the committed account for the hex-encoded public key.
///
/// Responds with:
/// - `200 OK` and account JSON if the account exists.
/// - `404 Not Found` if the account has not been written.
/// - `400 Bad Request` if the path is not a valid public key hex string.
/// - `503 Service Unavailable` if the state database has not been attached yet.
async fn fetch_account<C, P, H, St>(
    State(state): State<SharedState<C, P, H, St>>,
    Path(public_key): Path<String>,
) -> (StatusCode, String)
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    St: Strategy,
{
    let Some(bytes) = from_hex(&public_key) else {
        return (StatusCode::BAD_REQUEST, String::new());
    };
    if bytes.len() != TransactionPublicKey::SIZE {
        return (StatusCode::BAD_REQUEST, String::new());
    }
    let public_key = match TransactionPublicKey::decode(bytes.as_slice()) {
        Ok(public_key) => public_key,
        Err(_) => return (StatusCode::BAD_REQUEST, String::new()),
    };

    let Some(reader) = state.account_reader.get() else {
        return (StatusCode::SERVICE_UNAVAILABLE, String::new());
    };

    reader.get(public_key).await.map_or_else(
        || (StatusCode::NOT_FOUND, String::new()),
        |account| ok_json(&AccountResponse::from(account)),
    )
}

#[derive(serde::Serialize)]
struct AccountResponse {
    balance: u64,
    nonce: NonceResponse,
    /// Hex-encoded spendable private commitment (`PrivateAccount::current`).
    private_current: String,
    /// Hex-encoded incoming private commitment awaiting rollover
    /// (`PrivateAccount::pending`).
    private_pending: String,
}

#[derive(serde::Serialize)]
struct NonceResponse {
    base: u64,
    bitmap: u64,
}

impl From<Account> for AccountResponse {
    fn from(account: Account) -> Self {
        Self {
            balance: account.balance,
            nonce: NonceResponse::from(account.nonce),
            private_current: hex(&account.private.current.encode()),
            private_pending: hex(&account.private.pending.encode()),
        }
    }
}

impl From<Nonce> for NonceResponse {
    fn from(nonce: Nonce) -> Self {
        Self {
            base: nonce.base,
            bitmap: nonce.bitmap,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{AccountReader, TxStatus, mailbox::Message},
        Account, AccountReaderCell, AppState, MAX_CONCURRENT_INGRESS, Nonce, PublicKeyCache,
        Semaphore, SignedTransaction, TransactionPublicKey, hex, router,
    };
    use axum::{
        body::{Body, to_bytes},
        http::{Method, Request, StatusCode, header},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{Signer, ed25519, sha256};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Metrics, Runner as _};
    use commonware_utils::NZUsize;
    use constantinople_primitives::{
        ChainPrivatePaymentBackend, Payload, PrivateAccount, PrivatePaymentBackend, Transaction,
    };
    use core::num::NonZeroU64;
    use futures::future::{BoxFuture, FutureExt as _};
    use rand::{SeedableRng as _, rngs::StdRng};
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tower::ServiceExt;

    const NAMESPACE: &[u8] = b"mempool-http-test";

    /// Builds the router plus the actor-side receiver and account-reader
    /// cell, for tests that stand in for the mempool actor or state database.
    fn test_router_parts(
        context: impl Metrics,
        max_batch_bytes: usize,
    ) -> (
        axum::Router,
        mpsc::Receiver<Message<sha256::Digest, ed25519::PublicKey, sha256::Sha256>>,
        AccountReaderCell,
    ) {
        let (sender, receiver) = mpsc::channel(1);
        let account_reader: AccountReaderCell = Arc::new(std::sync::OnceLock::new());
        let state = Arc::new(AppState {
            mailbox: super::super::mailbox::Mailbox::new(sender),
            namespace: NAMESPACE,
            max_batch_bytes,
            strategy: Sequential,
            public_key_cache: PublicKeyCache::new(context, NZUsize!(16)),
            account_reader: account_reader.clone(),
            ingress_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_INGRESS)),
        });

        (
            router::<sha256::Digest, ed25519::PublicKey, sha256::Sha256, Sequential>(state),
            receiver,
            account_reader,
        )
    }

    fn test_router(context: impl Metrics, max_batch_bytes: usize) -> axum::Router {
        test_router_parts(context, max_batch_bytes).0
    }

    fn sign_tx(key: &ed25519::PrivateKey, nonce: u64) -> SignedTransaction<sha256::Sha256> {
        let public_key = TransactionPublicKey::ed25519(key.public_key());
        Transaction::new(
            public_key.clone(),
            public_key,
            NonZeroU64::new(1).expect("test value should be non-zero"),
            nonce,
        )
        .seal_and_sign(key, NAMESPACE, &mut sha256::Sha256::default())
    }

    fn sign_payload(
        key: &ed25519::PrivateKey,
        payload: Payload,
        nonce: u64,
    ) -> SignedTransaction<sha256::Sha256> {
        Transaction::from_payload(
            TransactionPublicKey::ed25519(key.public_key()),
            payload,
            nonce,
        )
        .seal_and_sign(key, NAMESPACE, &mut sha256::Sha256::default())
    }

    /// Funds a commitment with the configured chain backend (mock under
    /// default features, real zkpari BN254 under `--all-features`). The
    /// generic indirection reaches the `Backend` supertrait methods without
    /// naming `commonware-privacy`, which this crate does not depend on.
    fn fund<B: PrivatePaymentBackend>(
        value: u64,
        rng: &mut StdRng,
    ) -> (B::Commitment, B::FundProof) {
        let (commitment, _opening, proof) = B::fund(B::params(), value, rng);
        (commitment, proof)
    }

    fn private_fund_payload(value: u64, rng: &mut StdRng) -> Payload {
        let (commitment, proof) = fund::<ChainPrivatePaymentBackend>(value, rng);
        Payload::PrivateFund {
            value: NonZeroU64::new(value).expect("test value should be non-zero"),
            commitment,
            proof,
        }
    }

    /// Serves one fixed account for `/account` lookups.
    struct StaticAccountReader(Account);

    impl AccountReader for StaticAccountReader {
        fn get<'a>(&'a self, _public_key: TransactionPublicKey) -> BoxFuture<'a, Option<Account>> {
            let account = self.0.clone();
            async move { Some(account) }.boxed()
        }
    }

    #[test]
    fn router_accepts_requests_above_axum_default_limit() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let app = test_router(context, 4 * 1024 * 1024);
            let request = Request::builder()
                .method("POST")
                .uri("/transactions")
                .body(Body::from(vec![0u8; 2 * 1024 * 1024 + 1]))
                .expect("request should build");

            let response = app.oneshot(request).await.expect("router should respond");

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        });
    }

    #[test]
    fn router_rejects_malformed_length_prefix_without_panicking() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let app = test_router(context, 4 * 1024 * 1024);
            let request = Request::builder()
                .method("POST")
                .uri("/transactions")
                .body(Body::from(u32::MAX.encode()))
                .expect("request should build");

            // A panic here (rather than a clean rejection) would fail the test.
            let response = app.oneshot(request).await.expect("router should respond");

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        });
    }

    #[test]
    fn router_allows_explorer_account_preflight() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let app = test_router(context, 4 * 1024 * 1024);
            let request = Request::builder()
                .method(Method::OPTIONS)
                .uri("/account/00")
                .header(header::ORIGIN, "http://127.0.0.1:5173")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .body(Body::empty())
                .expect("request should build");

            let response = app.oneshot(request).await.expect("router should respond");

            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
                Some(&header::HeaderValue::from_static("*")),
            );
        });
    }

    /// A batch carrying a valid `PrivateFund` payload decodes, verifies, and
    /// resolves through the same `/transactions` submit path as a public
    /// transfer.
    #[test]
    fn submitted_private_fund_batch_is_accepted_with_public_transfer() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (app, mut receiver, _account_reader) = test_router_parts(context, 4 * 1024 * 1024);
            let mut rng = StdRng::from_seed([29; 32]);
            let key = ed25519::PrivateKey::from_seed(42);
            let fund_payload = private_fund_payload(4, &mut rng);
            let batch = vec![
                sign_tx(&key, 0),
                sign_payload(&key, fund_payload.clone(), 1),
            ];
            let request = Request::builder()
                .method("POST")
                .uri("/transactions")
                .body(Body::from(batch.encode()))
                .expect("request should build");

            // Stand in for the mempool actor: receive the verified batch and
            // resolve it as finalized.
            let response_task = tokio::spawn(app.oneshot(request));
            let message = receiver
                .recv()
                .await
                .expect("router should forward the batch");
            let Message::Submit {
                digests,
                transactions,
                result,
                ..
            } = message
            else {
                panic!("submission should reach the actor as a submit message");
            };
            assert_eq!(digests.len(), 2);
            assert!(matches!(
                transactions[0].value().payload,
                Payload::PublicTransfer { .. }
            ));
            assert_eq!(transactions[1].value().payload, fund_payload);
            result
                .expect("http submissions carry a result sender")
                .send(TxStatus::Finalized { height: 7 })
                .expect("handler should await the result");

            let response = response_task
                .await
                .expect("request task should not panic")
                .expect("router should respond");
            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body should buffer");
            assert_eq!(
                serde_json::from_slice::<TxStatus>(&body).expect("status should deserialize"),
                TxStatus::Finalized { height: 7 },
            );
        });
    }

    /// `/account` serializes non-zero private commitment state as the hex
    /// `private_current`/`private_pending` fields (renamed from
    /// `private`/`pending`).
    #[test]
    fn account_response_serializes_private_state_as_hex() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (app, _receiver, account_reader) = test_router_parts(context, 4 * 1024 * 1024);
            let mut rng = StdRng::from_seed([31; 32]);
            let (current, _proof) = fund::<ChainPrivatePaymentBackend>(7, &mut rng);
            let (pending, _proof) = fund::<ChainPrivatePaymentBackend>(3, &mut rng);
            let current_hex = hex(&current.encode());
            let pending_hex = hex(&pending.encode());
            let account = Account {
                balance: 42,
                nonce: Nonce::new(2, 1),
                private: PrivateAccount { current, pending },
            };
            assert!(
                account_reader
                    .set(Arc::new(StaticAccountReader(account)))
                    .is_ok()
            );

            let public_key =
                TransactionPublicKey::ed25519(ed25519::PrivateKey::from_seed(43).public_key());
            let request = Request::builder()
                .method(Method::GET)
                .uri(format!("/account/{}", hex(&public_key.encode())))
                .body(Body::empty())
                .expect("request should build");

            let response = app.oneshot(request).await.expect("router should respond");

            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body should buffer");
            let json: serde_json::Value =
                serde_json::from_slice(&body).expect("account should deserialize");
            let zero = hex(&PrivateAccount::<ChainPrivatePaymentBackend>::zero()
                .current
                .encode());
            assert_ne!(current_hex, zero, "state under test must be non-zero");
            assert_eq!(json["balance"], 42);
            assert_eq!(json["nonce"]["base"], 2);
            assert_eq!(json["nonce"]["bitmap"], 1);
            assert_eq!(json["private_current"], current_hex);
            assert_eq!(json["private_pending"], pending_hex);
            let object = json
                .as_object()
                .expect("account response should be an object");
            assert!(
                !object.contains_key("private"),
                "field was renamed to private_current"
            );
            assert!(
                !object.contains_key("pending"),
                "field was renamed to private_pending"
            );
        });
    }
}
