//! Reporters and uploader actor for indexer publishing.
//!
//! The publisher is split in two halves:
//!
//! - One or more cloneable [`Reporter`] implementations that encode incoming
//!   consensus events into atomic [`UploadBatch`]es and push them to a bounded
//!   MPSC channel.
//! - A single uploader task (see [`spawn_uploader`]) that owns the
//!   [`StoreClient`] and drains the channel, retrying until the store accepts
//!   the batch. On success it fulfills the marshal acknowledgement bundled
//!   with the batch (if any), giving the engine at-least-once delivery and
//!   marshal-driven back-pressure.
//!
//! [`Reporter`]: commonware_consensus::Reporter
//! [`StoreClient`]: exoware_sdk::StoreClient

use bytes::Bytes;
use commonware_utils::{Acknowledgement, acknowledgement::Exact};
use exoware_sdk::{RetryConfig, StoreClient, keys::Key};
use std::time::Duration;
use tokio::{sync::mpsc, task::JoinHandle, time::sleep};
use tracing::{debug, error, warn};

pub mod block;

pub use block::BlockReporter;

/// One atomic write to the exoware store.
///
/// The uploader uses `ingest().put` so every key in `rows` is committed in a
/// single store sequence number. If `ack` is `Some`, the uploader fulfills the
/// acknowledgement only after the put succeeds.
pub struct UploadBatch {
    /// Pre-encoded `(key, value)` pairs to ingest atomically.
    pub rows: Vec<(Key, Bytes)>,
    /// Marshal acknowledgement to release once the store has accepted the batch.
    pub ack: Option<Exact>,
}

/// Handle to the uploader task and the channel that feeds it.
///
/// Cloneable [`BlockReporter`]s share `tx` and forward batches to the single
/// uploader task that owns the [`StoreClient`].
pub struct UploaderHandle {
    pub tx: mpsc::Sender<UploadBatch>,
    pub join: JoinHandle<()>,
}

/// Spawn the uploader task on the current tokio runtime.
pub fn spawn_uploader(client: StoreClient, buffer: usize) -> UploaderHandle {
    let (tx, rx) = mpsc::channel::<UploadBatch>(buffer);
    let join = tokio::spawn(run_uploader(client, rx));
    UploaderHandle { tx, join }
}

async fn run_uploader(client: StoreClient, mut rx: mpsc::Receiver<UploadBatch>) {
    while let Some(batch) = rx.recv().await {
        upload_with_retry(&client, &batch).await;
        if let Some(ack) = batch.ack {
            ack.acknowledge();
        }
    }
    debug!("indexer uploader task exiting: channel closed");
}

/// Retry the put indefinitely with standard backoff until the store accepts it.
///
/// Marshal back-pressures the engine on the still-held ack, so retrying here
/// is the right way to express at-least-once delivery: we never lose a batch
/// and the engine slows down if the store is unhealthy.
async fn upload_with_retry(client: &StoreClient, batch: &UploadBatch) {
    let kvs: Vec<(&Key, &[u8])> = batch.rows.iter().map(|(k, v)| (k, v.as_ref())).collect();
    let mut attempt: u32 = 0;
    loop {
        match client.ingest().put(&kvs).await {
            Ok(seq) => {
                debug!(seq, rows = kvs.len(), "indexer uploaded batch");
                return;
            }
            Err(error) => {
                attempt = attempt.saturating_add(1);
                warn!(
                    ?error,
                    attempt,
                    rows = kvs.len(),
                    "indexer upload failed, retrying"
                );
                sleep(retry_backoff(attempt)).await;
            }
        }
    }
}

/// Exponential backoff capped at 2s, mirroring [`RetryConfig::standard`] but
/// applied across our own infinite retry loop above the SDK's per-call retry.
fn retry_backoff(attempt: u32) -> Duration {
    const INITIAL: Duration = Duration::from_millis(100);
    const MAX: Duration = Duration::from_secs(2);
    let factor = 1u32 << attempt.min(5);
    INITIAL.saturating_mul(factor).min(MAX)
}

/// Convenience: build a [`StoreClient`] with the SDK's standard retry policy.
pub fn standard_store_client(url: &str) -> StoreClient {
    StoreClient::with_retry_config(url, RetryConfig::standard())
}

/// Hand a batch off to the uploader in the background.
///
/// `Reporter::report` must never block consensus, so we always dispatch the
/// channel send onto a fresh tokio task and return immediately. Back-pressure
/// comes solely from the marshal acknowledgement bundled with the batch:
/// while the uploader queue grows, marshal still considers the block
/// undelivered and refuses to admit new ones.
///
/// If the uploader channel is closed (the task has exited) the batch is
/// dropped and any associated acknowledgement is canceled, which matches the
/// documented "drop = shutdown" semantics on
/// [`commonware_consensus::marshal::Update`].
pub(crate) fn dispatch_batch(tx: &mpsc::Sender<UploadBatch>, batch: UploadBatch) {
    let tx = tx.clone();
    tokio::spawn(async move {
        if let Err(error) = tx.send(batch).await {
            error!("indexer channel closed; dropping batch and ack: {error}");
        }
    });
}
