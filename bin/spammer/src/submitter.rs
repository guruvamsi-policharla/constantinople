//! Async submission engine with retry logic.
//!
//! Each validator gets an independent [`ValidatorSubmitter`] that submits one
//! batch at a time and blocks until every transaction in the batch is
//! finalized. This guarantees nonce ordering.

use crate::signer::Tx;
use commonware_codec::Encode;
use constantinople_mempool::webserver::{TxStatus, client::Client};
use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tracing::{debug, info, warn};

/// Shared counters for progress reporting.
pub struct Stats {
    pub finalized: AtomicU64,
    pub filtered: AtomicU64,
    pub dropped: AtomicU64,
    pub retried: AtomicU64,
    pub errors: AtomicU64,
}

impl Stats {
    pub const fn new() -> Self {
        Self {
            finalized: AtomicU64::new(0),
            filtered: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            retried: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }
}

const MAX_BACKOFF: Duration = Duration::from_secs(30);
const INITIAL_BACKOFF: Duration = Duration::from_millis(100);

/// Submits batches to a single validator, one at a time.
pub struct ValidatorSubmitter {
    client: Arc<Client>,
    stats: Arc<Stats>,
    validator_index: usize,
}

/// Submits batches through a relayer and waits for finalization before
/// advancing nonces.
pub struct RelayerSubmitter {
    url: String,
    http: reqwest::Client,
    stats: Arc<Stats>,
}

#[derive(Debug, serde::Deserialize)]
struct RelayerSubmitResponse {
    batch_id: String,
    #[allow(dead_code)]
    digests: Vec<String>,
    #[allow(dead_code)]
    acknowledged_leaders: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum RelayerBatchStatus {
    Accepted {
        #[allow(dead_code)]
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

impl RelayerSubmitter {
    pub fn new(url: String, stats: Arc<Stats>) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
            stats,
        }
    }

    /// Submits the batch through the relayer and waits until every transaction
    /// is finalized.
    pub async fn submit_until_finalized(&self, batch: Vec<Tx>) {
        let mut pending = batch;
        let mut backoff = INITIAL_BACKOFF;

        while !pending.is_empty() {
            let body = pending.encode();
            match self.submit_encoded(body.clone()).await {
                Ok(response) => match self.poll_status(&response.batch_id).await {
                    Ok(RelayerBatchStatus::Accepted { .. }) => {}
                    Ok(RelayerBatchStatus::Finalized { height, included }) => {
                        self.stats
                            .finalized
                            .fetch_add(included.len() as u64, Ordering::Relaxed);
                        debug!(height, count = included.len(), "relayed batch finalized");
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
                            "relayed batch partially finalized, resubmitting filtered"
                        );
                        pending = extract_filtered(&pending, &filtered);
                        backoff = INITIAL_BACKOFF;
                    }
                    Ok(RelayerBatchStatus::Dropped { filtered }) => {
                        self.stats
                            .dropped
                            .fetch_add(filtered.len() as u64, Ordering::Relaxed);
                        let filtered = extract_filtered(&pending, &filtered);
                        if !filtered.is_empty() {
                            pending = filtered;
                        }
                        debug!(
                            pending = pending.len(),
                            "relayed batch dropped, resubmitting"
                        );
                    }
                    Err(error) => {
                        self.stats.errors.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            error = %error,
                            backoff_ms = backoff.as_millis(),
                            "relayer status error, retrying"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                    }
                },
                Err(error) => {
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        error = %error,
                        backoff_ms = backoff.as_millis(),
                        "relayer submit error, retrying"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    }

    async fn submit_encoded(
        &self,
        body: bytes::Bytes,
    ) -> Result<RelayerSubmitResponse, constantinople_mempool::webserver::client::SubmitError> {
        use constantinople_mempool::webserver::client::SubmitError;

        let response = self
            .http
            .post(format!("{}/transactions", self.url))
            .header("content-type", "application/octet-stream")
            .body(body)
            .send()
            .await?;

        match response.status().as_u16() {
            202 => {
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

    async fn poll_status(
        &self,
        batch_id: &str,
    ) -> Result<RelayerBatchStatus, constantinople_mempool::webserver::client::SubmitError> {
        use constantinople_mempool::webserver::client::SubmitError;

        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let response = self
                .http
                .get(format!("{}/transactions/{batch_id}", self.url))
                .send()
                .await?;

            match response.status().as_u16() {
                200 => {
                    let bytes = response.bytes().await?;
                    let status: RelayerBatchStatus =
                        serde_json::from_slice(&bytes).map_err(SubmitError::InvalidResponse)?;
                    if matches!(status, RelayerBatchStatus::Accepted { .. }) {
                        continue;
                    }
                    return Ok(status);
                }
                404 => continue,
                400 => return Err(SubmitError::BadRequest),
                413 => return Err(SubmitError::PayloadTooLarge),
                500 => return Err(SubmitError::InternalServerError),
                503 => continue,
                other => return Err(SubmitError::Unexpected(other)),
            }
        }
    }
}

impl ValidatorSubmitter {
    pub fn new(client: Client, stats: Arc<Stats>, validator_index: usize) -> Self {
        Self {
            client: Arc::new(client),
            stats,
            validator_index,
        }
    }

    /// Submits the batch and blocks until **every** transaction is finalized.
    ///
    /// On partial finalization, only the filtered transactions are resubmitted.
    /// On drop or error, the entire remaining batch is retried with backoff.
    /// Returns only after all transactions have been finalized.
    pub async fn submit_until_finalized(&self, batch: Vec<Tx>) {
        let mut pending = batch;
        let mut backoff = INITIAL_BACKOFF;

        while !pending.is_empty() {
            match self.client.submit(&pending).await {
                Ok(TxStatus::Finalized { height }) => {
                    let count = pending.len() as u64;
                    self.stats.finalized.fetch_add(count, Ordering::Relaxed);
                    debug!(
                        validator = self.validator_index,
                        height, count, "round finalized"
                    );
                    return;
                }
                Ok(TxStatus::PartiallyFinalized {
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
                        validator = self.validator_index,
                        height,
                        included = included.len(),
                        filtered = filtered.len(),
                        "partially finalized, resubmitting filtered"
                    );
                    pending = extract_filtered(&pending, &filtered);
                    backoff = INITIAL_BACKOFF;
                }
                Ok(TxStatus::Dropped) => {
                    self.stats
                        .dropped
                        .fetch_add(pending.len() as u64, Ordering::Relaxed);
                    debug!(
                        validator = self.validator_index,
                        pending = pending.len(),
                        "batch dropped, resubmitting"
                    );
                    // Resubmit same pending set — nonces are still valid.
                }
                Err(constantinople_mempool::webserver::client::SubmitError::ServiceUnavailable) => {
                    warn!(
                        validator = self.validator_index,
                        backoff_ms = backoff.as_millis(),
                        "pool full, backing off"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
                Err(e) => {
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        validator = self.validator_index,
                        error = %e,
                        backoff_ms = backoff.as_millis(),
                        "submit error, retrying"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    }
}

/// Keeps only the transactions whose digest appears in `filtered_digests`.
fn extract_filtered(batch: &[Tx], filtered_digests: &[String]) -> Vec<Tx> {
    let filter_set: HashSet<&str> = filtered_digests.iter().map(String::as_str).collect();
    batch
        .iter()
        .filter(|tx| filter_set.contains(tx.message_digest().to_string().as_str()))
        .cloned()
        .collect()
}
