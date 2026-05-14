//! Certificate reporter that uploads simplex notarization and finalization
//! certificates to the raw KV store.
//!
//! Wired into the engine via the new `simplex_observer` slot on
//! [`constantinople_engine::Config`]. On every
//! [`simplex::types::Activity::Notarization`] or
//! [`simplex::types::Activity::Finalization`] we encode a single-row batch
//! and dispatch it to the raw KV uploader. The FINALIZED and NOTARIZED key
//! families share the raw store with BLOCK, BLOCK_BY_H, TX, and TX_BY_H. All
//! other activity variants (votes, Byzantine evidence, etc.) are dropped.
//!
//! Like [`super::block::BlockReporter`], certificate uploads are non-blocking
//! and run on a fresh tokio task.

use crate::{
    keys,
    publisher::{UploadBatch, dispatch_batch},
};
use commonware_codec::Encode;
use commonware_consensus::{
    Reporter,
    simplex::{self, types::Activity},
};
use commonware_cryptography::{Digest, certificate::Scheme};
use std::marker::PhantomData;
use tokio::sync::mpsc;

/// Cloneable [`Reporter`] over `Activity<S, D>` that filters notarizations and
/// finalizations and uploads each as a single atomic row to the raw KV store.
pub struct CertificateReporter<S, D> {
    raw: mpsc::Sender<UploadBatch>,
    _marker: PhantomData<fn() -> (S, D)>,
}

impl<S, D> CertificateReporter<S, D> {
    /// Build a reporter that forwards certificate batches to the raw uploader.
    pub const fn new(raw: mpsc::Sender<UploadBatch>) -> Self {
        Self {
            raw,
            _marker: PhantomData,
        }
    }
}

impl<S, D> Clone for CertificateReporter<S, D> {
    fn clone(&self) -> Self {
        Self {
            raw: self.raw.clone(),
            _marker: PhantomData,
        }
    }
}

impl<S, D> Reporter for CertificateReporter<S, D>
where
    S: Scheme,
    D: Digest,
    simplex::types::Notarization<S, D>: Encode,
    simplex::types::Finalization<S, D>: Encode,
{
    type Activity = Activity<S, D>;

    async fn report(&mut self, activity: Self::Activity) {
        match activity {
            Activity::Notarization(notarization) => {
                let view = notarization.round().view().get();
                let key = keys::notarized(view).expect("u64 view fits NOTARIZED family payload");
                let value = notarization.encode();
                dispatch_batch(
                    &self.raw,
                    UploadBatch {
                        rows: vec![(key, value)],
                        ack: None,
                    },
                );
            }
            Activity::Finalization(finalization) => {
                let view = finalization.round().view().get();
                let key = keys::finalized(view).expect("u64 view fits FINALIZED family payload");
                let value = finalization.encode();
                dispatch_batch(
                    &self.raw,
                    UploadBatch {
                        rows: vec![(key, value)],
                        ack: None,
                    },
                );
            }
            // Votes, certifications, nullifications, and Byzantine evidence
            // are not indexed.
            _ => {}
        }
    }
}
