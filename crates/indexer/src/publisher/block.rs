//! Block reporter that uploads finalized blocks atomically.
//!
//! Wired into the engine via the existing `marshal` reporter slot. On every
//! `Update::Block(block, ack)` we:
//!
//! 1. Encode one atomic batch containing the block, its `BLOCK_BY_H` index,
//!    every contained transaction, and a META cursor update.
//! 2. Forward the batch (with the marshal acknowledgement) to the uploader.
//! 3. Return immediately so consensus is not blocked on the network store —
//!    marshal itself back-pressures the engine through the still-held ack.

use crate::{
    keys,
    publisher::{UploadBatch, dispatch_batch},
};
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_consensus::{Reporter, marshal::Update};
use commonware_cryptography::{Hasher, PublicKey};
use constantinople_engine::types::EngineBlock;
use std::marker::PhantomData;
use tokio::sync::mpsc;
use tracing::warn;

/// Cloneable [`Reporter`] over `Update<EngineBlock<H, P>>`.
///
/// The reporter is itself stateless beyond the channel handle; cloning it
/// lets the engine fan the same upload pipeline out to multiple consumers.
pub struct BlockReporter<H, P> {
    tx: mpsc::Sender<UploadBatch>,
    _marker: PhantomData<fn() -> (H, P)>,
}

impl<H, P> BlockReporter<H, P> {
    /// Build a reporter that forwards batches to the given uploader channel.
    pub const fn new(tx: mpsc::Sender<UploadBatch>) -> Self {
        Self {
            tx,
            _marker: PhantomData,
        }
    }
}

impl<H, P> Clone for BlockReporter<H, P> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            _marker: PhantomData,
        }
    }
}

impl<H, P> Reporter for BlockReporter<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    type Activity = Update<EngineBlock<H, P>>;

    async fn report(&mut self, activity: Self::Activity) {
        match activity {
            // Tip-only updates carry no block payload; nothing to upload.
            Update::Tip(_, _, _) => {}
            Update::Block(block, ack) => {
                // Encoding is cheap and synchronous. The actual store write
                // is dispatched onto a background task so this method never
                // blocks consensus — see `dispatch_batch` for back-pressure
                // semantics.
                let rows = encode_block_rows(&block);
                dispatch_batch(
                    &self.tx,
                    UploadBatch {
                        rows,
                        ack: Some(ack),
                    },
                );
            }
        }
    }
}

/// Build every key-value row that the block ingest batch must contain.
fn encode_block_rows<H, P>(block: &EngineBlock<H, P>) -> Vec<(exoware_sdk::keys::Key, Bytes)>
where
    H: Hasher,
    P: PublicKey,
{
    let block_digest = block.seal();
    let height = block.header.height;
    let body_len = block.body.len();

    let mut rows = Vec::with_capacity(3 + 2 * body_len);

    // BLOCK family: digest -> encoded SealedBlock (which serializes the inner Block).
    rows.push((
        keys::block(block_digest.as_ref()).expect("block digest fits family payload"),
        block.encode(),
    ));

    // BLOCK_BY_H family: height -> block digest (32 bytes).
    rows.push((
        keys::block_by_height(height).expect("u64 height fits family payload"),
        Bytes::copy_from_slice(block_digest.as_ref()),
    ));

    // Per-transaction rows.
    for (idx, lazy) in block.body.iter().enumerate() {
        let Some(tx) = lazy.get() else {
            // Marshal must have already verified each tx upstream, so a decode
            // failure here means we received a malformed block. Skip rather
            // than abort the whole batch — the block still goes up.
            warn!(
                height,
                idx, "indexer: skipping transaction that failed to materialize"
            );
            continue;
        };
        let tx_digest = tx.message_digest();
        let tx_bytes = lazy.encode();
        let idx_u32 = u32::try_from(idx).expect("transaction index fits u32");

        rows.push((
            keys::tx(tx_digest.as_ref()).expect("tx digest fits family payload"),
            tx_bytes,
        ));
        rows.push((
            keys::tx_by_height(height, idx_u32).expect("(height, idx) fits family payload"),
            Bytes::copy_from_slice(tx_digest.as_ref()),
        ));
    }

    // META: latest_finalized_height = u64 BE. Stored last in the batch but
    // committed atomically with everything above.
    rows.push((
        keys::meta_latest_height().expect("meta key fits family payload"),
        Bytes::copy_from_slice(&height.to_be_bytes()),
    ));

    rows
}
