//! Mailbox for the mempool webserver actor.

use crate::TransactionSource;
use commonware_consensus::{Reporter, marshal::Update, simplex::types::Context};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_utils::channel::fallible::AsyncFallibleExt;
use constantinople_primitives::{Header, SealedBlock, VerifiedTransaction};
use tokio::sync::{mpsc, oneshot};

pub(super) enum Message<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    /// A verified transaction submitted by an HTTP handler.
    Submit {
        transaction: VerifiedTransaction<P, H>,
        size: usize,
    },
    /// Consensus requests transactions for the next proposal.
    Propose {
        response: oneshot::Sender<Vec<VerifiedTransaction<P, H>>>,
    },
    /// Consensus reports a finalized or tip block.
    Report(Update<SealedBlock<C, P, H>>),
}

/// Handle to the mempool actor, used by HTTP handlers and the consensus layer.
pub struct Mailbox<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    sender: mpsc::Sender<Message<C, P, H>>,
}

impl<C, P, H> Clone for Mailbox<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<C, P, H> Mailbox<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    pub(super) const fn new(sender: mpsc::Sender<Message<C, P, H>>) -> Self {
        Self { sender }
    }

    /// Non-blocking submission for HTTP handlers.
    ///
    /// Returns `true` if the transaction was enqueued into the actor channel,
    /// `false` if the channel is full (backpressure).
    pub fn try_submit(&self, transaction: VerifiedTransaction<P, H>, size: usize) -> bool {
        self.sender
            .try_send(Message::Submit { transaction, size })
            .is_ok()
    }
}

impl<C, P, H> TransactionSource<C, P, H> for Mailbox<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    async fn propose(
        &mut self,
        _parent: &Header<C, H::Digest, P>,
        _context: &Context<C, P>,
    ) -> Vec<VerifiedTransaction<P, H>> {
        self.sender
            .request(|response| Message::Propose { response })
            .await
            .expect("mempool actor mailbox closed")
    }
}

impl<C, P, H> Reporter for Mailbox<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    type Activity = Update<SealedBlock<C, P, H>>;

    async fn report(&mut self, activity: Self::Activity) {
        self.sender.send_lossy(Message::Report(activity)).await;
    }
}
