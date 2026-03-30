#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use commonware_consensus::{Reporter, simplex::types::Context};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use constantinople_primitives::{
    Block, Header, Receipt, Sealed, SignedTransaction, VerifiedTransaction,
};
use core::future::Future;

pub type SealedBlock<C, P, H> = Sealed<Block<C, P, H>, H>;
pub type PendingTransaction<P, H> = VerifiedTransaction<P, H>;

/// A finalized block and its execution receipts.
#[derive(Debug, Clone)]
pub struct Finalized<C: Digest, P: PublicKey, H: Hasher> {
    pub block: SealedBlock<C, P, H>,
    pub receipts: Vec<Receipt<H::Digest>>,
}

/// Supplies transactions for block proposals and reacts to finalized blocks.
pub trait TransactionSource<C, P, H>:
    Reporter<Activity = Finalized<C, P, H>> + Send + 'static
where
    C: Digest,
    H: Hasher,
    P: PublicKey,
{
    /// Returns the transactions to include in the next proposal.
    fn propose(
        &mut self,
        parent: &Header<C, H::Digest, P>,
        context: &Context<C, P>,
    ) -> impl Future<Output = Vec<PendingTransaction<P, H>>> + Send;
}

#[cfg(feature = "mocks")]
pub mod mocks;

pub mod server;
