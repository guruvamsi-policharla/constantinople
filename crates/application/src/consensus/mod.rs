//! Consensus-facing application integration.
//!
//! This module bridges consensus, the mempool, the processor, and the backing
//! databases. It is responsible for:
//!
//! - proposing blocks from mempool transactions
//! - filtering or rejecting invalid signatures before execution
//! - loading processor state from speculative database batches
//! - executing transaction slices against that loaded state
//! - finalizing state and transaction-history roots together
//! - verifying and applying certified blocks
//!
//! The execution boundary is intentionally narrow: the [`Application`] owns
//! the execution strategy and QMDB integration, while the processor owns the
//! in-memory state transition logic.

use crate::processor::executor::{self, ProposalOutput};
use commonware_consensus::{
    marshal::ancestry::{AncestorStream, BlockProvider},
    simplex::types::Context,
    types::{Height, Round, View},
};
use commonware_cryptography::{
    BatchVerifier, Digest, Digestible, Hasher, PublicKey, certificate::Scheme,
};
use commonware_glue::stateful::{
    Application as CApplication, Proposed,
    db::{DatabaseSet, Merkleized as _},
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock, Metrics, Spawner, Storage,
    telemetry::metrics::{Counter, MetricsExt},
};
use commonware_storage::{mmr, qmdb::sync::Target, translator::EightCap};
use commonware_utils::non_empty_range;
use constantinople_mempool::TransactionSource;
use constantinople_primitives::{Block, Header, Sealable, SealedBlock};
use futures::StreamExt;
use rand::Rng;
use rand_core::CryptoRngCore;
use std::{
    future::Future, marker::PhantomData, num::NonZeroU64, pin::Pin, sync::Arc, time::Instant,
};
use tracing::{info, warn};

mod db;
mod execution;
mod history;
mod time;
mod utils;
mod verification;
use db::{Databases, apply_changeset, apply_transaction_digests};
pub use db::{TransactionHistoryDb, TransactionHistoryOperation, TransactionHistoryTarget};
use execution::{ExecutionTimings, finalize_child_execution};
use history::header_range_to_target;
pub use utils::{load_lazy_state, load_state};

type FinalizedPruneFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
type FinalizedPruneFn = Arc<dyn Fn(Height) -> FinalizedPruneFuture + Send + Sync>;

/// Core constantinople application.
///
/// This type implements the consensus application trait on top of the
/// processor and the managed state databases.
pub struct Application<H, C, S, P, I, B, SigSt, HashSt>
where
    H: Hasher,
{
    signature_strategy: SigSt,
    hash_strategy: HashSt,
    genesis_leader: P,
    transaction_namespace: &'static [u8],
    genesis_transactions_target: TransactionHistoryTarget<<H as Hasher>::Digest>,
    prune_cadence_blocks: NonZeroU64,
    finalized_pruner: FinalizedPruneFn,
    proposed_transactions: Counter,
    _marker: PhantomData<(H, C, S, I, B)>,
}

impl<H, C, S, P, I, B, SigSt, HashSt> Clone for Application<H, C, S, P, I, B, SigSt, HashSt>
where
    H: Hasher,
    P: Clone,
    SigSt: Clone,
    HashSt: Clone,
{
    fn clone(&self) -> Self {
        Self {
            signature_strategy: self.signature_strategy.clone(),
            hash_strategy: self.hash_strategy.clone(),
            genesis_leader: self.genesis_leader.clone(),
            transaction_namespace: self.transaction_namespace,
            genesis_transactions_target: self.genesis_transactions_target.clone(),
            prune_cadence_blocks: self.prune_cadence_blocks,
            finalized_pruner: self.finalized_pruner.clone(),
            proposed_transactions: self.proposed_transactions.clone(),
            _marker: PhantomData,
        }
    }
}

impl<H, C, S, P, I, B, SigSt, HashSt> Application<H, C, S, P, I, B, SigSt, HashSt>
where
    C: Digest,
    H: Hasher,
    P: PublicKey,
    B: BatchVerifier<PublicKey = P>,
    SigSt: Strategy,
    HashSt: Strategy,
{
    /// Creates an application.
    ///
    /// The application keeps the execution strategy, genesis leader, and
    /// transaction signing namespace for all later block proposal,
    /// verification, and application.
    pub fn new(
        context: impl Metrics,
        signature_strategy: SigSt,
        hash_strategy: HashSt,
        genesis_leader: P,
        transaction_namespace: &'static [u8],
        genesis_transactions_target: TransactionHistoryTarget<<H as Hasher>::Digest>,
        prune_cadence_blocks: NonZeroU64,
        finalized_pruner: FinalizedPruneFn,
    ) -> Self {
        let proposed_transactions = context.counter(
            "proposed_transactions",
            "The number of transactions proposed into blocks",
        );

        Self {
            signature_strategy,
            hash_strategy,
            genesis_leader,
            transaction_namespace,
            genesis_transactions_target,
            prune_cadence_blocks,
            finalized_pruner,
            proposed_transactions,
            _marker: PhantomData,
        }
    }

    const fn should_prune_after_finalize(&self, height: u64) -> bool {
        height != 0 && height % self.prune_cadence_blocks.get() == 0
    }

    /// Proposes a child block from an already fetched parent.
    #[doc(hidden)]
    pub async fn propose_child<E>(
        &mut self,
        (runtime, context): (E, Context<C, P>),
        parent: &SealedBlock<C, P, H>,
        batches: <<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Unmerkleized,
        input: &mut I,
    ) -> Option<Proposed<Self, E>>
    where
        E: Rng + Spawner + Storage + Metrics + Clock + CryptoRngCore,
        S: Scheme<PublicKey = P>,
        I: TransactionSource<C, P, H> + Sync,
        B: BatchVerifier<PublicKey = P> + Send + Sync + 'static,
        SigSt: Strategy + Clone + Send + Sync + 'static,
        HashSt: Strategy + Clone + Send + Sync + 'static,
    {
        let propose_started_at = Instant::now();

        let input_started_at = Instant::now();
        let body = input.propose(&parent.header, &context).await;
        let input_ms = input_started_at.elapsed().as_millis();

        let (state_batches, transaction_batch) = batches;

        let load_state_started_at = Instant::now();
        let state = load_state(&state_batches, &body)
            .await
            .expect("proposal state loading must succeed")
            .expect("proposal transactions must have decodable senders");
        let load_state_ms = load_state_started_at.elapsed().as_millis();

        let execute_started_at = Instant::now();
        let ProposalOutput {
            valid,
            invalid: _,
            changeset,
        } = executor::propose(&state, body);
        let execute_ms = execute_started_at.elapsed().as_millis();

        self.proposed_transactions.inc_by(valid.len() as u64);

        let state_batch = apply_changeset(state_batches, &changeset);
        let transaction_count = valid.len();
        let transaction_batch = apply_transaction_digests(transaction_batch, &valid);
        let prepare_signers_ms = 0;
        let timings =
            ExecutionTimings::before_finalize(prepare_signers_ms, load_state_ms, execute_ms);
        let execution = finalize_child_execution(
            state_batch,
            transaction_batch,
            parent,
            transaction_count,
            timings,
            "database merkleization must succeed",
        )
        .await;

        let header = Header {
            context,
            parent: parent.digest(),
            height: parent.header.height + 1,
            timestamp: time::timestamp_ms(&runtime),
            state_root: execution.state.root(),
            state_range: execution.state_range(),
            transactions_root: execution.transactions.root(),
            transactions_range: execution.transactions_range.clone(),
        };
        let block = Block::new(header, valid).seal(&mut H::default());

        info!(
            epoch = block.header.context.round.epoch().get(),
            view = block.header.context.round.view().get(),
            height = block.header.height,
            txs = block.body.len(),
            timestamp = block.header.timestamp,
            input_ms,
            load_state_ms = execution.timings.load_state_ms,
            execute_ms = execution.timings.execute_ms,
            finalize_ms = execution.timings.finalize_ms,
            total_ms = propose_started_at.elapsed().as_millis(),
            "proposed block"
        );

        Some(Proposed {
            block,
            merkleized: execution.into_merkleized(),
        })
    }

    /// Verifies a child block against an already fetched parent.
    #[doc(hidden)]
    pub async fn verify_child<E>(
        &mut self,
        (runtime, _context): (E, Context<C, P>),
        block: SealedBlock<C, P, H>,
        parent: &SealedBlock<C, P, H>,
        batches: <<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Merkleized>
    where
        E: Rng + Spawner + Storage + Metrics + Clock + CryptoRngCore,
        S: Scheme<PublicKey = P>,
        I: TransactionSource<C, P, H> + Sync,
        B: BatchVerifier<PublicKey = P> + Send + Sync + 'static,
        SigSt: Strategy + Clone + Send + Sync + 'static,
        HashSt: Strategy + Clone + Send + Sync + 'static,
    {
        let verify_started_at = Instant::now();
        let Block { header, body } = block.into_inner();

        if !time::is_valid_child_timestamp(parent.header.timestamp, header.timestamp) {
            warn!(
                height = header.height,
                block_ts = header.timestamp,
                parent_ts = parent.header.timestamp,
                "verify rejected: invalid timestamp"
            );
            return None;
        }

        let deadline = time::block_deadline(header.timestamp);
        let prepare_started_at = Instant::now();
        let prepared = Arc::new(verification::prepare_transactions(body));
        let prepare_ms = prepare_started_at.elapsed().as_millis();

        let (state_batches, transaction_batch) = batches;
        let preload = verification::preload_transactions::<E, P, H, HashSt>(
            runtime.child("preload_transactions"),
            self.hash_strategy.clone(),
            Arc::clone(&prepared),
        );
        if let Err(reason) = preload.await {
            verification::reject(header.height, reason);
            return None;
        }

        let signature = verification::verify_signatures::<E, P, H, B, SigSt>(
            runtime.child("verify_signatures"),
            self.signature_strategy.clone(),
            self.transaction_namespace,
            Arc::clone(&prepared),
        );
        let execution = verification::execute_block(
            state_batches,
            transaction_batch,
            &self.hash_strategy,
            parent,
            prepared.as_ref(),
        );
        let sleep = verification::wait_for_timestamp(runtime, deadline);

        let (signature_ms, execution, sleep_ms) =
            match futures::try_join!(signature, execution, sleep) {
                Ok(result) => result,
                Err(reason) => {
                    verification::reject(header.height, reason);
                    return None;
                }
            };

        if !verification::commitments_match(&header, &execution) {
            return None;
        }

        info!(
            epoch = header.context.round.epoch().get(),
            view = header.context.round.view().get(),
            height = header.height,
            txs = execution.transaction_count,
            timestamp = header.timestamp,
            signature_ms,
            sleep_ms,
            prepare_ms,
            prepare_signers_ms = execution.timings.prepare_signers_ms,
            load_state_ms = execution.timings.load_state_ms,
            execute_ms = execution.timings.execute_ms,
            finalize_ms = execution.timings.finalize_ms,
            total_ms = verify_started_at.elapsed().as_millis(),
            "verified block"
        );
        Some(execution.into_merkleized())
    }

    /// Applies a certified block to speculative batches.
    #[doc(hidden)]
    pub async fn apply_certified<E>(
        &mut self,
        (runtime, _): (E, Context<C, P>),
        block: &SealedBlock<C, P, H>,
        batches: <<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <<Self as CApplication<E>>::Databases as DatabaseSet<E>>::Merkleized
    where
        E: Rng + Spawner + Storage + Metrics + Clock + CryptoRngCore,
        S: Scheme<PublicKey = P>,
        I: TransactionSource<C, P, H> + Sync,
        B: BatchVerifier<PublicKey = P> + Send + Sync + 'static,
        SigSt: Strategy + Clone + Send + Sync + 'static,
        HashSt: Strategy + Clone + Send + Sync + 'static,
    {
        let prepared = Arc::new(verification::prepare_transactions(block.body.clone()));
        let preload = verification::preload_transactions::<E, P, H, HashSt>(
            runtime.child("preload_transactions"),
            self.hash_strategy.clone(),
            Arc::clone(&prepared),
        );
        preload
            .await
            .unwrap_or_else(|reason| panic!("certified block contained {reason}"));

        let signature = verification::verify_signatures::<E, P, H, B, SigSt>(
            runtime,
            self.signature_strategy.clone(),
            self.transaction_namespace,
            Arc::clone(&prepared),
        );
        let (state_batches, transaction_batch) = batches;
        let execution = verification::apply_block(
            state_batches,
            transaction_batch,
            &self.hash_strategy,
            mmr::Location::new(block.header.transactions_range.start()),
            prepared.as_ref(),
        );

        match futures::try_join!(signature, execution) {
            Ok((_signature_ms, merkleized)) => merkleized,
            Err(reason) => panic!("certified block contained {reason}"),
        }
    }
}

impl<E, H, C, S, P, I, B, SigSt, HashSt> CApplication<E>
    for Application<H, C, S, P, I, B, SigSt, HashSt>
where
    E: Rng + Spawner + Storage + Metrics + Clock + CryptoRngCore,
    H: Hasher,
    C: Digest,
    S: Scheme<PublicKey = P>,
    P: PublicKey,
    I: TransactionSource<C, P, H> + Sync,
    B: BatchVerifier<PublicKey = P> + Send + Sync + 'static,
    SigSt: Strategy + Clone + Send + Sync + 'static,
    HashSt: Strategy + Clone + Send + Sync + 'static,
{
    type SigningScheme = S;
    type Context = Context<C, P>;
    type Block = SealedBlock<C, P, H>;
    type Databases = Databases<E, H, P, EightCap, HashSt>;
    type InputProvider = I;

    /// Returns the sync targets required to fetch the block's state.
    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        (
            Target {
                root: block.header.state_root,
                range: non_empty_range!(
                    mmr::Location::new(block.header.state_range.start()),
                    mmr::Location::new(block.header.state_range.end())
                ),
            },
            header_range_to_target(
                block.header.transactions_root,
                block.header.transactions_range.clone(),
            ),
        )
    }

    /// Builds the genesis block.
    ///
    /// The genesis block always uses timestamp `0` and the configured genesis
    /// leader.
    async fn genesis(&mut self) -> Self::Block {
        genesis_block(
            &mut H::default(),
            self.genesis_leader.clone(),
            0,
            self.genesis_transactions_target.clone(),
        )
    }

    /// Proposes the next block from the mempool and current ancestry.
    ///
    /// Proposal consumes already-verified mempool transactions, preloads the
    /// touched accounts, filters out statically invalid transfers, and
    /// executes the survivors against in-memory state before block
    /// construction.
    async fn propose<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        context: (E, Self::Context),
        mut ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        input: &mut Self::InputProvider,
    ) -> Option<Proposed<Self, E>> {
        let parent = ancestry.next().await?;
        self.propose_child(context, &parent, batches, input).await
    }

    /// Verifies a proposed block against speculative execution.
    ///
    /// Verification rejects invalid transaction signatures and invalid
    /// timestamps, then waits until the block timestamp has passed to
    /// account for clock skew. After the wait, it re-executes the block
    /// and compares all derived roots and ranges.
    async fn verify<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        context: (E, Self::Context),
        mut ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        let block = ancestry.next().await?;
        let parent = ancestry.next().await?;
        self.verify_child(context, block, &parent, batches).await
    }

    /// Applies a certified block to speculative batches and returns merkleized state.
    ///
    /// Unlike verification, application assumes consensus has already
    /// certified the block. It reconstitutes verified execution transactions
    /// from the signed wire block and deterministically replays them to
    /// derive the merkleized state batch.
    ///
    /// # Panics
    ///
    /// Panics if the certified block contains an invalid signature or if
    /// execution or database finalization fails.
    async fn apply(
        &mut self,
        context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet<E>>::Merkleized {
        self.apply_certified(context, block, batches).await
    }

    async fn finalized(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        databases: &Self::Databases,
    ) {
        let height = block.header.height;
        if !self.should_prune_after_finalize(height) {
            return;
        }

        (self.finalized_pruner)(Height::new(height)).await;

        let (state, _) = databases;
        {
            let mut state = state.write().await;
            let prune_to = state.sync_boundary();
            state
                .prune(prune_to)
                .await
                .expect("state db prune must not fail at the sync boundary");
        }

        // The transaction history database uses compact storage, so it already
        // retains only the compact frontier and exposes no explicit prune API.
    }
}

/// Creates the genesis block.
///
/// The genesis block starts with empty state, the initialized transaction
/// history target, and the provided leader and timestamp.
pub fn genesis_block<C, P, H>(
    hasher: &mut H,
    leader: P,
    timestamp: u64,
    transactions_target: TransactionHistoryTarget<H::Digest>,
) -> SealedBlock<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let header = Header {
        context: Context {
            round: Round::zero(),
            leader,
            parent: (View::zero(), C::EMPTY),
        },
        parent: H::Digest::EMPTY,
        height: 0,
        timestamp,
        state_root: H::Digest::EMPTY,
        state_range: non_empty_range!(0, 1),
        transactions_root: transactions_target.root,
        transactions_range: non_empty_range!(0, *transactions_target.leaf_count),
    };

    Block::<C, P, H>::new(header, Vec::new()).seal(hasher)
}

#[cfg(test)]
mod tests {
    use super::{
        TransactionHistoryTarget, genesis_block, history::parent_transactions_inactivity_floor,
    };
    use commonware_cryptography::{Digest as _, Hasher as _, Signer as _, ed25519, sha256};
    use commonware_utils::non_empty_range;
    use constantinople_primitives::{Block, Sealable, Signable, Transaction};
    use std::num::NonZeroU64;

    #[test]
    fn parent_inactivity_floor_skips_the_parent_commit() {
        let leader = ed25519::PrivateKey::from_seed(7);
        let recipient = ed25519::PrivateKey::from_seed(8);
        let genesis_target = TransactionHistoryTarget {
            root: sha256::Digest::EMPTY,
            leaf_count: commonware_storage::mmr::Location::new(1),
        };
        let mut header = genesis_block::<sha256::Digest, _, sha256::Sha256>(
            &mut sha256::Sha256::default(),
            leader.public_key(),
            0,
            genesis_target,
        )
        .into_inner()
        .header;
        header.transactions_range = non_empty_range!(5, 10);

        let to = recipient.public_key();
        let parent = Block::<sha256::Digest, _, sha256::Sha256>::new(
            header,
            (0..3)
                .map(|nonce| {
                    Transaction::new(
                        leader.public_key(),
                        to.clone(),
                        NonZeroU64::new(nonce + 1).expect("test value should be non-zero"),
                        nonce,
                    )
                    .seal_and_sign(
                        &leader,
                        constantinople_primitives::TRANSACTION_NAMESPACE,
                        &mut sha256::Sha256::default(),
                    )
                })
                .collect(),
        )
        .seal(&mut sha256::Sha256::default());

        assert_eq!(
            parent_transactions_inactivity_floor(&parent),
            commonware_storage::mmr::Location::new(6)
        );
    }

    #[test]
    fn genesis_block_uses_the_initialized_transaction_target() {
        let leader = ed25519::PrivateKey::from_seed(11).public_key();
        let target = TransactionHistoryTarget {
            root: sha256::Sha256::hash(b"genesis"),
            leaf_count: commonware_storage::mmr::Location::new(1),
        };

        let block = genesis_block::<sha256::Digest, _, sha256::Sha256>(
            &mut sha256::Sha256::default(),
            leader,
            0,
            target.clone(),
        );

        assert_eq!(block.header.transactions_root, target.root);
        assert_eq!(block.header.transactions_range, non_empty_range!(0, 1));
    }
}
