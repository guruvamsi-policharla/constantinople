//! Consensus-facing application integration.
//!
//! The consensus wrapper is deliberately thin. It prepares block bodies,
//! delegates account transitions to the executor, updates the backing QMDB
//! batches, and checks the commitments that consensus votes on.

use crate::executor::{self, PreparedTransfer, State};
use commonware_codec::types::lazy::Lazy;
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
use constantinople_primitives::{
    Block, Header, Sealable, SealedBlock, SignedTransaction, materialize_transaction_chunks,
    verify_transaction_chunks,
};
use futures::StreamExt;
use hashbrown::HashSet;
use rand::Rng;
use rand_core::CryptoRngCore;
use std::{
    future::Future,
    marker::PhantomData,
    num::NonZeroU64,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use tracing::{info, warn};

mod db;
mod history;
mod time;

use db::{Databases, StateBatch, TransactionBatch, apply_changeset, apply_transaction_digests};
pub use db::{
    STATE_BITMAP_CHUNK_BYTES, TransactionHistoryDb, TransactionHistoryOperation,
    TransactionHistoryTarget,
};
use history::{
    child_transactions_range, header_range_to_target, parent_transactions_inactivity_floor,
};

type FinalizedPruneFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
type FinalizedPruneFn = Arc<dyn Fn(Height) -> FinalizedPruneFuture + Send + Sync>;
type Result<T> = core::result::Result<T, &'static str>;

const INVALID_SIGNATURE: &str = "invalid signature";
const SIGNATURE_TASK_CLOSED: &str = "signature verification task closed";
const MATERIALIZE_TASK_CLOSED: &str = "transaction materialization task closed";
const MALFORMED_TRANSACTION: &str = "malformed transaction";
const STATIC_INVALID_TRANSACTION: &str = "statically invalid transaction";

/// Core Constantinople application.
pub struct Application<H, C, S, P, I, B, SigSt, HashSt>
where
    H: Hasher,
{
    signature_strategy: SigSt,
    hash_strategy: HashSt,
    genesis_leader: P,
    transaction_namespace: &'static [u8],
    genesis_state_root: H::Digest,
    genesis_state_sync_root: H::Digest,
    genesis_state_range: commonware_utils::range::NonEmptyRange<u64>,
    genesis_transactions_target: TransactionHistoryTarget<H::Digest>,
    prune_cadence_blocks: NonZeroU64,
    finalized_pruner: FinalizedPruneFn,
    finalized_state_sync_start: Arc<AtomicU64>,
    proposed_transactions: Counter,
    _marker: PhantomData<(C, S, I, B)>,
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
            genesis_state_root: self.genesis_state_root,
            genesis_state_sync_root: self.genesis_state_sync_root,
            genesis_state_range: self.genesis_state_range.clone(),
            genesis_transactions_target: self.genesis_transactions_target.clone(),
            prune_cadence_blocks: self.prune_cadence_blocks,
            finalized_pruner: self.finalized_pruner.clone(),
            finalized_state_sync_start: self.finalized_state_sync_start.clone(),
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
    #[expect(
        clippy::too_many_arguments,
        reason = "the engine constructs the application from already grouped config"
    )]
    pub fn new(
        context: impl Metrics,
        signature_strategy: SigSt,
        hash_strategy: HashSt,
        genesis_leader: P,
        transaction_namespace: &'static [u8],
        genesis_state_root: H::Digest,
        genesis_state_sync_root: H::Digest,
        genesis_state_range: commonware_utils::range::NonEmptyRange<u64>,
        genesis_transactions_target: TransactionHistoryTarget<H::Digest>,
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
            genesis_state_root,
            genesis_state_sync_root,
            genesis_state_range,
            genesis_transactions_target,
            prune_cadence_blocks,
            finalized_pruner,
            finalized_state_sync_start: Arc::new(AtomicU64::new(0)),
            proposed_transactions,
            _marker: PhantomData,
        }
    }

    const fn should_prune_after_finalize(&self, height: u64) -> bool {
        height != 0 && height.is_multiple_of(self.prune_cadence_blocks.get())
    }

    fn state_sync_start(&self, parent: &SealedBlock<C, P, H>) -> u64 {
        parent
            .header
            .state_range
            .start()
            .max(self.finalized_state_sync_start.load(Ordering::Relaxed))
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
        let started_at = Instant::now();

        let input_started_at = Instant::now();
        let body = input.propose(&parent.header, &context).await;
        let input_ms = input_started_at.elapsed().as_millis();

        let prepare_started_at = Instant::now();
        let proposal_input = executor::prepare_proposal(body);
        let candidate_transfers = proposal_input
            .candidates
            .iter()
            .map(|candidate| candidate.transfer.clone())
            .collect::<Vec<_>>();
        let prepare_ms = prepare_started_at.elapsed().as_millis();

        let (state_batch, transaction_batch) = batches;
        let execution = self
            .execute_proposal(
                state_batch,
                transaction_batch,
                parent,
                proposal_input,
                &candidate_transfers,
            )
            .await;
        let ProposalExecution {
            block_execution,
            body,
        } = execution;

        self.proposed_transactions
            .inc_by(block_execution.transaction_count as u64);

        let header = Header {
            context,
            parent: parent.digest(),
            height: parent.header.height + 1,
            timestamp: time::timestamp_ms(&runtime),
            state_root: block_execution.state.root(),
            state_sync_root: block_execution.state.sync_root(),
            state_range: block_execution.state_sync_range.clone(),
            transactions_root: block_execution.transactions.root(),
            transactions_range: block_execution.transactions_range.clone(),
        };
        let block = Block::new(header, body).seal(&mut H::default());

        info!(
            epoch = block.header.context.round.epoch().get(),
            view = block.header.context.round.view().get(),
            height = block.header.height,
            txs = block_execution.transaction_count,
            timestamp = block.header.timestamp,
            input_ms,
            prepare_ms,
            load_state_ms = block_execution.timings.load_state_ms,
            execute_ms = block_execution.timings.execute_ms,
            finalize_ms = block_execution.timings.finalize_ms,
            total_ms = started_at.elapsed().as_millis(),
            "proposed block"
        );

        Some(Proposed {
            block,
            merkleized: block_execution.into_merkleized(),
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
        let started_at = Instant::now();
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

        let body = Arc::new(PreparedBody { transactions: body });
        let (state_batch, transaction_batch) = batches;
        let signatures = verify_signatures::<E, P, H, B, SigSt, HashSt>(
            runtime.child("verify_signatures"),
            self.signature_strategy.clone(),
            self.hash_strategy.clone(),
            self.transaction_namespace,
            Arc::clone(&body),
        );
        let execution = execute_body(
            state_batch,
            transaction_batch,
            parent,
            self.state_sync_start(parent),
            Arc::clone(&body),
        );
        let wait = wait_for_timestamp(runtime, time::block_deadline(header.timestamp));

        let (signature_ms, execution, sleep_ms) =
            match futures::try_join!(signatures, execution, wait) {
                Ok(result) => result,
                Err(reason) => {
                    reject(header.height, reason);
                    return None;
                }
            };

        if !commitments_match(&header, &execution) {
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
            prepare_ms = execution.timings.prepare_ms,
            load_state_ms = execution.timings.load_state_ms,
            execute_ms = execution.timings.execute_ms,
            finalize_ms = execution.timings.finalize_ms,
            total_ms = started_at.elapsed().as_millis(),
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
        let materialized =
            materialize_body(runtime, self.hash_strategy.clone(), block.body.clone())
                .await
                .unwrap_or_else(|reason| panic!("certified block contained {reason}"));
        let body = materialized
            .iter()
            .map(executor::prepare_transfer)
            .collect::<Option<Vec<_>>>()
            .unwrap_or_else(|| panic!("certified block contained {MALFORMED_TRANSACTION}"));

        let (state_batch, transaction_batch) = batches;
        apply_prepared_body(
            state_batch,
            transaction_batch,
            mmr::Location::new(block.header.transactions_range.start()),
            &body,
        )
        .await
        .unwrap_or_else(|reason| panic!("certified block contained {reason}"))
    }

    async fn execute_proposal<E>(
        &self,
        state_batch: StateBatch<E, H, P, EightCap, HashSt>,
        transaction_batch: TransactionBatch<E, H, HashSt>,
        parent: &SealedBlock<C, P, H>,
        proposal_input: executor::ProposalInput<P, H>,
        candidate_transfers: &[PreparedTransfer<P, H>],
    ) -> ProposalExecution<E, H, P, HashSt>
    where
        E: Storage + Clock + Metrics,
        HashSt: Strategy,
    {
        let load_started_at = Instant::now();
        let state = load_state(&state_batch, candidate_transfers)
            .await
            .expect("proposal state loading must succeed");
        let load_state_ms = load_started_at.elapsed().as_millis();

        let execute_started_at = Instant::now();
        let output = executor::propose_prepared(&state, proposal_input);
        let execute_ms = execute_started_at.elapsed().as_millis();
        let transfers = output
            .valid
            .iter()
            .map(executor::prepare_transfer)
            .collect::<Option<Vec<_>>>()
            .expect("included proposal transactions were already prepared");
        let digests = transfer_digests(&transfers);
        let state_sync_range = child_state_sync_range(
            parent,
            self.state_sync_start(parent),
            output.changeset.len(),
        );
        let state_batch = apply_changeset(state_batch, &output.changeset);
        let transaction_batch = apply_transaction_digests(transaction_batch, &digests);
        let timings = Timings::before_finalize(0, load_state_ms, execute_ms);
        let execution = finalize_child(
            state_batch,
            transaction_batch,
            parent,
            state_sync_range,
            output.valid.len(),
            timings,
            "database merkleization must succeed",
        )
        .await;

        ProposalExecution {
            block_execution: execution,
            body: output.valid,
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

    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        (
            Target {
                root: block.header.state_sync_root,
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

    async fn genesis(&mut self) -> Self::Block {
        genesis_block(
            &mut H::default(),
            self.genesis_leader.clone(),
            0,
            self.genesis_state_root,
            self.genesis_state_sync_root,
            self.genesis_state_range.clone(),
            self.genesis_transactions_target.clone(),
        )
    }

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
        let mut state = state.write().await;
        let prune_to = state.sync_boundary();
        state
            .prune(prune_to)
            .await
            .expect("state db prune must not fail at the sync boundary");
        self.finalized_state_sync_start
            .store(*prune_to, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct PreparedBody<P, H>
where
    H: Hasher,
    P: PublicKey,
{
    transactions: Vec<Lazy<SignedTransaction<P, H>>>,
}

struct ProposalExecution<E, H, P, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    block_execution: BlockExecution<E, H, P, S>,
    body: Vec<SignedTransaction<P, H>>,
}

struct BlockExecution<E, H, P, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    state: db::StateMerkleized<E, H, P, EightCap, S>,
    transactions: db::TransactionMerkleized<E, H, S>,
    state_sync_range: commonware_utils::range::NonEmptyRange<u64>,
    transactions_range: commonware_utils::range::NonEmptyRange<u64>,
    transaction_count: usize,
    timings: Timings,
}

impl<E, H, P, S> BlockExecution<E, H, P, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    fn into_merkleized(self) -> db::MerkleizedDatabases<E, H, P, S> {
        (self.state, self.transactions)
    }
}

#[derive(Debug, Clone, Copy)]
struct Timings {
    prepare_ms: u128,
    load_state_ms: u128,
    execute_ms: u128,
    finalize_ms: u128,
}

impl Timings {
    const fn before_finalize(prepare_ms: u128, load_state_ms: u128, execute_ms: u128) -> Self {
        Self {
            prepare_ms,
            load_state_ms,
            execute_ms,
            finalize_ms: 0,
        }
    }

    const fn with_finalize_ms(mut self, finalize_ms: u128) -> Self {
        self.finalize_ms = finalize_ms;
        self
    }
}

async fn verify_signatures<E, P, H, B, SigSt, HashSt>(
    runtime: E,
    signature_strategy: SigSt,
    hash_strategy: HashSt,
    namespace: &'static [u8],
    body: Arc<PreparedBody<P, H>>,
) -> Result<u128>
where
    E: Spawner + CryptoRngCore,
    P: PublicKey,
    H: Hasher,
    B: BatchVerifier<PublicKey = P> + Send + Sync + 'static,
    SigSt: Strategy + Send + Sync + 'static,
    HashSt: Strategy + Send + Sync + 'static,
{
    let (result_tx, result_rx) = futures::channel::oneshot::channel();
    let _handle = runtime.shared(true).spawn(move |mut runtime| async move {
        let started_at = Instant::now();
        let result = verify_transaction_chunks::<P, H, B, _, _>(
            &signature_strategy,
            &hash_strategy,
            namespace,
            &mut runtime,
            body.transactions.clone(),
        )
        .map(|_| started_at.elapsed().as_millis())
        .ok_or(INVALID_SIGNATURE);
        let _ = result_tx.send(result);
    });

    result_rx.await.map_err(|_| SIGNATURE_TASK_CLOSED)?
}

async fn materialize_body<E, P, H, HashSt>(
    runtime: E,
    hash_strategy: HashSt,
    transactions: Vec<Lazy<SignedTransaction<P, H>>>,
) -> Result<Vec<SignedTransaction<P, H>>>
where
    E: Spawner,
    P: PublicKey,
    H: Hasher,
    HashSt: Strategy + Send + Sync + 'static,
{
    let (result_tx, result_rx) = futures::channel::oneshot::channel();
    let _handle = runtime.shared(true).spawn(move |_| async move {
        let result = materialize_transaction_chunks(&hash_strategy, transactions)
            .ok_or(MALFORMED_TRANSACTION);
        let _ = result_tx.send(result);
    });

    result_rx.await.map_err(|_| MATERIALIZE_TASK_CLOSED)?
}

async fn execute_body<E, C, P, H, S>(
    state_batch: StateBatch<E, H, P, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent: &SealedBlock<C, P, H>,
    state_sync_start: u64,
    body: Arc<PreparedBody<P, H>>,
) -> Result<BlockExecution<E, H, P, S>>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    let prepare_started_at = Instant::now();
    let transfers = body
        .transactions
        .iter()
        .map(|transaction| executor::prepare_transfer(transaction.get()?))
        .collect::<Option<Vec<_>>>()
        .ok_or(MALFORMED_TRANSACTION)?;
    let prepare_ms = prepare_started_at.elapsed().as_millis();

    execute_prepared_child(
        state_batch,
        transaction_batch,
        parent,
        state_sync_start,
        &transfers,
        prepare_ms,
    )
    .await
}

async fn execute_prepared_child<E, C, P, H, S>(
    state_batch: StateBatch<E, H, P, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent: &SealedBlock<C, P, H>,
    state_sync_start: u64,
    transfers: &[PreparedTransfer<P, H>],
    prepare_ms: u128,
) -> Result<BlockExecution<E, H, P, S>>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    let load_started_at = Instant::now();
    let state = load_state(&state_batch, transfers)
        .await
        .expect("block state loading must succeed");
    let load_state_ms = load_started_at.elapsed().as_millis();

    let execute_started_at = Instant::now();
    let changeset = executor::execute(&state, transfers).ok_or(STATIC_INVALID_TRANSACTION)?;
    let execute_ms = execute_started_at.elapsed().as_millis();
    let state_sync_range = child_state_sync_range(parent, state_sync_start, changeset.len());
    let digests = transfer_digests(transfers);
    let state_batch = apply_changeset(state_batch, &changeset);
    let transaction_batch = apply_transaction_digests(transaction_batch, &digests);
    let timings = Timings::before_finalize(prepare_ms, load_state_ms, execute_ms);

    Ok(finalize_child(
        state_batch,
        transaction_batch,
        parent,
        state_sync_range,
        transfers.len(),
        timings,
        "database merkleization during verification must succeed",
    )
    .await)
}

async fn apply_prepared_body<E, P, H, S>(
    state_batch: StateBatch<E, H, P, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    transaction_floor: mmr::Location,
    transfers: &[PreparedTransfer<P, H>],
) -> Result<db::MerkleizedDatabases<E, H, P, S>>
where
    E: Storage + Clock + Metrics,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    let state = load_state(&state_batch, transfers)
        .await
        .expect("state loading must succeed for certified apply");
    let changeset = executor::execute(&state, transfers).ok_or(STATIC_INVALID_TRANSACTION)?;
    let digests = transfer_digests(transfers);
    let state_batch = apply_changeset(state_batch, &changeset);
    let transaction_batch = apply_transaction_digests(transaction_batch, &digests)
        .with_inactivity_floor(transaction_floor);

    db::finalize_execution(state_batch, transaction_batch)
        .await
        .map_err(|_| STATIC_INVALID_TRANSACTION)
}

async fn load_state<E, H, P, S>(
    batch: &StateBatch<E, H, P, EightCap, S>,
    transfers: &[PreparedTransfer<P, H>],
) -> core::result::Result<State<P>, commonware_storage::qmdb::Error<mmr::Family>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    if transfers.is_empty() {
        return Ok(State::new());
    }

    let mut account_keys = HashSet::with_capacity(transfers.len().saturating_mul(2));
    for transfer in transfers {
        account_keys.insert(transfer.sender.clone());
        account_keys.insert(transfer.recipient.clone());
    }

    let account_keys = account_keys.into_iter().collect::<Vec<_>>();
    let keys = account_keys.iter().collect::<Vec<_>>();
    let values = batch.get_many(&keys).await?;
    Ok(account_keys
        .into_iter()
        .zip(values)
        .map(|(account_key, account)| (account_key, account.unwrap_or_default()))
        .collect())
}

async fn finalize_child<E, C, P, H, S>(
    state_batch: StateBatch<E, H, P, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent: &SealedBlock<C, P, H>,
    state_sync_range: commonware_utils::range::NonEmptyRange<u64>,
    transaction_count: usize,
    timings: Timings,
    expect_message: &'static str,
) -> BlockExecution<E, H, P, S>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    let transaction_batch =
        transaction_batch.with_inactivity_floor(parent_transactions_inactivity_floor(parent));
    let transactions_range = child_transactions_range(parent, transaction_count);
    let finalize_started_at = Instant::now();
    let (state, transactions) = db::finalize_execution(state_batch, transaction_batch)
        .await
        .expect(expect_message);
    let finalize_ms = finalize_started_at.elapsed().as_millis();

    BlockExecution {
        state,
        transactions,
        state_sync_range,
        transactions_range,
        transaction_count,
        timings: timings.with_finalize_ms(finalize_ms),
    }
}

fn child_state_sync_range<C, P, H>(
    parent: &SealedBlock<C, P, H>,
    state_sync_start: u64,
    state_write_count: usize,
) -> commonware_utils::range::NonEmptyRange<u64>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let state_ops = u64::try_from(state_write_count)
        .expect("state write count must fit into u64")
        .checked_add(1)
        .expect("state batch commit must not overflow u64");
    let state_sync_end = parent
        .header
        .state_range
        .end()
        .checked_add(state_ops)
        .expect("state sync range end must not overflow u64");
    non_empty_range!(state_sync_start, state_sync_end)
}

fn transfer_digests<P, H>(transfers: &[PreparedTransfer<P, H>]) -> Vec<H::Digest>
where
    H: Hasher,
    P: PublicKey,
{
    transfers.iter().map(|transfer| transfer.digest).collect()
}

async fn wait_for_timestamp<E>(runtime: E, deadline: std::time::SystemTime) -> Result<u128>
where
    E: Clock,
{
    let started_at = Instant::now();
    runtime.sleep_until(deadline).await;
    Ok(started_at.elapsed().as_millis())
}

fn reject(height: u64, reason: &'static str) {
    warn!(height, reason, "verify rejected");
}

fn commitments_match<E, C, P, H, S>(
    header: &Header<C, H::Digest, P>,
    execution: &BlockExecution<E, H, P, S>,
) -> bool
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    if execution.state.root() != header.state_root {
        warn!(
            height = header.height,
            "verify rejected: state root mismatch"
        );
        return false;
    }
    if execution.state.sync_root() != header.state_sync_root {
        warn!(
            height = header.height,
            "verify rejected: state sync root mismatch"
        );
        return false;
    }
    if execution.state_sync_range != header.state_range {
        warn!(
            height = header.height,
            "verify rejected: state range mismatch"
        );
        return false;
    }
    if execution.transactions.root() != header.transactions_root {
        warn!(
            height = header.height,
            "verify rejected: transaction root mismatch"
        );
        return false;
    }
    if execution.transactions_range != header.transactions_range {
        warn!(
            height = header.height,
            "verify rejected: transaction range mismatch"
        );
        return false;
    }

    true
}

/// Creates the genesis block.
pub fn genesis_block<C, P, H>(
    hasher: &mut H,
    leader: P,
    timestamp: u64,
    state_root: H::Digest,
    state_sync_root: H::Digest,
    state_range: commonware_utils::range::NonEmptyRange<u64>,
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
        state_root,
        state_sync_root,
        state_range,
        transactions_root: transactions_target.root,
        transactions_range: non_empty_range!(0, *transactions_target.leaf_count),
    };

    Block::<C, P, H>::new(header, Vec::new()).seal(hasher)
}

#[cfg(test)]
mod tests {
    use super::{TransactionHistoryTarget, genesis_block, parent_transactions_inactivity_floor};
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
            sha256::Digest::EMPTY,
            sha256::Digest::EMPTY,
            non_empty_range!(0, 1),
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
            sha256::Digest::EMPTY,
            sha256::Digest::EMPTY,
            non_empty_range!(0, 1),
            target.clone(),
        );

        assert_eq!(block.header.transactions_root, target.root);
        assert_eq!(block.header.transactions_range, non_empty_range!(0, 1));
    }
}
