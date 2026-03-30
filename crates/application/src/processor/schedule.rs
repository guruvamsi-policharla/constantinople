//! Greedy transaction scheduling and adaptive round execution.
//!
//! This module keeps the processor's parallel policy out of the main
//! transaction orchestration path. It has two jobs:
//!
//! - build cheap dependency rounds from declared read/write sets
//! - execute those rounds either inline or in coarse parallel chunks
//!
//! The scheduler is intentionally greedy and linear. It does not build an
//! explicit dependency graph or run a topological sort. Instead it tracks the
//! latest round that read or wrote each key and places each transaction into
//! the earliest legal round.
//!
//! Execution is adaptive:
//!
//! - schedules with little parallelism stay fully sequential
//! - small rounds stay inline
//! - wide rounds are chunked before they reach [`Strategy`]
//!
//! That keeps the hot path cheap and avoids paying thread-pool overhead for
//! schedules that are effectively serial anyway.
//!
//! Sources:
//!
//! - M. V. Hermenegildo and F. Bueno, "A methodology for granularity-based
//!   control of parallelism in logic programs", 1996.
//!   <https://doi.org/10.1006/jsco.1996.0038>

use super::{
    ProcessorOutput,
    state::{AccessListBuilder, AccessSet, FrameDiff, State},
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use constantinople_primitives::{
    AccessList, AccessMode, Address, Receipt, Slot, VerifiedTransaction,
};
use std::collections::HashMap;

/// The result of executing a prepared transaction slice before changeset export.
#[derive(Debug)]
pub struct ExecutedPrepared<D: Digest> {
    /// The final in-memory state after all transaction diffs have been merged.
    pub state: State,
    /// Receipts in transaction order.
    pub receipts: Vec<Receipt<D>>,
    /// Optionally built access lists in transaction order.
    pub access_lists: Option<Vec<Option<AccessList>>>,
}

/// Prepared processor inputs for repeated in-memory execution.
#[derive(Debug, Clone)]
pub struct PreparedExecution {
    /// The loaded in-memory state snapshot to clone for each execution.
    pub(super) state: State,
    /// Per-transaction metadata shared across executions.
    scheduled: Vec<ScheduledTransaction>,
    /// Greedy dependency rounds in transaction-index space.
    rounds: Vec<Vec<usize>>,
    /// Cheap schedule summary used to choose inline vs parallel execution.
    stats: ScheduleStats,
}

/// One scheduled transaction and its effective declared access set.
#[derive(Debug, Clone)]
pub(super) struct ScheduledTransaction {
    /// The transaction's original position in the slice.
    pub(super) index: usize,
    /// The transaction's effective read/write footprint.
    pub(super) access: AccessSet,
}

/// The result of executing one transaction against one state snapshot.
#[derive(Debug)]
pub(super) struct TransactionExecution<D: Digest> {
    /// The final receipt reported for the transaction.
    pub(super) receipt: Receipt<D>,
    /// The committed diff that should merge into processor state.
    pub(super) diff: FrameDiff,
    /// The optionally built access list for the transaction.
    pub(super) access_list: Option<AccessList>,
}

/// Summary information about a greedy schedule.
#[derive(Debug, Clone, Copy, Default)]
struct ScheduleStats {
    /// The number of dependency rounds in the schedule.
    total_rounds: usize,
    /// The number of rounds that contain exactly one transaction.
    singleton_rounds: usize,
    /// The widest round in the schedule.
    max_width: usize,
    /// The number of transactions that appear in non-singleton rounds.
    parallel_transactions: usize,
}

/// Shared execution inputs for one prepared transaction slice.
///
/// This keeps the round-execution helpers from passing a long argument list
/// around while still making the execution dependencies explicit.
struct ExecutionContext<'a, PK, H, F>
where
    H: Hasher,
    PK: PublicKey,
{
    /// Scheduled metadata for every transaction in the slice.
    scheduled: &'a [ScheduledTransaction],
    /// The original verified transactions in slice order.
    transactions: &'a [VerifiedTransaction<PK, H>],
    /// Whether successful transactions should return built access lists.
    build_access_lists: bool,
    /// The processor callback used to execute one transaction.
    execute_transaction: F,
}

/// Parallel dispatch is usually a loss below roughly two chunks per worker.
const MIN_PARALLEL_ROUND_FACTOR: usize = 2;
/// Parallelizing fewer than this many transactions per worker is rarely worth it.
const MIN_PARALLEL_TXS_FACTOR: usize = 4;
/// Coarse chunks keep scheduler overhead small on wide independent rounds.
const MIN_PARALLEL_CHUNK_SIZE: usize = 32;

/// Prepares transactions for repeated execution from an in-memory state snapshot.
pub(super) fn prepare<H, PK>(
    state: State,
    transactions: &[VerifiedTransaction<PK, H>],
    access_set: impl Fn(&VerifiedTransaction<PK, H>) -> AccessSet,
) -> PreparedExecution
where
    H: Hasher,
    PK: PublicKey,
{
    let scheduled = transactions
        .iter()
        .enumerate()
        .map(|(index, transaction)| ScheduledTransaction {
            index,
            access: access_set(transaction),
        })
        .collect::<Vec<_>>();
    let (rounds, stats) = schedule_rounds(&scheduled);

    PreparedExecution {
        state,
        scheduled,
        rounds,
        stats,
    }
}

/// Executes a prepared transaction slice.
///
/// The prepared state snapshot is cloned once per execution. Results are
/// always merged back into committed state in original transaction order,
/// even when the round body ran out of order or in parallel.
pub(super) fn execute_prepared<H, PK, S, F>(
    strategy: &S,
    prepared: &PreparedExecution,
    transactions: &[VerifiedTransaction<PK, H>],
    build_access_lists: bool,
    execute_transaction: F,
) -> ExecutedPrepared<H::Digest>
where
    H: Hasher,
    PK: PublicKey,
    S: Strategy,
    F: Fn(
            &State,
            &VerifiedTransaction<PK, H>,
            &AccessSet,
            Option<AccessListBuilder>,
        ) -> TransactionExecution<H::Digest>
        + Sync,
{
    let mut state = prepared.state.clone();
    let execution = ExecutionContext {
        scheduled: &prepared.scheduled,
        transactions,
        build_access_lists,
        execute_transaction,
    };
    let mut receipts = vec![None; transactions.len()];
    let mut access_lists = build_access_lists.then(|| vec![None; transactions.len()]);

    if should_execute_sequentially(strategy, prepared.stats) {
        execute_transactions_inline(&mut state, &execution, &mut receipts, &mut access_lists);
    } else {
        for round in &prepared.rounds {
            let results = execute_round(strategy, &state, &execution, round);

            for (transaction_index, result) in round.iter().copied().zip(results) {
                state.apply(result.diff);
                receipts[transaction_index] = Some(result.receipt);

                if let Some(access_lists) = &mut access_lists {
                    access_lists[transaction_index] = result.access_list;
                }
            }
        }
    }

    ExecutedPrepared {
        state,
        receipts: receipts
            .into_iter()
            .map(|receipt| receipt.expect("every transaction must produce a receipt"))
            .collect(),
        access_lists,
    }
}

/// Executes a prepared transaction slice and exports its persistent changeset.
pub(super) fn execute<H, PK, S, F>(
    strategy: &S,
    prepared: &PreparedExecution,
    transactions: &[VerifiedTransaction<PK, H>],
    build_access_lists: bool,
    execute_transaction: F,
) -> ProcessorOutput<H::Digest>
where
    H: Hasher,
    PK: PublicKey,
    S: Strategy,
    F: Fn(
            &State,
            &VerifiedTransaction<PK, H>,
            &AccessSet,
            Option<AccessListBuilder>,
        ) -> TransactionExecution<H::Digest>
        + Sync,
{
    let executed = execute_prepared(
        strategy,
        prepared,
        transactions,
        build_access_lists,
        execute_transaction,
    );

    ProcessorOutput {
        changeset: executed.state.changeset::<H>(strategy),
        receipts: executed.receipts,
        access_lists: executed.access_lists,
    }
}

/// Executes one dependency round either inline or in coarse parallel chunks.
fn execute_round<H, PK, S, F>(
    strategy: &S,
    state: &State,
    execution: &ExecutionContext<'_, PK, H, F>,
    round: &[usize],
) -> Vec<TransactionExecution<H::Digest>>
where
    H: Hasher,
    PK: PublicKey,
    S: Strategy,
    F: Fn(
            &State,
            &VerifiedTransaction<PK, H>,
            &AccessSet,
            Option<AccessListBuilder>,
        ) -> TransactionExecution<H::Digest>
        + Sync,
{
    if should_execute_round_inline(strategy, round) {
        return execute_round_inline(state, execution, round);
    }

    let grain_size = parallel_grain_size(strategy, round.len());
    let chunk_results = strategy.map_collect_vec(round.chunks(grain_size), |chunk| {
        execute_round_inline(state, execution, chunk)
    });

    let mut results = Vec::with_capacity(round.len());
    for chunk in chunk_results {
        results.extend(chunk);
    }
    results
}

/// Executes a contiguous subset of one dependency round inline.
fn execute_round_inline<H, PK, F>(
    state: &State,
    execution: &ExecutionContext<'_, PK, H, F>,
    round: &[usize],
) -> Vec<TransactionExecution<H::Digest>>
where
    H: Hasher,
    PK: PublicKey,
    F: Fn(
        &State,
        &VerifiedTransaction<PK, H>,
        &AccessSet,
        Option<AccessListBuilder>,
    ) -> TransactionExecution<H::Digest>,
{
    let mut results = Vec::with_capacity(round.len());

    for transaction_index in round {
        let transaction = &execution.transactions[*transaction_index];
        let scheduled = &execution.scheduled[*transaction_index];
        let access_list_builder = execution
            .build_access_lists
            .then(AccessListBuilder::default);
        results.push((execution.execute_transaction)(
            state,
            transaction,
            &scheduled.access,
            access_list_builder,
        ));
    }

    results
}

/// Executes the entire prepared slice inline without walking round boundaries.
///
/// This is the fast path for effectively serial schedules, where repeatedly
/// dispatching tiny rounds through the strategy would only add overhead.
fn execute_transactions_inline<H, PK, F>(
    state: &mut State,
    execution: &ExecutionContext<'_, PK, H, F>,
    receipts: &mut [Option<Receipt<H::Digest>>],
    access_lists: &mut Option<Vec<Option<AccessList>>>,
) where
    H: Hasher,
    PK: PublicKey,
    F: Fn(
        &State,
        &VerifiedTransaction<PK, H>,
        &AccessSet,
        Option<AccessListBuilder>,
    ) -> TransactionExecution<H::Digest>,
{
    for scheduled in execution.scheduled {
        let transaction_index = scheduled.index;
        let transaction = &execution.transactions[transaction_index];
        let access_list_builder = execution
            .build_access_lists
            .then(AccessListBuilder::default);
        let result = (execution.execute_transaction)(
            state,
            transaction,
            &scheduled.access,
            access_list_builder,
        );

        state.apply(result.diff);
        receipts[transaction_index] = Some(result.receipt);

        if let Some(access_lists) = access_lists {
            access_lists[transaction_index] = result.access_list;
        }
    }
}

/// Builds greedy dependency rounds from the effective access sets.
///
/// Each transaction is placed into the earliest round that does not violate
/// any read-after-write, write-after-read, or write-after-write dependency.
/// The algorithm is a single left-to-right pass over the transaction slice.
fn schedule_rounds(scheduled: &[ScheduledTransaction]) -> (Vec<Vec<usize>>, ScheduleStats) {
    let mut rounds: Vec<Vec<usize>> = Vec::new();
    let mut account_reads: HashMap<Address, usize> = HashMap::new();
    let mut account_writes: HashMap<Address, usize> = HashMap::new();
    let mut storage_reads: HashMap<(Address, Slot), usize> = HashMap::new();
    let mut storage_writes: HashMap<(Address, Slot), usize> = HashMap::new();

    for transaction in scheduled {
        let mut ready_round = 0;

        for (address, mode) in transaction.access.accounts() {
            match mode {
                AccessMode::Read => {
                    if let Some(round) = account_writes.get(&address) {
                        ready_round = ready_round.max(round + 1);
                    }
                }
                AccessMode::Write => {
                    if let Some(round) = account_reads.get(&address) {
                        ready_round = ready_round.max(round + 1);
                    }
                    if let Some(round) = account_writes.get(&address) {
                        ready_round = ready_round.max(round + 1);
                    }
                }
            }
        }

        for (address, slot, mode) in transaction.access.storage() {
            let key = (address, slot);
            match mode {
                AccessMode::Read => {
                    if let Some(round) = storage_writes.get(&key) {
                        ready_round = ready_round.max(round + 1);
                    }
                }
                AccessMode::Write => {
                    if let Some(round) = storage_reads.get(&key) {
                        ready_round = ready_round.max(round + 1);
                    }
                    if let Some(round) = storage_writes.get(&key) {
                        ready_round = ready_round.max(round + 1);
                    }
                }
            }
        }

        while rounds.len() <= ready_round {
            rounds.push(Vec::new());
        }
        rounds[ready_round].push(transaction.index);

        for (address, mode) in transaction.access.accounts() {
            account_reads.insert(address, ready_round);
            if mode == AccessMode::Write {
                account_writes.insert(address, ready_round);
            }
        }

        for (address, slot, mode) in transaction.access.storage() {
            storage_reads.insert((address, slot), ready_round);
            if mode == AccessMode::Write {
                storage_writes.insert((address, slot), ready_round);
            }
        }
    }

    let stats = schedule_stats(&rounds);
    (rounds, stats)
}

/// Derives cheap schedule statistics used by the adaptive execution policy.
fn schedule_stats(rounds: &[Vec<usize>]) -> ScheduleStats {
    let mut stats = ScheduleStats {
        total_rounds: rounds.len(),
        ..ScheduleStats::default()
    };

    for round in rounds {
        stats.max_width = stats.max_width.max(round.len());
        if round.len() == 1 {
            stats.singleton_rounds += 1;
            continue;
        }

        stats.parallel_transactions += round.len();
    }

    stats
}

/// Returns whether the whole schedule should run inline.
///
/// This prefers sequential execution when the schedule exposes too little
/// parallelism to amortize the strategy's dispatch overhead.
fn should_execute_sequentially(strategy: &impl Strategy, stats: ScheduleStats) -> bool {
    let parallelism = strategy.parallelism_hint().max(1);
    if parallelism == 1 {
        return true;
    }

    if stats.max_width < 2 {
        return true;
    }

    if stats.parallel_transactions < parallelism * MIN_PARALLEL_TXS_FACTOR {
        return true;
    }

    stats.singleton_rounds * 2 >= stats.total_rounds
}

/// Returns whether one round is too small to benefit from parallel dispatch.
fn should_execute_round_inline(strategy: &impl Strategy, round: &[usize]) -> bool {
    let parallelism = strategy.parallelism_hint().max(1);
    if parallelism == 1 {
        return true;
    }

    round.len() < parallelism * MIN_PARALLEL_ROUND_FACTOR
}

/// Returns the coarse chunk size for a wide parallel round.
///
/// The chunking heuristic targets a small multiple of the available workers
/// while enforcing a minimum chunk size so wide independent rounds do not
/// degenerate into one task per transaction.
fn parallel_grain_size(strategy: &impl Strategy, round_len: usize) -> usize {
    let parallelism = strategy.parallelism_hint().max(1);
    let target_chunks = parallelism * MIN_PARALLEL_ROUND_FACTOR;
    let evenly_split = round_len.div_ceil(target_chunks);
    evenly_split.max(MIN_PARALLEL_CHUNK_SIZE)
}
