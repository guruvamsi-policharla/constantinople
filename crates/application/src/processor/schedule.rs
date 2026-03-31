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

use super::{
    access::AccessSet,
    executor::ProcessorOutput,
    state::{FrameDiff, State},
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use constantinople_primitives::{
    AccessList, AccessMode, Address, Receipt, Slot, VerifiedTransaction,
};
use std::{collections::HashMap, sync::OnceLock};

/// The result of executing a prepared transaction slice before changeset export.
#[derive(Debug)]
pub(super) struct ExecutedPrepared<D: Digest> {
    /// The final in-memory state after all transaction diffs have been merged.
    pub state: State,
    /// Receipts in transaction order.
    pub receipts: Vec<Receipt<D>>,
    /// Optionally built access lists in transaction order.
    pub access_lists: Option<Vec<Option<AccessList>>>,
}

/// Prepared processor inputs for repeated in-memory execution.
#[derive(Debug)]
pub(super) struct PreparedExecution {
    /// The loaded in-memory state snapshot to clone for each execution.
    pub(super) state: State,
    /// Per-transaction metadata shared across executions.
    scheduled: Vec<ScheduledTransaction>,
    /// The greedy dependency round for each transaction.
    round_for_transaction: Vec<usize>,
    /// Lazily materialized round layout for parallel execution.
    rounds: OnceLock<MaterializedRounds>,
    /// Cheap schedule summary used to choose inline vs parallel execution.
    stats: ScheduleStats,
}

/// One scheduled transaction and its effective declared access set.
#[derive(Debug, Clone)]
pub(super) struct ScheduledTransaction {
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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

impl PreparedExecution {
    /// Returns the lazily materialized round layout used by parallel execution.
    fn materialized_rounds(&self) -> &MaterializedRounds {
        self.rounds.get_or_init(|| {
            MaterializedRounds::new(&self.round_for_transaction, self.stats.total_rounds)
        })
    }
}

/// A flat round layout for contiguous per-round transaction slices.
#[derive(Debug)]
struct MaterializedRounds {
    /// The start index of each round in `transaction_indices`.
    offsets: Vec<usize>,
    /// Transaction indices laid out contiguously by round.
    transaction_indices: Vec<usize>,
}

impl MaterializedRounds {
    /// Builds contiguous round slices from per-transaction round assignments.
    fn new(round_for_transaction: &[usize], total_rounds: usize) -> Self {
        let mut offsets = vec![0; total_rounds + 1];
        for &round in round_for_transaction {
            offsets[round + 1] += 1;
        }

        for round in 0..total_rounds {
            offsets[round + 1] += offsets[round];
        }

        let mut transaction_indices = vec![0; round_for_transaction.len()];
        let mut next_slot = offsets[..total_rounds].to_vec();
        for (transaction_index, &round) in round_for_transaction.iter().enumerate() {
            transaction_indices[next_slot[round]] = transaction_index;
            next_slot[round] += 1;
        }

        Self {
            offsets,
            transaction_indices,
        }
    }

    /// Returns the transaction indices for one dependency round.
    fn round(&self, round: usize) -> &[usize] {
        let start = self.offsets[round];
        let end = self.offsets[round + 1];
        &self.transaction_indices[start..end]
    }
}

impl ScheduleStats {
    /// Records that one transaction was placed into `round`.
    fn record_round_assignment(&mut self, round_widths: &mut Vec<usize>, round: usize) {
        while round_widths.len() <= round {
            round_widths.push(0);
            self.total_rounds += 1;
        }

        round_widths[round] += 1;
        let width = round_widths[round];
        self.max_width = self.max_width.max(width);

        match width {
            1 => {
                self.singleton_rounds += 1;
            }
            2 => {
                self.singleton_rounds -= 1;
                self.parallel_transactions += 2;
            }
            _ => {
                self.parallel_transactions += 1;
            }
        }
    }
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
    strategy: &impl Strategy,
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
        .map(|transaction| ScheduledTransaction {
            access: access_set(transaction),
        })
        .collect::<Vec<_>>();

    if strategy.parallelism_hint().max(1) == 1 {
        return PreparedExecution {
            state,
            scheduled,
            round_for_transaction: Vec::new(),
            rounds: OnceLock::new(),
            stats: ScheduleStats::default(),
        };
    }

    let (round_for_transaction, stats) = schedule_rounds(&scheduled);

    PreparedExecution {
        state,
        scheduled,
        round_for_transaction,
        rounds: OnceLock::new(),
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
    F: Fn(&State, &VerifiedTransaction<PK, H>, &AccessSet, bool) -> TransactionExecution<H::Digest>
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
        let rounds = prepared.materialized_rounds();
        for round_index in 0..prepared.stats.total_rounds {
            let round = rounds.round(round_index);
            if round.is_empty() {
                continue;
            }

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
    F: Fn(&State, &VerifiedTransaction<PK, H>, &AccessSet, bool) -> TransactionExecution<H::Digest>
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
    F: Fn(&State, &VerifiedTransaction<PK, H>, &AccessSet, bool) -> TransactionExecution<H::Digest>
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
    F: Fn(&State, &VerifiedTransaction<PK, H>, &AccessSet, bool) -> TransactionExecution<H::Digest>,
{
    let mut results = Vec::with_capacity(round.len());

    for transaction_index in round {
        let transaction = &execution.transactions[*transaction_index];
        let scheduled = &execution.scheduled[*transaction_index];
        results.push((execution.execute_transaction)(
            state,
            transaction,
            &scheduled.access,
            execution.build_access_lists,
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
    F: Fn(&State, &VerifiedTransaction<PK, H>, &AccessSet, bool) -> TransactionExecution<H::Digest>,
{
    for (transaction_index, scheduled) in execution.scheduled.iter().enumerate() {
        let transaction = &execution.transactions[transaction_index];
        let result = (execution.execute_transaction)(
            state,
            transaction,
            &scheduled.access,
            execution.build_access_lists,
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
fn schedule_rounds(scheduled: &[ScheduledTransaction]) -> (Vec<usize>, ScheduleStats) {
    const NONE: usize = usize::MAX;

    // Estimate unique keys from total access set sizes.
    let total_accesses: usize = scheduled.iter().map(|t| t.access.len()).sum();
    let mut accounts: HashMap<Address, (usize, usize)> =
        HashMap::with_capacity(total_accesses.min(scheduled.len() * 2));
    let mut storage: HashMap<(Address, Slot), (usize, usize)> =
        HashMap::with_capacity(total_accesses);
    let mut round_for_transaction = Vec::with_capacity(scheduled.len());
    let mut round_widths = Vec::new();
    let mut stats = ScheduleStats::default();

    for transaction in scheduled {
        let mut ready_round = 0;

        for (address, mode) in transaction.access.accounts() {
            if let Some(&(last_read, last_write)) = accounts.get(&address) {
                match mode {
                    AccessMode::Read => {
                        if last_write != NONE {
                            ready_round = ready_round.max(last_write + 1);
                        }
                    }
                    AccessMode::Write => {
                        if last_read != NONE {
                            ready_round = ready_round.max(last_read + 1);
                        }
                        if last_write != NONE {
                            ready_round = ready_round.max(last_write + 1);
                        }
                    }
                }
            }
        }

        for (address, slot, mode) in transaction.access.storage() {
            if let Some(&(last_read, last_write)) = storage.get(&(address, slot)) {
                match mode {
                    AccessMode::Read => {
                        if last_write != NONE {
                            ready_round = ready_round.max(last_write + 1);
                        }
                    }
                    AccessMode::Write => {
                        if last_read != NONE {
                            ready_round = ready_round.max(last_read + 1);
                        }
                        if last_write != NONE {
                            ready_round = ready_round.max(last_write + 1);
                        }
                    }
                }
            }
        }

        round_for_transaction.push(ready_round);
        stats.record_round_assignment(&mut round_widths, ready_round);

        for (address, mode) in transaction.access.accounts() {
            let entry = accounts.entry(address).or_insert((NONE, NONE));
            entry.0 = ready_round;
            if mode == AccessMode::Write {
                entry.1 = ready_round;
            }
        }

        for (address, slot, mode) in transaction.access.storage() {
            let entry = storage.entry((address, slot)).or_insert((NONE, NONE));
            entry.0 = ready_round;
            if mode == AccessMode::Write {
                entry.1 = ready_round;
            }
        }
    }

    (round_for_transaction, stats)
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

#[cfg(test)]
mod tests {
    use super::{MaterializedRounds, ScheduleStats, ScheduledTransaction, schedule_rounds};
    use crate::processor::access::AccessSet;
    use commonware_codec::{DecodeExt, FixedSize};
    use constantinople_primitives::{Access, AccessList, AccessMode, Address, Slot};

    #[test]
    fn schedule_rounds_groups_conflicts_and_tracks_stats() {
        let shared_a = address(0xa0);
        let shared_b = address(0xb0);
        let slot_a = slot(0x0a);
        let slot_b = slot(0x0b);
        let scheduled = vec![
            scheduled_transaction(
                1,
                vec![Access::Storage(shared_a, slot_a, AccessMode::Write)],
            ),
            scheduled_transaction(2, vec![Access::Storage(shared_b, slot_b, AccessMode::Read)]),
            scheduled_transaction(3, vec![Access::Storage(shared_a, slot_a, AccessMode::Read)]),
            scheduled_transaction(
                4,
                vec![Access::Storage(shared_b, slot_b, AccessMode::Write)],
            ),
        ];

        let (round_for_transaction, stats) = schedule_rounds(&scheduled);

        assert_eq!(round_for_transaction, vec![0, 0, 1, 1]);
        assert_eq!(
            stats,
            ScheduleStats {
                total_rounds: 2,
                singleton_rounds: 0,
                max_width: 2,
                parallel_transactions: 4,
            }
        );
    }

    #[test]
    fn materialized_rounds_preserve_transaction_order() {
        let rounds = MaterializedRounds::new(&[2, 0, 2, 1, 0], 3);

        assert_eq!(rounds.round(0), &[1, 4]);
        assert_eq!(rounds.round(1), &[3]);
        assert_eq!(rounds.round(2), &[0, 2]);
    }

    fn scheduled_transaction(seed: u8, access_list: AccessList) -> ScheduledTransaction {
        ScheduledTransaction {
            access: AccessSet::new(
                address(seed),
                address(seed.wrapping_add(100)),
                AccessMode::Read,
                &access_list,
            ),
        }
    }

    fn address(byte: u8) -> Address {
        Address::decode(&[byte; Address::SIZE][..]).expect("address bytes should decode")
    }

    fn slot(byte: u8) -> Slot {
        Slot::from([byte; Slot::SIZE])
    }
}
