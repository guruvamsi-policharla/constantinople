//! Transaction execution engine.
//!
//! The [`Processor`] struct orchestrates transaction execution: it validates
//! transactions, manages the prelude nonce bump, dispatches to precompiles or
//! plain transfers, and enforces exact access-list matching after each
//! successful execution.
//!
//! The public API has two stages:
//!
//! 1. [`Processor::validate`] — splits a batch into statically valid and
//!    invalid transactions, tracking nonce state across the batch.
//! 2. [`Processor::process`] — executes the validated transactions with
//!    greedy dependency scheduling.

use super::{
    Precompiles,
    access::{AccessListBuilder, AccessSet},
    frame::{Frame, FrameError},
    schedule::{self, TransactionExecution},
    state::{FrameDiff, State},
};
use bytes::Bytes;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use constantinople_primitives::{
    AccessList, AccessMode, Address, Receipt, ReceiptStatus, Slot, StateValue, VerifiedTransaction,
};
use std::{
    collections::{BTreeMap, HashMap},
    panic::{AssertUnwindSafe, catch_unwind},
};

const MAX_CALL_DEPTH: u16 = 64;

/// The final result of processing a set of transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessorOutput<D: Digest> {
    /// Receipts in transaction order.
    pub receipts: Vec<Receipt<D>>,
    /// Persistent database writes produced by the processed transactions.
    pub changeset: BTreeMap<Slot, StateValue>,
    /// Optionally built access lists for the processed transactions.
    ///
    /// This field is `None` unless access-list building is enabled on the
    /// processor via [`Processor::with_access_list_builder`]. When enabled,
    /// successful transactions produce `Some(access_list)` and reverted
    /// transactions produce `None`.
    pub access_lists: Option<Vec<Option<AccessList>>>,
}

/// The result of [`Processor::validate`].
#[derive(Debug)]
pub struct ValidationResult<PK: PublicKey, H: Hasher> {
    /// Transactions that passed static validation.
    pub valid: Vec<VerifiedTransaction<PK, H>>,
    /// Transactions that failed static validation.
    pub invalid: Vec<VerifiedTransaction<PK, H>>,
}

/// Executes transactions against the in-memory processor state.
///
/// The processor uses the declared transaction access lists to build greedy
/// dependency rounds. Each round executes against the same committed state
/// snapshot, and the resulting receipts and diffs are merged back into the
/// processor state in the original transaction order.
pub struct Processor<'a, S, P>
where
    S: Strategy,
    P: Precompiles,
{
    strategy: &'a S,
    precompiles: &'a P,
    access_list_builder: bool,
}

impl<S, P> core::fmt::Debug for Processor<'_, S, P>
where
    S: Strategy,
    P: Precompiles,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Processor").finish_non_exhaustive()
    }
}

impl<'a, S, P> Processor<'a, S, P>
where
    S: Strategy,
    P: Precompiles + Sync,
{
    /// Creates a processor with the given execution strategy and precompile
    /// registry.
    pub const fn new(strategy: &'a S, precompiles: &'a P) -> Self {
        Self {
            strategy,
            precompiles,
            access_list_builder: false,
        }
    }

    /// Enables access-list collection during execution.
    ///
    /// Successful transactions will return the observed access list in
    /// [`ProcessorOutput::access_lists`].
    pub const fn with_access_list_builder(mut self) -> Self {
        self.access_list_builder = true;
        self
    }

    /// Splits `transactions` into statically valid and invalid sets.
    ///
    /// Each transaction is checked against the visible state for correct
    /// nonce, sufficient balance, and valid precompile target. A pending
    /// nonce map tracks nonce increments across the batch so sequential
    /// transactions from the same sender validate correctly without
    /// mutating the underlying state.
    pub fn validate<H, PK>(
        &self,
        state: &State,
        transactions: Vec<VerifiedTransaction<PK, H>>,
    ) -> ValidationResult<PK, H>
    where
        H: Hasher,
        PK: PublicKey,
    {
        let mut pending_nonces = HashMap::with_capacity(transactions.len());
        let mut valid = Vec::with_capacity(transactions.len());
        let mut invalid = Vec::new();

        for transaction in transactions {
            let sender = transaction.signer();
            let tx = transaction.value();
            let base = state.account(sender);
            let nonce = pending_nonces.get(&sender).copied().unwrap_or(base.nonce);

            let is_valid = nonce == tx.nonce
                && nonce != u64::MAX
                && base.balance >= tx.value
                && (self.precompiles.is_precompile(tx.to) || tx.input.is_empty());

            if !is_valid {
                invalid.push(transaction);
                continue;
            }

            pending_nonces.insert(sender, nonce + 1);
            valid.push(transaction);
        }

        ValidationResult { valid, invalid }
    }

    /// Processes pre-validated transactions against `state` and returns
    /// receipts plus the final state diff.
    ///
    /// Callers should pass only transactions that have been through
    /// [`Processor::validate`]. The processor greedily partitions them into
    /// dependency rounds and executes through the configured [`Strategy`].
    pub fn process<H, PK>(
        &self,
        state: State,
        transactions: &[VerifiedTransaction<PK, H>],
    ) -> ProcessorOutput<H::Digest>
    where
        H: Hasher,
        PK: PublicKey,
    {
        let prepared = schedule::prepare(state, transactions, transaction_access_set::<H, PK>);
        schedule::execute(
            self.strategy,
            &prepared,
            transactions,
            self.access_list_builder,
            |state, transaction, access, return_access_list| {
                self.execute_validated_transaction(state, transaction, access, return_access_list)
            },
        )
    }

    /// Executes a single transaction against `state`.
    fn execute_validated_transaction<H, PK>(
        &self,
        state: &State,
        transaction: &VerifiedTransaction<PK, H>,
        access: &AccessSet,
        return_access_list: bool,
    ) -> TransactionExecution<H::Digest>
    where
        H: Hasher,
        PK: PublicKey,
    {
        let sender = transaction.signer();
        let builder = AccessListBuilder::default();
        let mut prelude = Frame::new(sender, state, access, builder, 0, 0, Bytes::new());
        if prelude.bump_sender_nonce().is_err() {
            return TransactionExecution {
                receipt: Receipt::revert(*transaction.message_digest(), Bytes::new()),
                diff: FrameDiff::default(),
                access_list: None,
            };
        }

        let tx = transaction.value();
        let mut root = prelude.child_with_depth(sender, 0, 0, Bytes::new());
        let result = if self.precompiles.is_precompile(tx.to) {
            root.call(self, tx.to, tx.value, tx.input.clone())
        } else {
            root.transfer(tx.to, tx.value).map(|()| Bytes::new())
        };

        match result {
            Ok(return_data) => {
                let (diff, builder) = root.into_parts();
                prelude.merge(diff, builder);
                let (diff, builder) = prelude.into_parts();

                if !access.is_exact_match(&builder) {
                    return TransactionExecution {
                        receipt: Receipt::revert(*transaction.message_digest(), Bytes::new()),
                        diff,
                        access_list: None,
                    };
                }

                TransactionExecution {
                    receipt: Receipt::new(
                        *transaction.message_digest(),
                        ReceiptStatus::Success,
                        return_data,
                    ),
                    diff,
                    access_list: return_access_list.then(|| builder.into_access_list()),
                }
            }
            Err(err) => {
                let payload = match err {
                    FrameError::Revert(p) => p,
                    _ => Bytes::new(),
                };
                let (diff, _) = prelude.into_parts();
                TransactionExecution {
                    receipt: Receipt::revert(*transaction.message_digest(), payload),
                    diff,
                    access_list: None,
                }
            }
        }
    }

    /// Executes a nested precompile call from `frame`.
    ///
    /// Successful child calls merge their diffs into the parent frame.
    /// Reverted or halted child calls discard their state diff but still
    /// propagate any observed accesses.
    pub(super) fn call_precompile(
        &self,
        frame: &mut Frame<'_>,
        to: Address,
        value: u64,
        input: Bytes,
    ) -> Result<Bytes, FrameError> {
        if frame.depth() == MAX_CALL_DEPTH {
            return Err(FrameError::CallDepthExceeded);
        }

        if !self.precompiles.is_precompile(to) {
            return Err(FrameError::InvalidTransactionTarget);
        }

        let mut child = frame.branch(to, value, input);
        child.transfer_between(frame.owner(), to, value)?;
        let result = catch_unwind(AssertUnwindSafe(|| {
            self.precompiles.execute(to, &mut child, self)
        }))
        .unwrap_or(Err(FrameError::PrecompilePanic));

        let (diff, access_list_builder) = child.into_parts();
        if result.is_ok() {
            frame.merge(diff, access_list_builder);
        } else {
            frame.merge_access_list_builder(access_list_builder);
        }

        result
    }
}

/// Builds the effective declared access set for `transaction`.
pub(super) fn transaction_access_set<H, PK>(transaction: &VerifiedTransaction<PK, H>) -> AccessSet
where
    H: Hasher,
    PK: PublicKey,
{
    let sender = transaction.signer();
    let tx = transaction.value();
    let recipient_mode = if tx.value > 0 {
        AccessMode::Write
    } else {
        AccessMode::Read
    };
    AccessSet::new(sender, tx.to, recipient_mode, &tx.access_list)
}
