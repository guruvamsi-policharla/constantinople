//! Transfer execution for the Constantinople account model.
//!
//! This module is the state-agnostic account engine used by consensus execution,
//! tests, and benchmarks. It decides which account keys must be loaded, builds
//! deterministic account effects from the transfer list, and applies those
//! effects to loaded block-start account state. DB-backed loading is handled by
//! `consensus::execution`; the in-memory entry points in this module read from
//! [`State`].
//!
//! Execution first builds an account-touch plan. The plan counts non-self
//! sender/recipient touches across the block. Transfers whose touched accounts
//! are unique stay on the discrete lane, where each loaded sender or recipient
//! produces one final write. Transfers that touch any contended account move to
//! the general lane.
//!
//! The general lane is account-owned. It aggregates every contended transfer
//! into one effect per account: sent nonces, non-self debit total,
//! self-transfer affordability floor, and recipient credit total. Account state
//! is loaded after these effects are known, then each loaded account is checked
//! and written once. A sender spends only the balance it held at the start of the
//! block, never funds credited to it within the same block.
//!
//! Verification is all or nothing: if any transfer fails its nonce or balance
//! check or overflows its recipient, the whole batch is rejected. Because a
//! successful batch has no failed debits, every loaded account effect produces
//! one final write. Proposal construction instead uses [`SelectiveExecutor`],
//! which applies the same per-account rules per transfer and drops what cannot
//! apply.

use ahash::AHashMap;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_privacy::payments::Backend;
use constantinople_primitives::{
    AccountKey, Nonce, Payload, PrivateAccount, PrivatePaymentBackend, SignedTransaction,
    StateAccount, StatePrivatePaymentBackend, to_state_burn_proof, to_state_commitment,
    to_state_fund_proof, to_state_transfer_proof,
};

/// Fully loaded base account state for one in-memory execution batch.
pub type State = AHashMap<AccountKey, StateAccount>;

/// Deterministic account writes produced by execution.
pub type Changeset = Vec<(AccountKey, StateAccount)>;

/// The state-side private payment backend executing and verifying proofs.
type ExecutionBackend = StatePrivatePaymentBackend;

type ExecutionCommitment = <ExecutionBackend as Backend>::Commitment;
type FundVerification = (
    u64,
    <ExecutionBackend as Backend>::Commitment,
    <ExecutionBackend as Backend>::FundProof,
);
type TransferVerification = (
    <ExecutionBackend as Backend>::Commitment,
    <ExecutionBackend as Backend>::Commitment,
    <ExecutionBackend as Backend>::TransferProof,
);
type BurnVerification = (
    <ExecutionBackend as Backend>::Commitment,
    u64,
    <ExecutionBackend as Backend>::BurnProof,
);

/// Deferred private-proof verification claims collected during execution.
///
/// Applying a private operation mutates commitment state immediately and
/// queues its proof here; the whole batch is verified once, after
/// speculation, via [`Self::verify_with_strategy`].
#[derive(Debug, Default)]
pub struct PrivateVerifications {
    pub(crate) funds: Vec<FundVerification>,
    pub(crate) transfers: Vec<TransferVerification>,
    pub(crate) burns: Vec<BurnVerification>,
}

impl PrivateVerifications {
    pub const fn new() -> Self {
        Self {
            funds: Vec::new(),
            transfers: Vec::new(),
            burns: Vec::new(),
        }
    }

    pub const fn is_empty(&self) -> bool {
        self.funds.is_empty() && self.transfers.is_empty() && self.burns.is_empty()
    }

    pub const fn len(&self) -> usize {
        self.funds.len() + self.transfers.len() + self.burns.len()
    }

    /// Batch-verifies every collected proof on the caller's strategy.
    pub fn verify_with_strategy(&self, strategy: &impl Strategy) -> bool {
        <ExecutionBackend as Backend>::batch_verify_with_strategy(
            strategy,
            <ExecutionBackend as PrivatePaymentBackend>::params(),
            &self.funds,
            &self.transfers,
            &self.burns,
            &mut rand::rng(),
        )
    }
}

fn verify_fund(
    value: u64,
    commitment: &<ExecutionBackend as Backend>::Commitment,
    proof: &<ExecutionBackend as Backend>::FundProof,
) -> bool {
    <ExecutionBackend as Backend>::batch_verify(
        <ExecutionBackend as PrivatePaymentBackend>::params(),
        &[(value, commitment.clone(), *proof)],
        &[],
        &[],
        &mut rand::rng(),
    )
}

fn verify_transfer(
    current: &ExecutionCommitment,
    amount: &ExecutionCommitment,
    proof: &<ExecutionBackend as Backend>::TransferProof,
) -> bool {
    <ExecutionBackend as Backend>::batch_verify(
        <ExecutionBackend as PrivatePaymentBackend>::params(),
        &[],
        &[(current.clone(), amount.clone(), *proof)],
        &[],
        &mut rand::rng(),
    )
}

fn verify_burn(
    current: &ExecutionCommitment,
    value: u64,
    proof: &<ExecutionBackend as Backend>::BurnProof,
) -> bool {
    <ExecutionBackend as Backend>::batch_verify(
        <ExecutionBackend as PrivatePaymentBackend>::params(),
        &[],
        &[],
        &[(current.clone(), value, *proof)],
        &mut rand::rng(),
    )
}

/// Account execution plan for one batch.
pub(crate) struct ExecutionPlan {
    /// Transfers whose non-self account touches are unique in the block.
    pub(crate) discrete: DiscreteWorkload,
    /// Account-owned effects for the remaining transfers.
    pub(crate) general: GeneralWorkload,
}

/// Transfers that can produce direct sender and recipient writes.
pub(crate) struct DiscreteWorkload {
    /// Indices into the original transfer list, in block order.
    pub(crate) transfers: Vec<usize>,
    /// Sender account keys, in transfer order.
    pub(crate) sender_keys: Vec<AccountKey>,
    /// Non-self recipient account keys, in transfer order.
    pub(crate) recipient_keys: Vec<AccountKey>,
}

/// Account-owned effects for transfers that touch contended accounts.
pub(crate) struct GeneralWorkload {
    /// Account keys to load, deduplicated exactly.
    account_keys: Vec<AccountKey>,
    /// Effects to apply to each loaded account.
    effects: Vec<AccountEffect>,
}

impl GeneralWorkload {
    /// Whether the general lane has no account effects.
    pub(crate) const fn is_empty(&self) -> bool {
        self.account_keys.is_empty()
    }

    /// Account keys to load for the general lane.
    pub(crate) fn account_keys(&self) -> &[AccountKey] {
        &self.account_keys
    }
}

/// Operation data used by the executor, with proofs converted to the
/// state-side backend representation.
#[derive(Debug, Clone)]
pub struct PreparedOperation {
    /// Sender account key.
    pub sender: AccountKey,
    /// Sender key prefix used for routing and transient indexing.
    pub sender_prefix: u64,
    /// Sender nonce required by the transaction.
    pub nonce: u64,
    /// The prepared action.
    pub payload: PreparedPayload,
}

/// Prepared payload with decoded account keys and state-side proof types.
///
/// Proof-bearing variants dwarf `PrivateRollover`, but this enum sits on the
/// execution hot path where boxing would cost an allocation per operation.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum PreparedPayload {
    /// Public transfer.
    PublicTransfer {
        recipient: AccountKey,
        recipient_prefix: u64,
        value: u64,
    },
    /// Private fund.
    PrivateFund {
        value: u64,
        commitment: <ExecutionBackend as Backend>::Commitment,
        proof: <ExecutionBackend as Backend>::FundProof,
    },
    /// Private transfer.
    PrivateTransfer {
        recipient: AccountKey,
        recipient_prefix: u64,
        amount: <ExecutionBackend as Backend>::Commitment,
        proof: <ExecutionBackend as Backend>::TransferProof,
    },
    /// Private burn.
    PrivateBurn {
        value: u64,
        proof: <ExecutionBackend as Backend>::BurnProof,
    },
    /// Explicit private rollover.
    PrivateRollover,
}

impl PreparedOperation {
    /// Builds a public-transfer operation; used by tests and benchmarks.
    pub fn public_transfer(
        sender: AccountKey,
        recipient: AccountKey,
        value: u64,
        nonce: u64,
    ) -> Self {
        Self {
            sender,
            sender_prefix: sender.prefix(),
            nonce,
            payload: PreparedPayload::PublicTransfer {
                recipient,
                recipient_prefix: recipient.prefix(),
                value,
            },
        }
    }

    /// The recipient's `(prefix, key)` when the payload credits another
    /// account (public and private transfers only).
    pub const fn recipient_entry(&self) -> Option<(u64, &AccountKey)> {
        match &self.payload {
            PreparedPayload::PublicTransfer {
                recipient,
                recipient_prefix,
                ..
            }
            | PreparedPayload::PrivateTransfer {
                recipient,
                recipient_prefix,
                ..
            } => Some((*recipient_prefix, recipient)),
            PreparedPayload::PrivateFund { .. }
            | PreparedPayload::PrivateBurn { .. }
            | PreparedPayload::PrivateRollover => None,
        }
    }

    /// Whether the payload is a transfer to a distinct recipient account.
    fn non_self_recipient(&self) -> Option<(u64, &AccountKey)> {
        self.recipient_entry()
            .filter(|(_, recipient)| **recipient != self.sender)
    }

    /// Whether applying this operation queues a proof for batch verification.
    pub(crate) const fn has_proof(&self) -> bool {
        matches!(
            &self.payload,
            PreparedPayload::PrivateFund { .. }
                | PreparedPayload::PrivateTransfer { .. }
                | PreparedPayload::PrivateBurn { .. }
        )
    }
}

/// Prepares one transaction for account execution.
// The zkpari fund proof is the unit type, which trips `unit_arg` on the
// backend-generic conversion call.
#[allow(clippy::unit_arg)]
pub fn prepare_operation<H>(transaction: &SignedTransaction<H>) -> Option<PreparedOperation>
where
    H: Hasher,
{
    let tx = transaction.value();
    let sender = AccountKey::from_public_key(tx.sender_lazy().get()?);
    let payload = match &tx.payload {
        Payload::PublicTransfer { to, value } => PreparedPayload::PublicTransfer {
            recipient: *to,
            recipient_prefix: to.prefix(),
            value: value.get(),
        },
        Payload::PrivateFund {
            value,
            commitment,
            proof,
        } => PreparedPayload::PrivateFund {
            value: value.get(),
            commitment: to_state_commitment(commitment.clone()),
            proof: to_state_fund_proof(*proof),
        },
        Payload::PrivateTransfer { to, amount, proof } => PreparedPayload::PrivateTransfer {
            recipient: *to,
            recipient_prefix: to.prefix(),
            amount: to_state_commitment(amount.clone()),
            proof: to_state_transfer_proof(*proof),
        },
        Payload::PrivateBurn { value, proof } => PreparedPayload::PrivateBurn {
            value: value.get(),
            proof: to_state_burn_proof(*proof),
        },
        Payload::PrivateRollover => PreparedPayload::PrivateRollover,
    };
    Some(PreparedOperation {
        sender,
        sender_prefix: sender.prefix(),
        nonce: tx.nonce,
        payload,
    })
}

/// Which side of a private operation an account replay entry covers.
#[derive(Debug, Clone, Copy)]
enum PrivateRole {
    Sender,
    Recipient,
}

#[derive(Default)]
pub(crate) struct AccountEffect {
    /// Operation indices sent by this account, in block order.
    sent: Vec<u32>,
    /// Total non-self debit to subtract from the account.
    debit: u64,
    /// Largest self-transfer value that must be affordable.
    self_transfer_floor: u64,
    /// Total credit to add to the account after debits.
    credit: u64,
    /// Private commitment operations touching this account, in block order.
    ///
    /// Commitment mutations do not commute (burn zeroes `current`, rollover
    /// folds `pending` into it), so they replay per account in block-index
    /// order instead of aggregating. An account's `current` depends only on
    /// its own sent operations, and its `pending` on order-interleaved
    /// deposits, so per-account replay reproduces global block order exactly.
    private_ops: Vec<(u32, PrivateRole)>,
}

struct AccountIndexTable {
    slots: Vec<AccountIndexSlot>,
    mask: usize,
    len: usize,
}

#[derive(Clone, Copy)]
struct AccountIndexSlot {
    key: Option<AccountKey>,
    index: u32,
}

impl AccountIndexTable {
    fn with_capacity(capacity: usize) -> Self {
        let slots = capacity.saturating_mul(2).next_power_of_two().max(16);
        Self {
            slots: vec![
                AccountIndexSlot {
                    key: None,
                    index: 0
                };
                slots
            ],
            mask: slots - 1,
            len: 0,
        }
    }

    /// Looks up a key without inserting.
    fn get(&self, prefix: u64, key: &AccountKey) -> Option<u32> {
        let mut slot = (prefix as usize) & self.mask;
        loop {
            let entry = self.slots[slot];
            entry.key?;
            if entry.key == Some(*key) {
                return Some(entry.index);
            }
            slot = (slot + 1) & self.mask;
        }
    }

    fn get_or_insert(&mut self, prefix: u64, key: AccountKey, index: u32) -> (u32, bool) {
        if self.len.saturating_mul(2) >= self.slots.len() {
            self.grow();
        }

        let mut slot = (prefix as usize) & self.mask;
        loop {
            let entry = self.slots[slot];
            if entry.key.is_none() {
                self.slots[slot] = AccountIndexSlot {
                    key: Some(key),
                    index,
                };
                self.len += 1;
                return (index, true);
            }
            if entry.key == Some(key) {
                return (entry.index, false);
            }
            slot = (slot + 1) & self.mask;
        }
    }

    fn grow(&mut self) {
        let new_slots = self.slots.len() * 2;
        let old_slots = core::mem::replace(
            &mut self.slots,
            vec![
                AccountIndexSlot {
                    key: None,
                    index: 0
                };
                new_slots
            ],
        );
        self.mask = new_slots - 1;
        self.len = 0;

        for slot in old_slots {
            if let Some(key) = slot.key {
                self.insert_unique(key, slot.index);
            }
        }
    }

    fn insert_unique(&mut self, key: AccountKey, index: u32) {
        let mut slot = (key.prefix() as usize) & self.mask;
        while self.slots[slot].key.is_some() {
            slot = (slot + 1) & self.mask;
        }
        self.slots[slot] = AccountIndexSlot {
            key: Some(key),
            index,
        };
        self.len += 1;
    }
}

/// Builder for the general lane's dense account-effect table.
///
/// Account keys are copied from the prepared transfer slice and deduplicated by
/// value. The prefix only seeds the probe position; equality still compares the
/// full account key, so equal keys from different transfer slots share one
/// effect.
struct GeneralBuilder {
    account_keys: Vec<AccountKey>,
    effects: Vec<AccountEffect>,
    indices: AccountIndexTable,
}

impl GeneralBuilder {
    fn new(transfers: usize) -> Self {
        let expected_accounts = transfers.saturating_mul(2).max(16);
        Self {
            account_keys: Vec::with_capacity(expected_accounts),
            effects: Vec::with_capacity(expected_accounts),
            indices: AccountIndexTable::with_capacity(expected_accounts),
        }
    }

    fn account(&mut self, prefix: u64, key: &AccountKey) -> &mut AccountEffect {
        let (account, inserted) =
            self.indices
                .get_or_insert(prefix, *key, self.account_keys.len() as u32);
        if inserted {
            self.account_keys.push(*key);
            self.effects.push(AccountEffect::default());
        }
        &mut self.effects[account as usize]
    }

    fn into_workload(self) -> GeneralWorkload {
        GeneralWorkload {
            account_keys: self.account_keys,
            effects: self.effects,
        }
    }
}

/// Builds the execution plan used by both DB-backed and in-memory execution.
pub(crate) fn execution_plan(operations: &[PreparedOperation]) -> Option<ExecutionPlan> {
    // Count account touches by each key's precomputed 64-bit prefix instead
    // of rehashing full 32-byte keys. A prefix collision between distinct
    // keys only merges their counts, which can only demote operations to the
    // general lane; that lane deduplicates by full key and applies the same
    // per-account checks as the discrete lane, so routing stays
    // consensus-neutral.
    let mut touches: AHashMap<u64, u32> =
        AHashMap::with_capacity(operations.len().saturating_mul(2));
    for operation in operations {
        *touches.entry(operation.sender_prefix).or_default() += 1;
        if let Some((recipient_prefix, _)) = operation.non_self_recipient() {
            *touches.entry(recipient_prefix).or_default() += 1;
        }
    }

    let mut general = None;
    let mut discrete = DiscreteWorkload {
        transfers: Vec::with_capacity(operations.len()),
        sender_keys: Vec::with_capacity(operations.len()),
        recipient_keys: Vec::with_capacity(operations.len()),
    };

    for (index, operation) in operations.iter().enumerate() {
        let sender_is_unique = touches
            .get(&operation.sender_prefix)
            .copied()
            .unwrap_or_default()
            == 1;
        let recipient = operation.non_self_recipient();
        let recipient_is_unique = recipient.is_none_or(|(recipient_prefix, _)| {
            touches.get(&recipient_prefix).copied().unwrap_or_default() == 1
        });
        if sender_is_unique && recipient_is_unique {
            discrete.transfers.push(index);
            discrete.sender_keys.push(operation.sender);
            if let Some((_, recipient)) = recipient {
                discrete.recipient_keys.push(*recipient);
            }
            continue;
        }

        let general = general.get_or_insert_with(|| GeneralBuilder::new(operations.len()));
        let sender = general.account(operation.sender_prefix, &operation.sender);
        sender.sent.push(index as u32);
        match &operation.payload {
            PreparedPayload::PublicTransfer {
                recipient,
                recipient_prefix,
                value,
            } => {
                if operation.sender == *recipient {
                    sender.self_transfer_floor = sender.self_transfer_floor.max(*value);
                } else {
                    sender.debit = sender.debit.checked_add(*value)?;
                    let recipient = general.account(*recipient_prefix, recipient);
                    recipient.credit = recipient.credit.checked_add(*value)?;
                }
            }
            PreparedPayload::PrivateFund { value, .. } => {
                sender.debit = sender.debit.checked_add(*value)?;
                sender.private_ops.push((index as u32, PrivateRole::Sender));
            }
            PreparedPayload::PrivateTransfer {
                recipient,
                recipient_prefix,
                ..
            } => {
                sender.private_ops.push((index as u32, PrivateRole::Sender));
                let recipient = general.account(*recipient_prefix, recipient);
                recipient
                    .private_ops
                    .push((index as u32, PrivateRole::Recipient));
            }
            PreparedPayload::PrivateBurn { value, .. } => {
                sender.credit = sender.credit.checked_add(*value)?;
                sender.private_ops.push((index as u32, PrivateRole::Sender));
            }
            PreparedPayload::PrivateRollover => {
                sender.private_ops.push((index as u32, PrivateRole::Sender));
            }
        }
    }

    Some(ExecutionPlan {
        discrete,
        general: general.map_or_else(
            || GeneralWorkload {
                account_keys: Vec::new(),
                effects: Vec::new(),
            },
            GeneralBuilder::into_workload,
        ),
    })
}

/// Applies one credit to an account.
pub(crate) fn apply_credit(account: &mut StateAccount, value: u64) -> Option<()> {
    account.balance = account.balance.checked_add(value)?;
    Some(())
}

/// Applies one discrete-lane sender operation to its block-start account.
///
/// Public balance checks run against the block-start value (nonce is the
/// final, mutating gate), commitment mutations apply immediately, and proofs
/// queue on `verifications` for post-speculation batch verification.
pub(crate) fn apply_discrete_sender(
    account: &mut StateAccount,
    operation: &PreparedOperation,
    verifications: &mut PrivateVerifications,
) -> Option<()> {
    match &operation.payload {
        PreparedPayload::PublicTransfer {
            recipient, value, ..
        } => {
            if account.balance < *value || !account.nonce.consume(operation.nonce) {
                return None;
            }
            if operation.sender != *recipient {
                account.balance -= *value;
            }
        }
        PreparedPayload::PrivateFund {
            value,
            commitment,
            proof,
        } => {
            if account.balance < *value || !account.nonce.consume(operation.nonce) {
                return None;
            }
            account.balance -= *value;
            verifications
                .funds
                .push((*value, commitment.clone(), *proof));
            account.private.deposit(commitment);
        }
        PreparedPayload::PrivateTransfer {
            recipient,
            amount,
            proof,
            ..
        } => {
            if !account.nonce.consume(operation.nonce) {
                return None;
            }
            verifications
                .transfers
                .push((account.private.current.clone(), amount.clone(), *proof));
            account.private.withdraw(amount);
            if operation.sender == *recipient {
                account.private.deposit(amount);
            }
        }
        PreparedPayload::PrivateBurn { value, proof } => {
            let balance = account.balance.checked_add(*value)?;
            if !account.nonce.consume(operation.nonce) {
                return None;
            }
            verifications
                .burns
                .push((account.private.current.clone(), *value, *proof));
            account.balance = balance;
            account.private.burn();
        }
        PreparedPayload::PrivateRollover => {
            if !account.nonce.consume(operation.nonce) {
                return None;
            }
            account.private.rollover();
        }
    }
    Some(())
}

/// Applies one discrete-lane recipient credit to its block-start account.
///
/// Only transfer payloads reach here (recipient keys are built from exactly
/// the non-self transfer operations).
pub(crate) fn apply_discrete_recipient(
    account: &mut StateAccount,
    operation: &PreparedOperation,
) -> Option<()> {
    match &operation.payload {
        PreparedPayload::PublicTransfer { value, .. } => apply_credit(account, *value),
        PreparedPayload::PrivateTransfer { amount, .. } => {
            account.private.deposit(amount);
            Some(())
        }
        PreparedPayload::PrivateFund { .. }
        | PreparedPayload::PrivateBurn { .. }
        | PreparedPayload::PrivateRollover => {
            unreachable!("recipient keys are built from transfer operations only")
        }
    }
}

/// Applies account-owned effects to loaded accounts.
///
/// Returns one final account per workload entry, in `account_keys` order.
pub(crate) fn apply_general_accounts(
    values: &[Option<StateAccount>],
    workload: &GeneralWorkload,
    operations: &[PreparedOperation],
    verifications: &mut PrivateVerifications,
) -> Option<Vec<StateAccount>> {
    assert_eq!(values.len(), workload.account_keys.len());
    assert_eq!(values.len(), workload.effects.len());

    let mut writes = Vec::with_capacity(workload.effects.len());
    for (effect, value) in workload.effects.iter().zip(values) {
        let mut account = value.clone().unwrap_or_default();
        for index in &effect.sent {
            let operation = &operations[*index as usize];
            if !account.nonce.consume(operation.nonce) {
                return None;
            }
        }
        if account.balance < effect.self_transfer_floor || account.balance < effect.debit {
            return None;
        }
        account.balance -= effect.debit;
        apply_credit(&mut account, effect.credit)?;

        // Replay this account's commitment operations in block-index order;
        // see the `private_ops` field docs for why replay (not aggregation)
        // is required and why per-account order suffices.
        for (index, role) in &effect.private_ops {
            let operation = &operations[*index as usize];
            match (&operation.payload, role) {
                (
                    PreparedPayload::PrivateFund {
                        value,
                        commitment,
                        proof,
                    },
                    PrivateRole::Sender,
                ) => {
                    verifications
                        .funds
                        .push((*value, commitment.clone(), *proof));
                    account.private.deposit(commitment);
                }
                (PreparedPayload::PrivateTransfer { amount, proof, .. }, PrivateRole::Sender) => {
                    verifications.transfers.push((
                        account.private.current.clone(),
                        amount.clone(),
                        *proof,
                    ));
                    account.private.withdraw(amount);
                }
                (PreparedPayload::PrivateTransfer { amount, .. }, PrivateRole::Recipient) => {
                    account.private.deposit(amount);
                }
                (PreparedPayload::PrivateBurn { value, proof }, PrivateRole::Sender) => {
                    verifications
                        .burns
                        .push((account.private.current.clone(), *value, *proof));
                    account.private.burn();
                }
                (PreparedPayload::PrivateRollover, PrivateRole::Sender) => {
                    account.private.rollover();
                }
                _ => unreachable!("private replay entries match their payload variants"),
            }
        }
        writes.push(account);
    }
    Some(writes)
}

fn execute_discrete(
    state: &State,
    plan: &DiscreteWorkload,
    operations: &[PreparedOperation],
    verifications: &mut PrivateVerifications,
) -> Option<Changeset> {
    assert_eq!(plan.sender_keys.len(), plan.transfers.len());
    let mut changeset =
        Changeset::with_capacity(plan.sender_keys.len() + plan.recipient_keys.len());
    for (sender_key, operation_index) in plan.sender_keys.iter().zip(&plan.transfers) {
        let operation = &operations[*operation_index];
        let mut sender = state.get(&operation.sender).cloned().unwrap_or_default();
        apply_discrete_sender(&mut sender, operation, verifications)?;
        changeset.push((*sender_key, sender));
    }

    for operation_index in &plan.transfers {
        let operation = &operations[*operation_index];
        let Some((_, recipient_key)) = operation.non_self_recipient() else {
            continue;
        };
        let mut recipient = state.get(recipient_key).cloned().unwrap_or_default();
        apply_discrete_recipient(&mut recipient, operation)?;
        changeset.push((*recipient_key, recipient));
    }

    Some(changeset)
}

/// Incremental best-effort executor for proposals.
///
/// Verification is all or nothing: a block containing an inapplicable
/// transfer is invalid. A proposer, however, chooses the block body, so it
/// applies candidate transfers in block order against block-start account
/// state and simply drops any transfer that cannot apply (stale nonce,
/// insufficient start balance, credit overflow) — typically a transaction
/// that already landed in another block on this chain. Candidates can be fed
/// in multiple rounds (the initial selection, then mempool refills), with
/// account state loaded incrementally per round.
///
/// The per-account bookkeeping mirrors `apply_general_accounts` exactly:
/// debits and self-transfer floors are checked against the block-start
/// balance only (credits never fund debits in the same block), nonces are
/// consumed in block order, and the final value is
/// `start - debits + credits`. Applied transfers therefore re-execute
/// cleanly, with identical account writes, under the all-or-nothing
/// verification path.
pub struct SelectiveExecutor {
    /// Prefix-seeded open-addressing map from account key to dense index.
    indices: AccountIndexTable,
    /// Touched account keys, in first-appearance (= staged read) order.
    keys: Vec<AccountKey>,
    /// Working state per key; the dense index doubles as the staged read
    /// index because keys are staged in exactly this order.
    accounts: Vec<WorkingAccount>,
}

/// Opaque snapshot of a [`SelectiveExecutor`]'s working account state.
pub struct SelectorCheckpoint(Vec<WorkingAccount>);

#[derive(Clone)]
struct WorkingAccount {
    /// Block-start balance.
    start_balance: u64,
    /// Nonce state after the transfers applied so far.
    nonce: Nonce,
    /// Total non-self debits applied so far.
    debit: u64,
    /// Total credits applied so far.
    credit: u64,
    /// Whether any applied transfer touched this account.
    touched: bool,
    /// Private-payment commitment state carried through from block start.
    private: PrivateAccount<StatePrivatePaymentBackend>,
}

impl Default for SelectiveExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl SelectiveExecutor {
    pub fn new() -> Self {
        Self {
            indices: AccountIndexTable::with_capacity(16),
            keys: Vec::new(),
            accounts: Vec::new(),
        }
    }

    /// Records the accounts a candidate round touches, returning the keys not
    /// seen in any earlier round, in the order their block-start values must
    /// be staged (their dense indices continue the staged read space).
    pub fn begin_round(&mut self, operations: &[PreparedOperation]) -> Vec<AccountKey> {
        let before = self.keys.len();
        for operation in operations {
            let recipient = operation
                .recipient_entry()
                .map(|(prefix, key)| (prefix, *key));
            for (prefix, key) in
                core::iter::once((operation.sender_prefix, operation.sender)).chain(recipient)
            {
                let (_, inserted) = self
                    .indices
                    .get_or_insert(prefix, key, self.keys.len() as u32);
                if inserted {
                    self.keys.push(key);
                }
            }
        }
        self.keys[before..].to_vec()
    }

    /// Snapshots working account state before a trial application round.
    pub fn checkpoint(&self) -> SelectorCheckpoint {
        SelectorCheckpoint(self.accounts.clone())
    }

    /// Rewinds working account state to a checkpoint taken this round.
    ///
    /// Keys and dense indices only grow in `begin_round`, so a checkpoint
    /// from after registration stays index-aligned.
    pub fn restore(&mut self, checkpoint: SelectorCheckpoint) {
        self.accounts = checkpoint.0;
    }

    /// Registers the staged block-start values for the keys the last
    /// [`begin_round`](Self::begin_round) returned, in the same order.
    pub fn register(&mut self, values: &[Option<StateAccount>]) {
        assert_eq!(
            self.accounts.len() + values.len(),
            self.keys.len(),
            "registered values must cover exactly the unregistered keys"
        );
        for value in values {
            let start = value.clone().unwrap_or_default();
            self.accounts.push(WorkingAccount {
                start_balance: start.balance,
                nonce: start.nonce,
                debit: 0,
                credit: 0,
                touched: false,
                private: start.private,
            });
        }
    }

    /// Applies `operations` in order, returning one applied/dropped flag per
    /// operation plus the private proofs the applied operations queued for
    /// batch verification. Every touched account must be registered.
    pub fn apply(&mut self, operations: &[PreparedOperation]) -> (Vec<bool>, PrivateVerifications) {
        let mut verifications = PrivateVerifications::new();
        let mut applied = Vec::with_capacity(operations.len());
        for operation in operations {
            applied.push(self.apply_one(operation, false, &mut verifications));
        }
        (applied, verifications)
    }

    /// Like [`Self::apply`], but verifies each private proof inline before
    /// applying it and drops offenders individually. Used to attribute
    /// failures after a round's batch verification fails.
    pub fn apply_verifying(&mut self, operations: &[PreparedOperation]) -> Vec<bool> {
        let mut verifications = PrivateVerifications::new();
        let mut applied = Vec::with_capacity(operations.len());
        for operation in operations {
            applied.push(self.apply_one(operation, true, &mut verifications));
        }
        debug_assert!(verifications.is_empty());
        applied
    }

    fn apply_one(
        &mut self,
        operation: &PreparedOperation,
        verify_each: bool,
        verifications: &mut PrivateVerifications,
    ) -> bool {
        let sender = self
            .indices
            .get(operation.sender_prefix, &operation.sender)
            .expect("touched account must be registered") as usize;

        match &operation.payload {
            PreparedPayload::PublicTransfer {
                recipient,
                recipient_prefix,
                value,
            } => {
                if operation.sender == *recipient {
                    let account = &mut self.accounts[sender];

                    // Affordable from the start balance (self-transfers never
                    // debit), with the nonce as the final, mutating gate.
                    if account.start_balance < *value || !account.nonce.consume(operation.nonce) {
                        return false;
                    }
                    account.touched = true;
                    return true;
                }
                let recipient =
                    self.indices
                        .get(*recipient_prefix, recipient)
                        .expect("touched account must be registered") as usize;

                // Check everything that could fail before consuming the
                // nonce, so a dropped transfer leaves no trace.
                let Some(debit) = self.accounts[sender].debit.checked_add(*value) else {
                    return false;
                };
                if self.accounts[sender].start_balance < debit {
                    return false;
                }

                // The recipient's final value is `start - debits + credits`;
                // its debits only grow after this point, so checking against
                // the current debit total is conservative.
                let Some(credit) = self.accounts[recipient].credit.checked_add(*value) else {
                    return false;
                };
                if (self.accounts[recipient].start_balance - self.accounts[recipient].debit)
                    .checked_add(credit)
                    .is_none()
                {
                    return false;
                }
                if !self.accounts[sender].nonce.consume(operation.nonce) {
                    return false;
                }

                self.accounts[sender].debit = debit;
                self.accounts[sender].touched = true;
                self.accounts[recipient].credit = credit;
                self.accounts[recipient].touched = true;
                true
            }
            PreparedPayload::PrivateFund {
                value,
                commitment,
                proof,
            } => {
                let Some(debit) = self.accounts[sender].debit.checked_add(*value) else {
                    return false;
                };
                if self.accounts[sender].start_balance < debit {
                    return false;
                }
                if verify_each && !verify_fund(*value, commitment, proof) {
                    return false;
                }
                if !self.accounts[sender].nonce.consume(operation.nonce) {
                    return false;
                }
                let account = &mut self.accounts[sender];
                account.debit = debit;
                account.private.deposit(commitment);
                account.touched = true;
                if !verify_each {
                    verifications
                        .funds
                        .push((*value, commitment.clone(), *proof));
                }
                true
            }
            PreparedPayload::PrivateTransfer {
                recipient,
                recipient_prefix,
                amount,
                proof,
            } => {
                // Transfer proofs bind the sender's working `current`
                // commitment at apply time, so the claim is captured here and
                // cannot be hoisted ahead of selection.
                let current = self.accounts[sender].private.current.clone();
                if verify_each && !verify_transfer(&current, amount, proof) {
                    return false;
                }
                if operation.sender == *recipient {
                    if !self.accounts[sender].nonce.consume(operation.nonce) {
                        return false;
                    }
                    let account = &mut self.accounts[sender];
                    account.private.withdraw(amount);
                    account.private.deposit(amount);
                    account.touched = true;
                } else {
                    let recipient = self
                        .indices
                        .get(*recipient_prefix, recipient)
                        .expect("touched account must be registered")
                        as usize;
                    if !self.accounts[sender].nonce.consume(operation.nonce) {
                        return false;
                    }
                    self.accounts[sender].private.withdraw(amount);
                    self.accounts[sender].touched = true;
                    self.accounts[recipient].private.deposit(amount);
                    self.accounts[recipient].touched = true;
                }
                if !verify_each {
                    verifications
                        .transfers
                        .push((current, amount.clone(), *proof));
                }
                true
            }
            PreparedPayload::PrivateBurn { value, proof } => {
                let account = &self.accounts[sender];
                let Some(credit) = account.credit.checked_add(*value) else {
                    return false;
                };
                if (account.start_balance - account.debit)
                    .checked_add(credit)
                    .is_none()
                {
                    return false;
                }
                let current = account.private.current.clone();
                if verify_each && !verify_burn(&current, *value, proof) {
                    return false;
                }
                if !self.accounts[sender].nonce.consume(operation.nonce) {
                    return false;
                }
                let account = &mut self.accounts[sender];
                account.credit = credit;
                account.private.burn();
                account.touched = true;
                if !verify_each {
                    verifications.burns.push((current, *value, *proof));
                }
                true
            }
            PreparedPayload::PrivateRollover => {
                if !self.accounts[sender].nonce.consume(operation.nonce) {
                    return false;
                }
                let account = &mut self.accounts[sender];
                account.private.rollover();
                account.touched = true;
                true
            }
        }
    }

    /// Final values for every account touched by an applied transfer, as
    /// staged-index updates in staged order.
    pub fn into_updates(self) -> Vec<(usize, Option<StateAccount>)> {
        self.accounts
            .into_iter()
            .enumerate()
            .filter(|(_, account)| account.touched)
            .map(|(index, account)| {
                let balance = account.start_balance - account.debit + account.credit;
                (
                    index,
                    Some(StateAccount {
                        balance,
                        nonce: account.nonce,
                        private: account.private,
                    }),
                )
            })
            .collect()
    }
}

/// Computes a batch changeset against an in-memory base state.
///
/// Returns the sorted changeset, or `None` if any operation fails its nonce
/// or balance check or any recipient credit overflows. Private proofs queue
/// on `verifications`; the caller decides when to batch-verify them.
pub fn compute(
    state: &State,
    operations: &[PreparedOperation],
    verifications: &mut PrivateVerifications,
) -> Option<Changeset> {
    let plan = execution_plan(operations)?;
    let mut changeset = execute_discrete(state, &plan.discrete, operations, verifications)?;
    if !plan.general.is_empty() {
        let accounts: Vec<Option<StateAccount>> = plan
            .general
            .account_keys()
            .iter()
            .map(|key| state.get(key).cloned())
            .collect();
        let written = apply_general_accounts(&accounts, &plan.general, operations, verifications)?;
        changeset.extend(plan.general.account_keys().iter().copied().zip(written));
    }
    changeset.sort_unstable_by_key(|(key, _)| *key);
    Some(changeset)
}

/// Computes a batch changeset and batch-verifies its private proofs.
///
/// All or nothing: returns `None` on any nonce/balance failure or if any
/// private proof in the batch is invalid.
pub fn execute_with_strategy(
    state: &State,
    operations: &[PreparedOperation],
    strategy: &impl Strategy,
) -> Option<Changeset> {
    let mut verifications = PrivateVerifications::new();
    let changeset = compute(state, operations, &mut verifications)?;
    if !verifications.is_empty() && !verifications.verify_with_strategy(strategy) {
        return None;
    }
    Some(changeset)
}

#[cfg(test)]
mod tests;
