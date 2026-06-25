//! Transaction execution for the Constantinople account model.

use bytes::BytesMut;
use commonware_codec::{FixedSize as _, Write as _};
use commonware_cryptography::Hasher;
use commonware_parallel::{Sequential, Strategy};
use constantinople_primitives::{
    Account, AccountKey, ChainPrivatePaymentBackend, Payload, PrivatePaymentBackend,
    PrivatePaymentExecutionBackend, SignedTransaction, StatePrivatePaymentBackend,
    TransactionPublicKey,
};
use hashbrown::HashMap;
use rand_core::OsRng;
use tracing::info_span;

/// Fully loaded account state for one execution batch.
pub type State<B = StatePrivatePaymentBackend> = HashMap<AccountKey, Account<B>>;

/// Deterministic account writes produced by execution.
pub type Changeset<B = StatePrivatePaymentBackend> = Vec<(AccountKey, Account<B>)>;

type FundVerification<B> = (
    u64,
    <B as commonware_privacy::payments::Backend>::Commitment,
    <B as commonware_privacy::payments::Backend>::FundProof,
);
type TransferVerification<B> = (
    <B as commonware_privacy::payments::Backend>::Commitment,
    <B as commonware_privacy::payments::Backend>::Commitment,
    <B as commonware_privacy::payments::Backend>::TransferProof,
);
type BurnVerification<B> = (
    <B as commonware_privacy::payments::Backend>::Commitment,
    u64,
    <B as commonware_privacy::payments::Backend>::BurnProof,
);

#[derive(Debug)]
struct PrivateVerifications<B: PrivatePaymentBackend> {
    funds: Vec<FundVerification<B>>,
    transfers: Vec<TransferVerification<B>>,
    burns: Vec<BurnVerification<B>>,
}

impl<B> PrivateVerifications<B>
where
    B: PrivatePaymentBackend,
{
    const fn new() -> Self {
        Self {
            funds: Vec::new(),
            transfers: Vec::new(),
            burns: Vec::new(),
        }
    }

    const fn is_empty(&self) -> bool {
        self.funds.is_empty() && self.transfers.is_empty() && self.burns.is_empty()
    }

    const fn len(&self) -> usize {
        self.funds.len() + self.transfers.len() + self.burns.len()
    }

    fn verify_with_strategy(&self, strategy: &impl Strategy) -> bool {
        B::batch_verify_with_strategy(
            strategy,
            B::params(),
            &self.funds,
            &self.transfers,
            &self.burns,
            &mut OsRng,
        )
    }
}

/// Prepared transaction operation.
#[derive(Debug, Clone)]
pub struct PreparedOperation<H, B = StatePrivatePaymentBackend>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    /// Sender account key.
    pub sender: AccountKey,
    /// Operation payload.
    pub payload: PreparedPayload<B>,
    /// Sender nonce required by the transaction.
    pub nonce: u64,
    /// Transaction digest written to the transaction history.
    pub digest: H::Digest,
}

/// Prepared payload with decoded account keys.
#[derive(Debug, Clone)]
pub enum PreparedPayload<B: PrivatePaymentBackend = StatePrivatePaymentBackend> {
    /// Public transfer.
    PublicTransfer { recipient: AccountKey, value: u64 },
    /// Private fund.
    PrivateFund {
        value: u64,
        commitment: B::Commitment,
        proof: B::FundProof,
    },
    /// Private transfer.
    PrivateTransfer {
        recipient: AccountKey,
        amount: B::Commitment,
        proof: B::TransferProof,
    },
    /// Private burn.
    PrivateBurn { value: u64, proof: B::BurnProof },
    /// Explicit private rollover.
    PrivateRollover,
}

/// Transaction paired with its prepared execution data.
#[derive(Clone)]
pub(crate) struct PreparedTransaction<H, B = ChainPrivatePaymentBackend>
where
    H: Hasher,
    B: PrivatePaymentExecutionBackend,
{
    /// Original signed transaction.
    pub transaction: SignedTransaction<H, B>,
    /// Prepared operation data.
    pub operation: PreparedOperation<H, B::ExecutionBackend>,
}

/// Proposal-side transaction preparation.
pub(crate) struct ProposalInput<H, B = ChainPrivatePaymentBackend>
where
    H: Hasher,
    B: PrivatePaymentExecutionBackend,
{
    /// Transactions with decodable execution metadata.
    pub candidates: Vec<PreparedTransaction<H, B>>,
    /// Transactions rejected before account execution.
    pub invalid: Vec<SignedTransaction<H, B>>,
}

/// The result of proposal-side filtering and execution.
pub struct ProposalOutput<H, B = ChainPrivatePaymentBackend>
where
    H: Hasher,
    B: PrivatePaymentExecutionBackend,
{
    /// Transactions included in the proposed block.
    pub valid: Vec<SignedTransaction<H, B>>,
    /// Transactions excluded from the proposed block.
    pub invalid: Vec<SignedTransaction<H, B>>,
    /// Persistent account writes produced by included transactions.
    pub changeset: Changeset<B::ExecutionBackend>,
    pub(crate) operations: Vec<PreparedOperation<H, B::ExecutionBackend>>,
}

/// Prepares transactions for proposal-side execution.
pub(crate) fn prepare_proposal<H, B>(
    transactions: Vec<SignedTransaction<H, B>>,
) -> ProposalInput<H, B>
where
    H: Hasher,
    B: PrivatePaymentExecutionBackend,
{
    let mut candidates = Vec::with_capacity(transactions.len());
    let mut invalid = Vec::new();

    for transaction in transactions {
        let Some(operation) = prepare_operation(&transaction) else {
            invalid.push(transaction);
            continue;
        };
        candidates.push(PreparedTransaction {
            transaction,
            operation,
        });
    }

    ProposalInput {
        candidates,
        invalid,
    }
}

/// Executes proposal candidates and filters statically invalid operations.
pub(crate) fn propose_prepared<H, B>(
    state: &State<B::ExecutionBackend>,
    input: ProposalInput<H, B>,
) -> ProposalOutput<H, B>
where
    H: Hasher,
    B: PrivatePaymentExecutionBackend,
{
    propose_prepared_with_strategy(state, input, &Sequential)
}

/// Executes proposal candidates and filters statically invalid operations using
/// a caller-provided proof verification strategy.
pub(crate) fn propose_prepared_with_strategy<H, B, St>(
    state: &State<B::ExecutionBackend>,
    input: ProposalInput<H, B>,
    strategy: &St,
) -> ProposalOutput<H, B>
where
    H: Hasher,
    B: PrivatePaymentExecutionBackend,
    St: Strategy,
{
    let ProposalInput {
        candidates,
        invalid,
    } = input;
    let mut overlay = Overlay::new(state, candidates.len());
    let mut valid_candidates = Vec::with_capacity(candidates.len());
    let mut operations = Vec::with_capacity(candidates.len());
    let mut private_verifications = PrivateVerifications::new();

    for candidate in &candidates {
        if apply_operation::<H, B::ExecutionBackend>(
            &mut overlay,
            &candidate.operation,
            false,
            &mut private_verifications,
        ) {
            operations.push(candidate.operation.clone());
            valid_candidates.push(true);
        } else {
            valid_candidates.push(false);
        }
    }

    if !private_verifications.is_empty() {
        let verified = info_span!(
            "application.executor.private_batch_verify",
            phase = "propose",
            backend = B::ExecutionBackend::NAME,
            private_txs = private_verifications.len(),
            private_funds = private_verifications.funds.len(),
            private_transfers = private_verifications.transfers.len(),
            private_burns = private_verifications.burns.len(),
            proof_parallelism = strategy.parallelism_hint()
        )
        .in_scope(|| private_verifications.verify_with_strategy(strategy));
        if !verified {
            return propose_prepared_individual(state, candidates, invalid);
        }
    }

    let mut valid = Vec::with_capacity(operations.len());
    let mut invalid = invalid;
    invalid.reserve(candidates.len().saturating_sub(operations.len()));
    for (candidate, is_valid) in candidates.into_iter().zip(valid_candidates) {
        if is_valid {
            valid.push(candidate.transaction);
        } else {
            invalid.push(candidate.transaction);
        }
    }

    ProposalOutput {
        valid,
        invalid,
        changeset: overlay.into_changeset(),
        operations,
    }
}

fn propose_prepared_individual<H, B>(
    state: &State<B::ExecutionBackend>,
    candidates: Vec<PreparedTransaction<H, B>>,
    mut invalid: Vec<SignedTransaction<H, B>>,
) -> ProposalOutput<H, B>
where
    H: Hasher,
    B: PrivatePaymentExecutionBackend,
{
    let mut overlay = Overlay::new(state, candidates.len());
    let mut valid = Vec::with_capacity(candidates.len());
    let mut operations = Vec::with_capacity(candidates.len());

    for candidate in candidates {
        if apply_one::<H, B::ExecutionBackend>(&mut overlay, &candidate.operation, true) {
            operations.push(candidate.operation);
            valid.push(candidate.transaction);
        } else {
            invalid.push(candidate.transaction);
        }
    }

    ProposalOutput {
        valid,
        invalid,
        changeset: overlay.into_changeset(),
        operations,
    }
}

/// Prepares and executes proposal transactions.
pub fn propose<H, B>(
    state: &State<B::ExecutionBackend>,
    transactions: Vec<SignedTransaction<H, B>>,
) -> ProposalOutput<H, B>
where
    H: Hasher,
    B: PrivatePaymentExecutionBackend,
{
    propose_prepared(state, prepare_proposal(transactions))
}

/// Prepares one transaction for account execution.
pub fn prepare_operation<H, B>(
    transaction: &SignedTransaction<H, B>,
) -> Option<PreparedOperation<H, B::ExecutionBackend>>
where
    H: Hasher,
    B: PrivatePaymentExecutionBackend,
{
    let tx = transaction.value();
    let payload = match &tx.payload {
        Payload::PublicTransfer { to, value } => PreparedPayload::PublicTransfer {
            recipient: to.clone(),
            value: value.get(),
        },
        Payload::PrivateFund {
            value,
            commitment,
            proof,
        } => PreparedPayload::PrivateFund {
            value: value.get(),
            commitment: B::to_execution_commitment(commitment.clone()),
            proof: B::to_execution_fund_proof(proof.clone()),
        },
        Payload::PrivateTransfer { to, amount, proof } => PreparedPayload::PrivateTransfer {
            recipient: to.clone(),
            amount: B::to_execution_commitment(amount.clone()),
            proof: B::to_execution_transfer_proof(proof.clone()),
        },
        Payload::PrivateBurn { value, proof } => PreparedPayload::PrivateBurn {
            value: value.get(),
            proof: B::to_execution_burn_proof(proof.clone()),
        },
        Payload::PrivateRollover => PreparedPayload::PrivateRollover,
    };

    Some(PreparedOperation {
        sender: account_key_from_sender(tx.sender_lazy())?,
        payload,
        nonce: tx.nonce,
        digest: *transaction.message_digest(),
    })
}

/// Executes already prepared operations.
pub fn execute<H, B>(
    state: &State<B>,
    operations: &[PreparedOperation<H, B>],
) -> Option<Changeset<B>>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    execute_with_strategy(state, operations, &Sequential)
}

/// Executes already prepared operations using a caller-provided proof
/// verification strategy.
pub fn execute_with_strategy<H, B, St>(
    state: &State<B>,
    operations: &[PreparedOperation<H, B>],
    strategy: &St,
) -> Option<Changeset<B>>
where
    H: Hasher,
    B: PrivatePaymentBackend,
    St: Strategy,
{
    let _span = info_span!(
        "application.executor.execute",
        txs = operations.len(),
        backend = B::NAME,
        proof_parallelism = strategy.parallelism_hint()
    )
    .entered();

    let mut overlay = Overlay::new(state, operations.len());
    let mut private_verifications = PrivateVerifications::new();

    for operation in operations {
        if !apply_operation::<H, B>(&mut overlay, operation, false, &mut private_verifications) {
            return None;
        }
    }

    if !private_verifications.is_empty() {
        let verified = info_span!(
            "application.executor.private_batch_verify",
            backend = B::NAME,
            private_txs = private_verifications.len(),
            private_funds = private_verifications.funds.len(),
            private_transfers = private_verifications.transfers.len(),
            private_burns = private_verifications.burns.len(),
            proof_parallelism = strategy.parallelism_hint()
        )
        .in_scope(|| private_verifications.verify_with_strategy(strategy));
        if !verified {
            return None;
        }
    }

    Some(overlay.into_changeset())
}

#[cfg(test)]
pub(crate) fn execute_unique<H, B>(
    operations: &[PreparedOperation<H, B>],
    accounts: &[(AccountKey, Account<B>)],
) -> Option<Changeset<B>>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    execute_unique_with_strategy(operations, accounts, &Sequential)
}

pub(crate) fn execute_unique_with_strategy<H, B, St>(
    operations: &[PreparedOperation<H, B>],
    accounts: &[(AccountKey, Account<B>)],
    strategy: &St,
) -> Option<Changeset<B>>
where
    H: Hasher,
    B: PrivatePaymentBackend,
    St: Strategy,
{
    let mut state = State::with_capacity(accounts.len());
    for (account_key, account) in accounts {
        state.insert(account_key.clone(), account.clone());
    }
    execute_with_strategy(&state, operations, strategy)
}

fn account_key_from_sender(
    sender: &commonware_codec::types::lazy::Lazy<TransactionPublicKey>,
) -> Option<AccountKey> {
    let mut bytes = BytesMut::with_capacity(TransactionPublicKey::SIZE);
    sender.write(&mut bytes);
    AccountKey::from_public_key_bytes(&bytes)
}

#[derive(Debug)]
struct Overlay<'a, B: PrivatePaymentBackend> {
    base: &'a State<B>,
    writes: HashMap<AccountKey, Account<B>>,
}

impl<'a, B> Overlay<'a, B>
where
    B: PrivatePaymentBackend,
{
    fn new(base: &'a State<B>, transaction_count: usize) -> Self {
        let capacity = base.len().min(transaction_count.saturating_mul(2));
        Self {
            base,
            writes: HashMap::with_capacity(capacity),
        }
    }

    fn get(&self, account_key: &AccountKey) -> Option<Account<B>> {
        self.writes
            .get(account_key)
            .or_else(|| self.base.get(account_key))
            .cloned()
    }

    fn set(&mut self, account_key: AccountKey, account: Account<B>) {
        self.writes.insert(account_key, account);
    }

    fn into_changeset(self) -> Changeset<B> {
        let mut changeset: Changeset<B> = self.writes.into_iter().collect();
        changeset.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        changeset
    }
}

fn apply_one<H, B>(
    state: &mut Overlay<'_, B>,
    operation: &PreparedOperation<H, B>,
    verify_private: bool,
) -> bool
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    let mut private_verifications = PrivateVerifications::new();
    apply_operation(state, operation, verify_private, &mut private_verifications)
}

fn apply_operation<H, B>(
    state: &mut Overlay<'_, B>,
    operation: &PreparedOperation<H, B>,
    verify_private: bool,
    private_verifications: &mut PrivateVerifications<B>,
) -> bool
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    let Some(mut sender) = state.get(&operation.sender) else {
        return false;
    };
    if !sender.nonce.consume(operation.nonce) {
        return false;
    }

    match &operation.payload {
        PreparedPayload::PublicTransfer { recipient, value } => {
            if sender.balance < *value {
                return false;
            }
            if operation.sender == *recipient {
                state.set(operation.sender.clone(), sender);
                return true;
            }
            let Some(mut recipient_account) = state.get(recipient) else {
                return false;
            };
            let Some(recipient_balance) = recipient_account.balance.checked_add(*value) else {
                return false;
            };
            sender.balance -= *value;
            recipient_account.balance = recipient_balance;
            state.set(operation.sender.clone(), sender);
            state.set(recipient.clone(), recipient_account);
            true
        }
        PreparedPayload::PrivateFund {
            value,
            commitment,
            proof,
        } => {
            if sender.balance < *value {
                return false;
            }
            if verify_private && !verify_fund::<B>(*value, commitment, proof) {
                return false;
            }
            sender.balance -= *value;
            sender.private.deposit(commitment);
            if !verify_private {
                private_verifications
                    .funds
                    .push((*value, commitment.clone(), proof.clone()));
            }
            state.set(operation.sender.clone(), sender);
            true
        }
        PreparedPayload::PrivateTransfer {
            recipient,
            amount,
            proof,
        } => {
            let Some(mut recipient_account) = state.get(recipient) else {
                return false;
            };
            let current = sender.private.current.clone();
            if verify_private && !verify_transfer::<B>(&current, amount, proof) {
                return false;
            }
            sender.private.withdraw(amount);
            recipient_account.private.deposit(amount);
            if !verify_private {
                private_verifications
                    .transfers
                    .push((current, amount.clone(), proof.clone()));
            }
            state.set(operation.sender.clone(), sender);
            state.set(recipient.clone(), recipient_account);
            true
        }
        PreparedPayload::PrivateBurn { value, proof } => {
            let current = sender.private.current.clone();
            if verify_private && !verify_burn::<B>(&current, *value, proof) {
                return false;
            }
            let Some(next_balance) = sender.balance.checked_add(*value) else {
                return false;
            };
            sender.balance = next_balance;
            sender.private.burn();
            if !verify_private {
                private_verifications
                    .burns
                    .push((current, *value, proof.clone()));
            }
            state.set(operation.sender.clone(), sender);
            true
        }
        PreparedPayload::PrivateRollover => {
            sender.private.rollover();
            state.set(operation.sender.clone(), sender);
            true
        }
    }
}

fn verify_fund<B>(value: u64, commitment: &B::Commitment, proof: &B::FundProof) -> bool
where
    B: PrivatePaymentBackend,
{
    B::batch_verify(
        B::params(),
        &[(value, commitment.clone(), proof.clone())],
        &[],
        &[],
        &mut OsRng,
    )
}

fn verify_transfer<B>(
    current: &B::Commitment,
    amount: &B::Commitment,
    proof: &B::TransferProof,
) -> bool
where
    B: PrivatePaymentBackend,
{
    B::batch_verify(
        B::params(),
        &[],
        &[(current.clone(), amount.clone(), proof.clone())],
        &[],
        &mut OsRng,
    )
}

fn verify_burn<B>(current: &B::Commitment, value: u64, proof: &B::BurnProof) -> bool
where
    B: PrivatePaymentBackend,
{
    B::batch_verify(
        B::params(),
        &[],
        &[],
        &[(current.clone(), value, proof.clone())],
        &mut OsRng,
    )
}

#[cfg(test)]
mod tests;
