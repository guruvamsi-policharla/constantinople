//! Transaction execution for the Constantinople account model.

use bytes::BytesMut;
use commonware_codec::{FixedSize as _, Write as _};
use commonware_cryptography::Hasher;
use constantinople_primitives::{
    Account, AccountKey, MockPrivatePaymentBackend, Payload, PrivatePaymentBackend,
    SignedTransaction, TransactionPublicKey,
};
use hashbrown::HashMap;
use private_payments::Transaction as PrivateTransaction;
use rand_core::OsRng;
use tracing::info_span;

/// Fully loaded account state for one execution batch.
pub type State<B = MockPrivatePaymentBackend> = HashMap<AccountKey, Account<B>>;

/// Deterministic account writes produced by execution.
pub type Changeset<B = MockPrivatePaymentBackend> = Vec<(AccountKey, Account<B>)>;

/// Prepared transaction operation.
#[derive(Debug, Clone)]
pub struct PreparedOperation<H, B = MockPrivatePaymentBackend>
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
pub enum PreparedPayload<B: PrivatePaymentBackend = MockPrivatePaymentBackend> {
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
#[derive(Debug, Clone)]
pub(crate) struct PreparedTransaction<H, B = MockPrivatePaymentBackend>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    /// Original signed transaction.
    pub transaction: SignedTransaction<H, B>,
    /// Prepared operation data.
    pub operation: PreparedOperation<H, B>,
}

/// Proposal-side transaction preparation.
#[derive(Debug)]
pub(crate) struct ProposalInput<H, B = MockPrivatePaymentBackend>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    /// Transactions with decodable execution metadata.
    pub candidates: Vec<PreparedTransaction<H, B>>,
    /// Transactions rejected before account execution.
    pub invalid: Vec<SignedTransaction<H, B>>,
}

/// The result of proposal-side filtering and execution.
#[derive(Debug)]
pub struct ProposalOutput<H, B = MockPrivatePaymentBackend>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    /// Transactions included in the proposed block.
    pub valid: Vec<SignedTransaction<H, B>>,
    /// Transactions excluded from the proposed block.
    pub invalid: Vec<SignedTransaction<H, B>>,
    /// Persistent account writes produced by included transactions.
    pub changeset: Changeset<B>,
    pub(crate) operations: Vec<PreparedOperation<H, B>>,
}

/// Prepares transactions for proposal-side execution.
pub(crate) fn prepare_proposal<H, B>(
    transactions: Vec<SignedTransaction<H, B>>,
) -> ProposalInput<H, B>
where
    H: Hasher,
    B: PrivatePaymentBackend,
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
    state: &State<B>,
    input: ProposalInput<H, B>,
) -> ProposalOutput<H, B>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    let mut overlay = Overlay::new(state, input.candidates.len());
    let mut valid = Vec::with_capacity(input.candidates.len());
    let mut operations = Vec::with_capacity(input.candidates.len());
    let mut invalid = input.invalid;

    for candidate in input.candidates {
        if apply_one::<H, B>(&mut overlay, &candidate.operation, true) {
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
    state: &State<B>,
    transactions: Vec<SignedTransaction<H, B>>,
) -> ProposalOutput<H, B>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    propose_prepared(state, prepare_proposal(transactions))
}

/// Backward-compatible public name.
pub fn prepare_transfer<H, B>(
    transaction: &SignedTransaction<H, B>,
) -> Option<PreparedOperation<H, B>>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    prepare_operation(transaction)
}

/// Prepares one transaction for account execution.
pub fn prepare_operation<H, B>(
    transaction: &SignedTransaction<H, B>,
) -> Option<PreparedOperation<H, B>>
where
    H: Hasher,
    B: PrivatePaymentBackend,
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
            commitment: commitment.clone(),
            proof: proof.clone(),
        },
        Payload::PrivateTransfer { to, amount, proof } => PreparedPayload::PrivateTransfer {
            recipient: to.clone(),
            amount: amount.clone(),
            proof: proof.clone(),
        },
        Payload::PrivateBurn { value, proof } => PreparedPayload::PrivateBurn {
            value: value.get(),
            proof: proof.clone(),
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
    let _span = info_span!(
        "application.executor.execute",
        txs = operations.len(),
        backend = B::NAME
    )
    .entered();

    let mut overlay = Overlay::new(state, operations.len());
    let mut private_txs = Vec::new();
    let mut sender_currents = Vec::new();

    for operation in operations {
        if !apply_operation::<H, B>(
            &mut overlay,
            operation,
            false,
            &mut private_txs,
            &mut sender_currents,
        ) {
            return None;
        }
    }

    if !private_txs.is_empty() {
        let verified = info_span!(
            "application.executor.private_batch_verify",
            backend = B::NAME,
            private_txs = private_txs.len(),
            sender_currents = sender_currents.len()
        )
        .in_scope(|| B::batch_verify(B::params(), &private_txs, &sender_currents, &mut OsRng));
        if !verified {
            return None;
        }
    }

    Some(overlay.into_changeset())
}

pub(crate) fn execute_unique<H, B>(
    operations: &[PreparedOperation<H, B>],
    accounts: &[(AccountKey, Account<B>)],
) -> Option<Changeset<B>>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    let mut state = State::with_capacity(accounts.len());
    for (account_key, account) in accounts {
        state.insert(account_key.clone(), account.clone());
    }
    execute(&state, operations)
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
    let mut private_txs = Vec::new();
    let mut sender_currents = Vec::new();
    apply_operation(
        state,
        operation,
        verify_private,
        &mut private_txs,
        &mut sender_currents,
    )
}

fn apply_operation<H, B>(
    state: &mut Overlay<'_, B>,
    operation: &PreparedOperation<H, B>,
    verify_private: bool,
    private_txs: &mut Vec<PrivateTransaction<B>>,
    sender_currents: &mut Vec<B::Commitment>,
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
            let tx = PrivateTransaction::Fund {
                sender: 0,
                value: *value,
                fund_commitment: commitment.clone(),
                proof: proof.clone(),
            };
            if verify_private && !verify_single::<B>(&tx, &[]) {
                return false;
            }
            sender.balance -= *value;
            sender.private.deposit(commitment);
            private_txs.push(tx);
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
            let tx = PrivateTransaction::Transfer {
                sender: 0,
                recipient: 1,
                amount_commitment: amount.clone(),
                proof: proof.clone(),
            };
            if verify_private && !verify_single::<B>(&tx, core::slice::from_ref(&current)) {
                return false;
            }
            sender.private.withdraw(amount);
            recipient_account.private.deposit(amount);
            private_txs.push(tx);
            sender_currents.push(current);
            state.set(operation.sender.clone(), sender);
            state.set(recipient.clone(), recipient_account);
            true
        }
        PreparedPayload::PrivateBurn { value, proof } => {
            let current = sender.private.current.clone();
            let tx = PrivateTransaction::Burn {
                sender: 0,
                value: *value,
                proof: proof.clone(),
            };
            if verify_private && !verify_single::<B>(&tx, core::slice::from_ref(&current)) {
                return false;
            }
            let Some(next_balance) = sender.balance.checked_add(*value) else {
                return false;
            };
            sender.balance = next_balance;
            sender.private.burn();
            private_txs.push(tx);
            sender_currents.push(current);
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

fn verify_single<B>(tx: &PrivateTransaction<B>, currents: &[B::Commitment]) -> bool
where
    B: PrivatePaymentBackend,
{
    B::batch_verify(B::params(), core::slice::from_ref(tx), currents, &mut OsRng)
}

#[cfg(test)]
mod tests;
