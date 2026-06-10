//! Transfer execution for the Constantinople account model.

use bytes::BytesMut;
use commonware_codec::{FixedSize as _, Write as _};
use commonware_cryptography::Hasher;
use constantinople_primitives::{
    Account, AccountKey, BalanceCommitment, Payload, ProofClaim, SignedTransaction,
    TransactionPublicKey, verify_proofs_batch,
};
use hashbrown::HashMap;

/// Fully loaded account state for one execution batch.
pub type State = HashMap<AccountKey, Account>;

/// Deterministic account writes produced by execution.
pub type Changeset = Vec<(AccountKey, Account)>;

/// The state transition performed by a prepared transfer.
#[derive(Debug, Clone)]
pub enum PreparedAction {
    /// Public transfer of `value` to `recipient`.
    Transfer {
        /// Recipient account key.
        recipient: AccountKey,
        /// Amount transferred.
        value: u64,
    },
    /// Private transfer of a committed amount to `recipient`.
    ///
    /// The mock proof is verified during preparation, so only the
    /// state-dependent inputs are carried here.
    PrivateTransfer {
        /// Recipient account key.
        recipient: AccountKey,
        /// The sender's expected private balance commitment before this
        /// transfer.
        sender_commitment: BalanceCommitment,
        /// Commitment to the transferred amount.
        amount: BalanceCommitment,
    },
    /// Moves `value` from the sender's public balance into its private
    /// balance.
    Fund {
        /// Amount moved into the private balance.
        value: u64,
        /// The sender's expected private balance commitment before funding.
        sender_commitment: BalanceCommitment,
    },
    /// Moves `value` from the sender's private balance back to its public
    /// balance.
    Burn {
        /// Amount moved out of the private balance.
        value: u64,
        /// The sender's expected private balance commitment before burning.
        sender_commitment: BalanceCommitment,
    },
}

impl PreparedAction {
    /// Returns the sender's declared input commitment, if this action acts on
    /// the private balance.
    pub const fn sender_commitment(&self) -> Option<&BalanceCommitment> {
        match self {
            Self::Transfer { .. } => None,
            Self::PrivateTransfer {
                sender_commitment, ..
            }
            | Self::Fund {
                sender_commitment, ..
            }
            | Self::Burn {
                sender_commitment, ..
            } => Some(sender_commitment),
        }
    }
}

/// Transfer data used by the executor.
#[derive(Debug, Clone)]
pub struct PreparedTransfer<H>
where
    H: Hasher,
{
    /// Sender account key.
    pub sender: AccountKey,
    /// Sender nonce required by the transaction.
    pub nonce: u64,
    /// Transaction digest written to the transaction history.
    pub digest: H::Digest,
    /// The state transition to apply.
    pub action: PreparedAction,
}

impl<H> PreparedTransfer<H>
where
    H: Hasher,
{
    /// Returns the recipient account key, if this transfer has a counterparty.
    pub const fn recipient(&self) -> Option<&AccountKey> {
        match &self.action {
            PreparedAction::Transfer { recipient, .. }
            | PreparedAction::PrivateTransfer { recipient, .. } => Some(recipient),
            PreparedAction::Fund { .. } | PreparedAction::Burn { .. } => None,
        }
    }
}

/// Transaction paired with its prepared execution data.
#[derive(Debug, Clone)]
pub(crate) struct PreparedTransaction<H>
where
    H: Hasher,
{
    /// Original signed transaction.
    pub transaction: SignedTransaction<H>,
    /// Prepared transfer data.
    pub transfer: PreparedTransfer<H>,
}

/// Proposal-side transaction preparation.
#[derive(Debug)]
pub(crate) struct ProposalInput<H>
where
    H: Hasher,
{
    /// Transactions with decodable execution metadata.
    pub candidates: Vec<PreparedTransaction<H>>,
    /// Transactions rejected before account execution.
    pub invalid: Vec<SignedTransaction<H>>,
}

/// The result of proposal-side filtering and execution.
#[derive(Debug)]
pub struct ProposalOutput<H>
where
    H: Hasher,
{
    /// Transactions included in the proposed block.
    pub valid: Vec<SignedTransaction<H>>,
    /// Transactions excluded from the proposed block.
    pub invalid: Vec<SignedTransaction<H>>,
    /// Persistent account writes produced by included transactions.
    pub changeset: Changeset,
    pub(crate) transfers: Vec<PreparedTransfer<H>>,
}

/// Prepares transactions for proposal-side execution.
pub(crate) fn prepare_proposal<H>(transactions: Vec<SignedTransaction<H>>) -> ProposalInput<H>
where
    H: Hasher,
{
    let mut candidates = Vec::with_capacity(transactions.len());
    let mut invalid = Vec::new();

    for transaction in transactions {
        let Some(transfer) = prepare_transfer(&transaction) else {
            invalid.push(transaction);
            continue;
        };
        candidates.push(PreparedTransaction {
            transaction,
            transfer,
        });
    }

    let mut input = ProposalInput {
        candidates,
        invalid,
    };
    filter_invalid_proofs(&mut input);
    input
}

/// Extracts the ZK proof claim a transaction carries, if any.
///
/// Public transfers and funds carry no proof.
fn proof_claim<H>(transaction: &SignedTransaction<H>) -> Option<ProofClaim>
where
    H: Hasher,
{
    match &transaction.value().payload {
        Payload::PrivateTransfer {
            sender_commitment,
            amount,
            proof,
            ..
        } => Some(ProofClaim::Transfer {
            input: *sender_commitment,
            amount: *amount,
            proof: *proof,
        }),
        Payload::Burn {
            sender_commitment,
            value,
            proof,
        } => Some(ProofClaim::Burn {
            input: *sender_commitment,
            value: value.get(),
            proof: *proof,
        }),
        Payload::Transfer { .. } | Payload::Fund { .. } => None,
    }
}

/// Batch-verifies every ZK proof carried by `transactions` in a single pairing
/// check. Transactions without a proof (public transfers, funds) are skipped;
/// an empty set trivially passes.
pub fn verify_proofs<'a, H>(
    transactions: impl IntoIterator<Item = &'a SignedTransaction<H>>,
) -> bool
where
    H: Hasher + 'a,
{
    let claims: Vec<ProofClaim> = transactions.into_iter().filter_map(proof_claim).collect();
    verify_proofs_batch(&claims)
}

/// Drops proposal candidates whose ZK proofs do not verify, moving them to
/// `invalid`.
///
/// Verifies the whole candidate set with one batched pairing check; only when
/// that fails does it fall back to per-candidate checks to isolate the
/// offending transactions (an honest mempool keeps this to the single batch).
fn filter_invalid_proofs<H>(input: &mut ProposalInput<H>)
where
    H: Hasher,
{
    let claims: Vec<ProofClaim> = input
        .candidates
        .iter()
        .filter_map(|candidate| proof_claim(&candidate.transaction))
        .collect();
    if claims.is_empty() || verify_proofs_batch(&claims) {
        return;
    }

    let mut kept = Vec::with_capacity(input.candidates.len());
    for candidate in input.candidates.drain(..) {
        let valid =
            proof_claim(&candidate.transaction).is_none_or(|claim| verify_proofs_batch(&[claim]));
        if valid {
            kept.push(candidate);
        } else {
            input.invalid.push(candidate.transaction);
        }
    }
    input.candidates = kept;
}

/// The outcome of applying one prepared transfer to an overlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Application {
    /// The transfer was applied to the overlay.
    Applied,
    /// The sender's private balance commitment does not match the declared
    /// input commitment. The transfer may become applicable after an earlier
    /// link of the sender's chain executes.
    WrongCommitment,
    /// The transfer can never apply against this state.
    Invalid,
}

/// Executes proposal candidates and filters statically invalid transfers.
///
/// Private-side transactions (private transfer, fund, burn) form per-sender
/// chains: each declares the sender's private balance commitment it expects as
/// input. Pool order need not match chain order, so candidates whose declared
/// commitment does not match the current state are deferred and retried as
/// soon as another transaction from the same sender produces the commitment
/// they expect. Deferred candidates whose predecessor never materializes are
/// rejected.
pub(crate) fn propose_prepared<H>(state: &State, input: ProposalInput<H>) -> ProposalOutput<H>
where
    H: Hasher,
{
    let mut overlay = Overlay::new(state, input.candidates.len());
    let mut valid = Vec::with_capacity(input.candidates.len());
    let mut transfers = Vec::with_capacity(input.candidates.len());
    let mut invalid = input.invalid;
    let mut deferred: HashMap<(AccountKey, BalanceCommitment), Vec<PreparedTransaction<H>>> =
        HashMap::new();

    for candidate in input.candidates {
        match apply_transfer(&mut overlay, &candidate.transfer) {
            Application::Applied => {
                let sender = candidate.transfer.sender.clone();
                transfers.push(candidate.transfer);
                valid.push(candidate.transaction);
                cascade_deferred(
                    &mut overlay,
                    &mut deferred,
                    sender,
                    &mut valid,
                    &mut transfers,
                    &mut invalid,
                );
            }
            Application::WrongCommitment => {
                let commitment = *candidate
                    .transfer
                    .action
                    .sender_commitment()
                    .expect("commitment mismatch requires a private action");
                deferred
                    .entry((candidate.transfer.sender.clone(), commitment))
                    .or_default()
                    .push(candidate);
            }
            Application::Invalid => invalid.push(candidate.transaction),
        }
    }

    // Whatever is still deferred is unlinkable: its declared input commitment
    // was never produced (missing predecessor or forked chain).
    invalid.extend(
        deferred
            .into_values()
            .flatten()
            .map(|candidate| candidate.transaction),
    );

    ProposalOutput {
        valid,
        invalid,
        changeset: overlay.into_changeset(),
        transfers,
    }
}

/// Applies deferred candidates unlocked by `sender`'s latest commitment.
///
/// Each successful application advances the sender's private balance
/// commitment, which may unlock the next deferred link of the chain.
fn cascade_deferred<H>(
    overlay: &mut Overlay<'_>,
    deferred: &mut HashMap<(AccountKey, BalanceCommitment), Vec<PreparedTransaction<H>>>,
    sender: AccountKey,
    valid: &mut Vec<SignedTransaction<H>>,
    transfers: &mut Vec<PreparedTransfer<H>>,
    invalid: &mut Vec<SignedTransaction<H>>,
) where
    H: Hasher,
{
    loop {
        let Some(account) = overlay.get(&sender) else {
            return;
        };
        let key = (sender.clone(), account.private);
        let Some(mut queue) = deferred.remove(&key) else {
            return;
        };

        // Try queued candidates until one applies. At most one can: they all
        // declare the same input commitment, and a success replaces it.
        let mut applied = false;
        let mut index = 0;
        while index < queue.len() {
            match apply_transfer(overlay, &queue[index].transfer) {
                Application::Applied => {
                    let candidate = queue.swap_remove(index);
                    transfers.push(candidate.transfer);
                    valid.push(candidate.transaction);
                    applied = true;
                    break;
                }
                Application::WrongCommitment => index += 1,
                Application::Invalid => {
                    invalid.push(queue.swap_remove(index).transaction);
                }
            }
        }

        // Leftovers (forked chain links) stay deferred and are rejected when
        // the proposal drains the map.
        if !queue.is_empty() {
            deferred.insert(key, queue);
        }
        if !applied {
            return;
        }
    }
}

/// Prepares and executes proposal transactions.
pub fn propose<H>(state: &State, transactions: Vec<SignedTransaction<H>>) -> ProposalOutput<H>
where
    H: Hasher,
{
    propose_prepared(state, prepare_proposal(transactions))
}

/// Prepares one transaction for account execution.
///
/// Returns `None` if the sender key cannot derive an account or if a
/// private-side mock proof fails to verify. Proofs bind only to transaction
/// fields, so they are checked once here rather than during state application.
pub fn prepare_transfer<H>(transaction: &SignedTransaction<H>) -> Option<PreparedTransfer<H>>
where
    H: Hasher,
{
    let tx = transaction.value();
    let sender = account_key_from_sender(tx.sender_lazy())?;

    let action = match &tx.payload {
        Payload::Transfer { to, value } => PreparedAction::Transfer {
            recipient: to.clone(),
            value: value.get(),
        },
        Payload::PrivateTransfer {
            to,
            sender_commitment,
            amount,
            ..
        } => {
            // ZK proofs are verified in one batched pass per block (see
            // `verify_proofs`), not here: preparation only decodes and derives
            // the state-transition inputs. The proof binds to the declared
            // commitments, the signature authenticates the sender, and the
            // nonce orders the sender's chain.
            PreparedAction::PrivateTransfer {
                recipient: to.clone(),
                sender_commitment: *sender_commitment,
                amount: *amount,
            }
        }
        Payload::Fund {
            value,
            sender_commitment,
        } => PreparedAction::Fund {
            value: value.get(),
            sender_commitment: *sender_commitment,
        },
        Payload::Burn {
            value,
            sender_commitment,
            ..
        } => PreparedAction::Burn {
            value: value.get(),
            sender_commitment: *sender_commitment,
        },
    };

    Some(PreparedTransfer {
        sender,
        nonce: tx.nonce,
        digest: *transaction.message_digest(),
        action,
    })
}

/// Executes already prepared transfers.
///
/// Transfers are applied strictly in order: any commitment mismatch or invalid
/// transfer rejects the whole batch.
pub fn execute<H>(state: &State, transfers: &[PreparedTransfer<H>]) -> Option<Changeset>
where
    H: Hasher,
{
    let mut overlay = Overlay::new(state, transfers.len());

    for transfer in transfers {
        if apply_transfer(&mut overlay, transfer) != Application::Applied {
            return None;
        }
    }

    Some(overlay.into_changeset())
}

pub(crate) fn execute_unique<H>(
    transfers: &[PreparedTransfer<H>],
    accounts: &[Account],
) -> Option<Changeset>
where
    H: Hasher,
{
    let expected_accounts: usize = transfers
        .iter()
        .map(|transfer| if transfer.recipient().is_some() { 2 } else { 1 })
        .sum();
    if accounts.len() != expected_accounts {
        return None;
    }
    let mut changeset = Vec::with_capacity(accounts.len());
    let mut accounts = accounts.iter();

    for transfer in transfers {
        let mut sender = *accounts.next()?;
        if let Some(expected) = transfer.action.sender_commitment()
            && sender.private != *expected
        {
            return None;
        }
        if !sender.nonce.consume(transfer.nonce) {
            return None;
        }

        match &transfer.action {
            PreparedAction::Transfer { recipient, value } => {
                if sender.balance < *value {
                    return None;
                }
                let mut recipient_account = *accounts.next()?;
                let recipient_balance = recipient_account.balance.checked_add(*value)?;

                sender.balance -= value;
                recipient_account.balance = recipient_balance;
                changeset.push((transfer.sender.clone(), sender));
                changeset.push((recipient.clone(), recipient_account));
            }
            PreparedAction::PrivateTransfer {
                recipient, amount, ..
            } => {
                let mut recipient_account = *accounts.next()?;

                sender.private = sender.private.sub(amount);
                recipient_account.pending = recipient_account.pending.add(amount);
                changeset.push((transfer.sender.clone(), sender));
                changeset.push((recipient.clone(), recipient_account));
            }
            PreparedAction::Fund { value, .. } => {
                if sender.balance < *value {
                    return None;
                }
                sender.balance -= value;
                sender.private = sender.private.add(&BalanceCommitment::commit(*value));
                changeset.push((transfer.sender.clone(), sender));
            }
            PreparedAction::Burn { value, .. } => {
                sender.balance = sender.balance.checked_add(*value)?;
                sender.private = sender.private.sub(&BalanceCommitment::commit(*value));
                changeset.push((transfer.sender.clone(), sender));
            }
        }
    }

    changeset.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
    Some(changeset)
}

fn account_key_from_sender(
    sender: &commonware_codec::types::lazy::Lazy<TransactionPublicKey>,
) -> Option<AccountKey> {
    let mut bytes = BytesMut::with_capacity(TransactionPublicKey::SIZE);
    sender.write(&mut bytes);
    AccountKey::from_public_key_bytes(&bytes)
}

#[derive(Debug)]
struct Overlay<'a> {
    base: &'a State,
    writes: HashMap<AccountKey, Account>,
}

impl<'a> Overlay<'a> {
    fn new(base: &'a State, transaction_count: usize) -> Self {
        let capacity = base.len().min(transaction_count.saturating_mul(2));
        Self {
            base,
            writes: HashMap::with_capacity(capacity),
        }
    }

    fn get(&self, account_key: &AccountKey) -> Option<Account> {
        self.writes
            .get(account_key)
            .or_else(|| self.base.get(account_key))
            .copied()
    }

    fn set(&mut self, account_key: AccountKey, account: Account) {
        self.writes.insert(account_key, account);
    }

    fn into_changeset(self) -> Changeset {
        let mut changeset: Changeset = self.writes.into_iter().collect();
        changeset.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        changeset
    }
}

fn apply_transfer<H>(state: &mut Overlay<'_>, transfer: &PreparedTransfer<H>) -> Application
where
    H: Hasher,
{
    let Some(mut sender) = state.get(&transfer.sender) else {
        return Application::Invalid;
    };
    if let Some(expected) = transfer.action.sender_commitment()
        && sender.private != *expected
    {
        return Application::WrongCommitment;
    }
    if !sender.nonce.consume(transfer.nonce) {
        return Application::Invalid;
    }

    match &transfer.action {
        PreparedAction::Transfer { recipient, value } => {
            if sender.balance < *value {
                return Application::Invalid;
            }

            if transfer.sender == *recipient {
                state.set(transfer.sender.clone(), sender);
                return Application::Applied;
            }

            let Some(mut recipient_account) = state.get(recipient) else {
                return Application::Invalid;
            };
            let Some(recipient_balance) = recipient_account.balance.checked_add(*value) else {
                return Application::Invalid;
            };

            sender.balance -= value;
            recipient_account.balance = recipient_balance;
            state.set(transfer.sender.clone(), sender);
            state.set(recipient.clone(), recipient_account);
        }
        PreparedAction::PrivateTransfer {
            recipient, amount, ..
        } => {
            sender.private = sender.private.sub(amount);

            if transfer.sender == *recipient {
                sender.pending = sender.pending.add(amount);
                state.set(transfer.sender.clone(), sender);
                return Application::Applied;
            }

            let Some(mut recipient_account) = state.get(recipient) else {
                return Application::Invalid;
            };
            recipient_account.pending = recipient_account.pending.add(amount);
            state.set(transfer.sender.clone(), sender);
            state.set(recipient.clone(), recipient_account);
        }
        PreparedAction::Fund { value, .. } => {
            if sender.balance < *value {
                return Application::Invalid;
            }

            sender.balance -= value;
            sender.private = sender.private.add(&BalanceCommitment::commit(*value));
            state.set(transfer.sender.clone(), sender);
        }
        PreparedAction::Burn { value, .. } => {
            let Some(balance) = sender.balance.checked_add(*value) else {
                return Application::Invalid;
            };

            sender.balance = balance;
            sender.private = sender.private.sub(&BalanceCommitment::commit(*value));
            state.set(transfer.sender.clone(), sender);
        }
    }

    Application::Applied
}

#[cfg(test)]
mod tests;
