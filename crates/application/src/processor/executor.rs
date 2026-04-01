//! Transaction execution engine for simple transfers.

use super::{
    schedule::{self, TransactionExecution},
    state::{AccountDiff, DiscoveryState, State, StateReader},
};
use bytes::Bytes;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Strategy;
use constantinople_primitives::{Account, Address, Receipt, ReceiptStatus, VerifiedTransaction};
use std::collections::{BTreeMap, HashMap};

/// The final result of verifier-side execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutput<D: Digest> {
    /// Receipts in transaction order.
    pub receipts: Vec<Receipt<D>>,
    /// Persistent account writes produced by execution.
    pub changeset: BTreeMap<Address, Account>,
}

/// The result of [`Processor::validate`].
#[derive(Debug)]
pub struct ValidationResult<PK: PublicKey, H: Hasher> {
    /// Transactions that passed static validation.
    pub valid: Vec<VerifiedTransaction<PK, H>>,
    /// Transactions that failed static validation.
    pub invalid: Vec<VerifiedTransaction<PK, H>>,
}

/// Executes transfer-only transactions.
pub struct Processor<'a, S>
where
    S: Strategy,
{
    strategy: &'a S,
}

impl<S> core::fmt::Debug for Processor<'_, S>
where
    S: Strategy,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Processor").finish_non_exhaustive()
    }
}

impl<'a, S> Processor<'a, S>
where
    S: Strategy,
{
    /// Creates a processor with the given execution strategy.
    pub const fn new(strategy: &'a S) -> Self {
        Self { strategy }
    }

    /// Splits `transactions` into statically valid and invalid sets.
    pub fn validate<H, PK>(
        &self,
        state: &impl StateReader,
        transactions: Vec<VerifiedTransaction<PK, H>>,
    ) -> ValidationResult<PK, H>
    where
        H: Hasher,
        PK: PublicKey,
    {
        let mut pending_accounts = HashMap::with_capacity(transactions.len());
        let mut valid = Vec::with_capacity(transactions.len());
        let mut invalid = Vec::new();

        for transaction in transactions {
            let sender = transaction.signer();
            let tx = transaction.value();
            let mut sender_account = pending_accounts
                .get(&sender)
                .copied()
                .unwrap_or_else(|| state.account(sender));
            let value = tx.value.get();

            let Some(next_nonce) = sender_account.nonce.checked_add(1) else {
                invalid.push(transaction);
                continue;
            };

            if sender_account.nonce != tx.nonce || sender_account.balance < value {
                invalid.push(transaction);
                continue;
            }

            sender_account.nonce = next_nonce;
            if sender == tx.to {
                pending_accounts.insert(sender, sender_account);
                valid.push(transaction);
                continue;
            }

            let mut recipient_account = pending_accounts
                .get(&tx.to)
                .copied()
                .unwrap_or_else(|| state.account(tx.to));
            let Some(recipient_balance) = recipient_account.balance.checked_add(value) else {
                invalid.push(transaction);
                continue;
            };

            sender_account.balance -= value;
            recipient_account.balance = recipient_balance;

            pending_accounts.insert(sender, sender_account);
            pending_accounts.insert(tx.to, recipient_account);
            valid.push(transaction);
        }

        ValidationResult { valid, invalid }
    }

    /// Sequentially executes `transactions` over a lazy state reader.
    pub fn propose<H, PK, R>(
        &self,
        state: &mut DiscoveryState<R>,
        transactions: &[VerifiedTransaction<PK, H>],
    ) -> ExecutionOutput<H::Digest>
    where
        H: Hasher,
        PK: PublicKey,
        R: StateReader,
    {
        let mut receipts = Vec::with_capacity(transactions.len());

        for transaction in transactions {
            let result = self.execute_transaction(state, transaction);
            state.apply(result.diff);
            receipts.push(result.receipt);
        }

        ExecutionOutput {
            receipts,
            changeset: state.changeset(),
        }
    }

    /// Verifies pre-validated transactions against `state`.
    pub fn verify<H, PK>(
        &self,
        state: State,
        transactions: &[VerifiedTransaction<PK, H>],
    ) -> ExecutionOutput<H::Digest>
    where
        H: Hasher,
        PK: PublicKey,
    {
        let executed =
            schedule::execute(self.strategy, state, transactions, |state, transaction| {
                self.execute_transaction(state, transaction)
            });

        ExecutionOutput {
            receipts: executed.receipts,
            changeset: executed.state.changeset(),
        }
    }

    /// Executes a single transaction against `state`.
    fn execute_transaction<H, PK, V>(
        &self,
        state: &V,
        transaction: &VerifiedTransaction<PK, H>,
    ) -> TransactionExecution<H::Digest>
    where
        H: Hasher,
        PK: PublicKey,
        V: StateReader,
    {
        let sender = transaction.signer();
        let tx = transaction.value();
        let value = tx.value.get();
        let sender_account = state.account(sender);
        if sender_account.nonce != tx.nonce || sender_account.balance < value {
            return Self::revert(transaction);
        }

        let Some(next_nonce) = sender_account.nonce.checked_add(1) else {
            return Self::revert(transaction);
        };

        let mut diff = AccountDiff::default();
        if sender == tx.to {
            diff.set_account(
                sender,
                sender_account,
                Account {
                    balance: sender_account.balance,
                    nonce: next_nonce,
                },
            );

            return Self::success(transaction, diff);
        }

        let recipient_account = state.account(tx.to);
        let Some(recipient_balance) = recipient_account.balance.checked_add(value) else {
            return Self::revert(transaction);
        };

        diff.set_account(
            sender,
            sender_account,
            Account {
                balance: sender_account.balance - value,
                nonce: next_nonce,
            },
        );
        diff.set_account(
            tx.to,
            recipient_account,
            Account {
                balance: recipient_balance,
                nonce: recipient_account.nonce,
            },
        );

        Self::success(transaction, diff)
    }

    fn success<H, PK>(
        transaction: &VerifiedTransaction<PK, H>,
        diff: AccountDiff,
    ) -> TransactionExecution<H::Digest>
    where
        H: Hasher,
        PK: PublicKey,
    {
        TransactionExecution {
            receipt: Receipt::new(
                *transaction.message_digest(),
                ReceiptStatus::Success,
                Bytes::new(),
            ),
            diff,
        }
    }

    fn revert<H, PK>(transaction: &VerifiedTransaction<PK, H>) -> TransactionExecution<H::Digest>
    where
        H: Hasher,
        PK: PublicKey,
    {
        TransactionExecution {
            receipt: Receipt::revert(*transaction.message_digest(), Bytes::new()),
            diff: AccountDiff::default(),
        }
    }
}
