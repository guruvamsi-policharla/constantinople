//! Account state and per-transaction private state transitions.

use crate::{
    backend::{Backend, Commitment},
    protocol::Transaction,
};

/// Per-account private commitment state.
pub struct Account<B: Backend> {
    current: B::Commitment,
    pending: B::Commitment,
}

impl<B: Backend> Account<B> {
    /// A fresh private account.
    pub fn zero() -> Self {
        Self {
            current: B::Commitment::zero(),
            pending: B::Commitment::zero(),
        }
    }

    /// Construct private state from chain-stored commitments.
    pub const fn from_parts(current: B::Commitment, pending: B::Commitment) -> Self {
        Self { current, pending }
    }

    /// Spendable commitment.
    pub const fn current(&self) -> &B::Commitment {
        &self.current
    }

    /// Incoming commitment not yet spendable.
    pub const fn pending(&self) -> &B::Commitment {
        &self.pending
    }

    /// Fold pending into current.
    pub fn rollover(&mut self) {
        self.current = self.current.clone() + &self.pending;
        self.pending = B::Commitment::zero();
    }

    /// Credit incoming value to pending.
    pub fn deposit(&mut self, commitment: &B::Commitment) {
        self.pending = self.pending.clone() + commitment;
    }

    /// Debit spendable value from current.
    pub fn withdraw(&mut self, commitment: &B::Commitment) {
        self.current = self.current.clone() - commitment;
    }

    /// Reset current to zero after full burn.
    pub fn burn(&mut self) {
        self.current = B::Commitment::zero();
    }
}

impl<B: Backend> Clone for Account<B> {
    fn clone(&self) -> Self {
        Self {
            current: self.current.clone(),
            pending: self.pending.clone(),
        }
    }
}

/// Apply one private transaction's state transition to its touched accounts.
pub fn apply<B: Backend>(
    tx: &Transaction<B>,
    sender: &mut Account<B>,
    recipient: Option<&mut Account<B>>,
) {
    match tx {
        Transaction::Fund {
            fund_commitment, ..
        } => sender.deposit(fund_commitment),
        Transaction::Transfer {
            amount_commitment, ..
        } => {
            sender.withdraw(amount_commitment);
            recipient
                .expect("a transfer must be applied with its recipient account")
                .deposit(amount_commitment);
        }
        Transaction::Burn { .. } => sender.burn(),
    }
}
