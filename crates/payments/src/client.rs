//! Client-side private balance bookkeeping.

use crate::{
    backend::{Backend, Commitment, Opening},
    ledger::Account,
};
use rand_core::RngCore;

/// A client's secret view of its spendable private balance.
pub struct ClientBalance<B: Backend> {
    commitment: B::Commitment,
    opening: B::Opening,
}

impl<B: Backend> Clone for ClientBalance<B> {
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment.clone(),
            opening: self.opening.clone(),
        }
    }
}

impl<B: Backend> ClientBalance<B> {
    /// Empty spendable private balance.
    pub fn empty() -> Self {
        Self {
            commitment: B::Commitment::zero(),
            opening: B::Opening::zero(),
        }
    }

    /// Plaintext spendable balance.
    pub fn value(&self) -> u64 {
        self.opening.value()
    }

    /// Commitment opened by this client state.
    pub fn commitment(&self) -> B::Commitment {
        self.commitment.clone()
    }

    /// Fund the private balance and advance the client view.
    pub fn fund(
        &mut self,
        value: u64,
        params: &B::Params,
        rng: &mut impl RngCore,
    ) -> (B::Commitment, B::FundProof) {
        let (fund_commitment, fund_opening, proof) = B::fund(params, value, rng);
        self.commitment = self.commitment.clone() + &fund_commitment;
        self.opening = self.opening.clone() + &fund_opening;
        (fund_commitment, proof)
    }

    /// Prove a transfer and advance to the post-transfer state.
    pub fn transfer(
        &mut self,
        amount: u64,
        params: &B::Params,
        rng: &mut impl RngCore,
    ) -> Option<(B::Commitment, B::Opening, B::TransferProof)> {
        if amount > self.value() {
            return None;
        }
        let (amount_commitment, amount_opening, proof) =
            B::transfer(params, &self.commitment, &self.opening, amount, rng);
        self.commitment = self.commitment.clone() - &amount_commitment;
        self.opening = self.opening.clone() - &amount_opening;
        Some((amount_commitment, amount_opening, proof))
    }

    /// Fully de-shield the private balance.
    pub fn burn(&mut self, params: &B::Params, rng: &mut impl RngCore) -> (u64, B::BurnProof) {
        let value = self.opening.value();
        let proof = B::burn(params, &self.commitment, &self.opening, rng);
        self.commitment = B::Commitment::zero();
        self.opening = B::Opening::zero();
        (value, proof)
    }

    /// Mirror an incoming pending payment.
    pub fn receive(&mut self, amount_commitment: &B::Commitment, amount_opening: &B::Opening) {
        self.commitment = self.commitment.clone() + amount_commitment;
        self.opening = self.opening.clone() + amount_opening;
    }

    /// Mirror an explicit chain rollover after all pending openings are known.
    pub fn rollover(&mut self, pending: &Self) {
        self.commitment = self.commitment.clone() + &pending.commitment;
        self.opening = self.opening.clone() + &pending.opening;
    }
}

/// Build a client view from chain private account state and an opening.
pub fn account_commitment<B: Backend>(account: &Account<B>) -> B::Commitment {
    account.current().clone()
}
