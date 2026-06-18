//! Swappable proof-backend surface for confidential payments.

use crate::protocol::Transaction;
use core::ops::{Add, Sub};
use rand_core::RngCore;

/// A homomorphic commitment to a balance value.
pub trait Commitment:
    Clone + Eq + for<'a> Add<&'a Self, Output = Self> + for<'a> Sub<&'a Self, Output = Self>
{
    /// The commitment to zero with zero blinding.
    fn zero() -> Self;
}

/// The opening of a commitment: the committed value and its blinding.
pub trait Opening:
    Clone + for<'a> Add<&'a Self, Output = Self> + for<'a> Sub<&'a Self, Output = Self>
{
    /// The empty opening.
    fn zero() -> Self;

    /// The committed plaintext value.
    fn value(&self) -> u64;
}

/// A swappable proof backend for the confidential payment protocol.
pub trait Backend: Sized {
    /// Public parameters.
    type Params;
    /// Homomorphic balance commitment.
    type Commitment: Commitment;
    /// Client-held opening.
    type Opening: Opening;
    /// Proof carried by a fund transaction.
    type FundProof;
    /// Proof carried by a transfer transaction.
    type TransferProof;
    /// Proof carried by a burn transaction.
    type BurnProof;
    /// Deterministic setup input.
    type SetupInput;
    /// Setup error.
    type SetupError: core::fmt::Debug;

    /// Deterministically derive public parameters.
    fn setup(input: &Self::SetupInput) -> Result<Self::Params, Self::SetupError>;

    /// Move a public `value` into the private balance.
    fn fund(
        params: &Self::Params,
        value: u64,
        rng: &mut impl RngCore,
    ) -> (Self::Commitment, Self::Opening, Self::FundProof);

    /// Move private `amount` from a sender balance to a fresh amount commitment.
    fn transfer(
        params: &Self::Params,
        input_commitment: &Self::Commitment,
        input_opening: &Self::Opening,
        amount: u64,
        rng: &mut impl RngCore,
    ) -> (Self::Commitment, Self::Opening, Self::TransferProof);

    /// Fully de-shield the private balance.
    fn burn(
        params: &Self::Params,
        commitment: &Self::Commitment,
        opening: &Self::Opening,
        rng: &mut impl RngCore,
    ) -> Self::BurnProof;

    /// Verify every private payment proof in `txs` together.
    fn batch_verify(
        params: &Self::Params,
        txs: &[Transaction<Self>],
        sender_currents: &[Self::Commitment],
        rng: &mut impl RngCore,
    ) -> bool;
}
