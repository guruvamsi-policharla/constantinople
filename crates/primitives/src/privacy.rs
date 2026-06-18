//! Chain-facing private payment backend adapter.
//!
//! Constantinople execution is generic over [`private_payments::Backend`].
//! This module adds the codec and static-parameter requirements needed to store
//! backend commitments/proofs in consensus state and transaction bytes.

use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use private_payments::{Backend, Commitment, Opening, Transaction as PrivateTransaction};
use rand_core::RngCore;
use std::sync::OnceLock;

/// Backend requirements imposed by Constantinople's wire/state codecs.
pub trait PrivatePaymentBackend:
    Backend<
        Params: Send + Sync + 'static,
        Commitment: FixedSize
                        + Read<Cfg = ()>
                        + Write
                        + core::fmt::Debug
                        + core::hash::Hash
                        + Send
                        + Sync,
        FundProof: FixedSize
                       + Read<Cfg = ()>
                       + Write
                       + Clone
                       + Eq
                       + core::fmt::Debug
                       + core::hash::Hash
                       + Send
                       + Sync,
        TransferProof: FixedSize
                           + Read<Cfg = ()>
                           + Write
                           + Clone
                           + Eq
                           + core::fmt::Debug
                           + core::hash::Hash
                           + Send
                           + Sync,
        BurnProof: FixedSize
                       + Read<Cfg = ()>
                       + Write
                       + Clone
                       + Eq
                       + core::fmt::Debug
                       + core::hash::Hash
                       + Send
                       + Sync,
    > + Send
    + Sync
    + Clone
    + Eq
    + 'static
{
    /// Low-cardinality backend name for tracing.
    const NAME: &'static str;

    /// Verifier/prover parameters used by chain execution.
    fn params() -> &'static Self::Params;
}

/// Stored private commitment state for one Constantinople account.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PrivateAccount<B: PrivatePaymentBackend = MockPrivatePaymentBackend>
where
    B::Params: Send + Sync + 'static,
    B::Commitment:
        FixedSize + Read<Cfg = ()> + Write + core::fmt::Debug + core::hash::Hash + Send + Sync,
    B::FundProof: FixedSize
        + Read<Cfg = ()>
        + Write
        + Clone
        + core::fmt::Debug
        + core::hash::Hash
        + Send
        + Sync,
    B::TransferProof: FixedSize
        + Read<Cfg = ()>
        + Write
        + Clone
        + core::fmt::Debug
        + core::hash::Hash
        + Send
        + Sync,
    B::BurnProof: FixedSize
        + Read<Cfg = ()>
        + Write
        + Clone
        + core::fmt::Debug
        + core::hash::Hash
        + Send
        + Sync,
{
    /// Spendable private commitment.
    pub current: B::Commitment,
    /// Incoming private commitment waiting for explicit rollover.
    pub pending: B::Commitment,
}

impl<B> PrivateAccount<B>
where
    B: PrivatePaymentBackend,
    B::Params: Send + Sync + 'static,
    B::Commitment:
        FixedSize + Read<Cfg = ()> + Write + core::fmt::Debug + core::hash::Hash + Send + Sync,
    B::FundProof: FixedSize
        + Read<Cfg = ()>
        + Write
        + Clone
        + core::fmt::Debug
        + core::hash::Hash
        + Send
        + Sync,
    B::TransferProof: FixedSize
        + Read<Cfg = ()>
        + Write
        + Clone
        + core::fmt::Debug
        + core::hash::Hash
        + Send
        + Sync,
    B::BurnProof: FixedSize
        + Read<Cfg = ()>
        + Write
        + Clone
        + core::fmt::Debug
        + core::hash::Hash
        + Send
        + Sync,
{
    /// Fresh private state.
    pub fn zero() -> Self {
        Self {
            current: B::Commitment::zero(),
            pending: B::Commitment::zero(),
        }
    }

    /// Convert into the generic API's account type.
    pub fn to_private_payments(&self) -> private_payments::Account<B> {
        private_payments::Account::from_parts(self.current.clone(), self.pending.clone())
    }

    /// Fold pending into current.
    pub fn rollover(&mut self) {
        self.current = self.current.clone() + &self.pending;
        self.pending = B::Commitment::zero();
    }

    /// Credit a commitment to pending.
    pub fn deposit(&mut self, commitment: &B::Commitment) {
        self.pending = self.pending.clone() + commitment;
    }

    /// Debit a commitment from current.
    pub fn withdraw(&mut self, commitment: &B::Commitment) {
        self.current = self.current.clone() - commitment;
    }

    /// Reset current to zero after a full burn.
    pub fn burn(&mut self) {
        self.current = B::Commitment::zero();
    }
}

impl<B> Default for PrivateAccount<B>
where
    B: PrivatePaymentBackend,
    B::Params: Send + Sync + 'static,
    B::Commitment:
        FixedSize + Read<Cfg = ()> + Write + core::fmt::Debug + core::hash::Hash + Send + Sync,
    B::FundProof: FixedSize
        + Read<Cfg = ()>
        + Write
        + Clone
        + core::fmt::Debug
        + core::hash::Hash
        + Send
        + Sync,
    B::TransferProof: FixedSize
        + Read<Cfg = ()>
        + Write
        + Clone
        + core::fmt::Debug
        + core::hash::Hash
        + Send
        + Sync,
    B::BurnProof: FixedSize
        + Read<Cfg = ()>
        + Write
        + Clone
        + core::fmt::Debug
        + core::hash::Hash
        + Send
        + Sync,
{
    fn default() -> Self {
        Self::zero()
    }
}

impl<B> FixedSize for PrivateAccount<B>
where
    B: PrivatePaymentBackend,
    B::Params: Send + Sync + 'static,
    B::Commitment:
        FixedSize + Read<Cfg = ()> + Write + core::fmt::Debug + core::hash::Hash + Send + Sync,
    B::FundProof: FixedSize
        + Read<Cfg = ()>
        + Write
        + Clone
        + core::fmt::Debug
        + core::hash::Hash
        + Send
        + Sync,
    B::TransferProof: FixedSize
        + Read<Cfg = ()>
        + Write
        + Clone
        + core::fmt::Debug
        + core::hash::Hash
        + Send
        + Sync,
    B::BurnProof: FixedSize
        + Read<Cfg = ()>
        + Write
        + Clone
        + core::fmt::Debug
        + core::hash::Hash
        + Send
        + Sync,
{
    const SIZE: usize = B::Commitment::SIZE + B::Commitment::SIZE;
}

impl<B> Write for PrivateAccount<B>
where
    B: PrivatePaymentBackend,
    B::Params: Send + Sync + 'static,
    B::Commitment:
        FixedSize + Read<Cfg = ()> + Write + core::fmt::Debug + core::hash::Hash + Send + Sync,
    B::FundProof: FixedSize
        + Read<Cfg = ()>
        + Write
        + Clone
        + core::fmt::Debug
        + core::hash::Hash
        + Send
        + Sync,
    B::TransferProof: FixedSize
        + Read<Cfg = ()>
        + Write
        + Clone
        + core::fmt::Debug
        + core::hash::Hash
        + Send
        + Sync,
    B::BurnProof: FixedSize
        + Read<Cfg = ()>
        + Write
        + Clone
        + core::fmt::Debug
        + core::hash::Hash
        + Send
        + Sync,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.current.write(buf);
        self.pending.write(buf);
    }
}

impl<B> Read for PrivateAccount<B>
where
    B: PrivatePaymentBackend,
    B::Params: Send + Sync + 'static,
    B::Commitment:
        FixedSize + Read<Cfg = ()> + Write + core::fmt::Debug + core::hash::Hash + Send + Sync,
    B::FundProof: FixedSize
        + Read<Cfg = ()>
        + Write
        + Clone
        + core::fmt::Debug
        + core::hash::Hash
        + Send
        + Sync,
    B::TransferProof: FixedSize
        + Read<Cfg = ()>
        + Write
        + Clone
        + core::fmt::Debug
        + core::hash::Hash
        + Send
        + Sync,
    B::BurnProof: FixedSize
        + Read<Cfg = ()>
        + Write
        + Clone
        + core::fmt::Debug
        + core::hash::Hash
        + Send
        + Sync,
{
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            current: B::Commitment::read(buf)?,
            pending: B::Commitment::read(buf)?,
        })
    }
}

/// Non-cryptographic backend used as the default type parameter and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MockPrivatePaymentBackend;

/// Mock commitment `(value, blinding)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MockCommitment {
    value: u64,
    blind: u64,
}

impl MockCommitment {
    /// Construct a mock commitment.
    pub const fn new(value: u64, blind: u64) -> Self {
        Self { value, blind }
    }

    /// Committed value component.
    pub const fn value(&self) -> u64 {
        self.value
    }
}

impl core::ops::Add<&Self> for MockCommitment {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Self {
            value: self.value.wrapping_add(rhs.value),
            blind: self.blind.wrapping_add(rhs.blind),
        }
    }
}

impl core::ops::Sub<&Self> for MockCommitment {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Self {
            value: self.value.wrapping_sub(rhs.value),
            blind: self.blind.wrapping_sub(rhs.blind),
        }
    }
}

impl Commitment for MockCommitment {
    fn zero() -> Self {
        Self { value: 0, blind: 0 }
    }
}

impl FixedSize for MockCommitment {
    const SIZE: usize = u64::SIZE + u64::SIZE;
}

impl Write for MockCommitment {
    fn write(&self, buf: &mut impl BufMut) {
        self.value.write(buf);
        self.blind.write(buf);
    }
}

impl Read for MockCommitment {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            value: u64::read(buf)?,
            blind: u64::read(buf)?,
        })
    }
}

/// Mock opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockOpening {
    value: u64,
    blind: u64,
}

impl core::ops::Add<&Self> for MockOpening {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Self {
            value: self.value.wrapping_add(rhs.value),
            blind: self.blind.wrapping_add(rhs.blind),
        }
    }
}

impl core::ops::Sub<&Self> for MockOpening {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Self {
            value: self.value.wrapping_sub(rhs.value),
            blind: self.blind.wrapping_sub(rhs.blind),
        }
    }
}

impl Opening for MockOpening {
    fn zero() -> Self {
        Self { value: 0, blind: 0 }
    }

    fn value(&self) -> u64 {
        self.value
    }
}

/// Empty mock proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MockProof;

impl FixedSize for MockProof {
    const SIZE: usize = 0;
}

impl Write for MockProof {
    fn write(&self, _buf: &mut impl BufMut) {}
}

impl Read for MockProof {
    type Cfg = ();

    fn read_cfg(_buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self)
    }
}

impl Backend for MockPrivatePaymentBackend {
    type Params = ();
    type Commitment = MockCommitment;
    type Opening = MockOpening;
    type FundProof = MockProof;
    type TransferProof = MockProof;
    type BurnProof = MockCommitment;
    type SetupInput = ();
    type SetupError = core::convert::Infallible;

    fn setup(_input: &Self::SetupInput) -> Result<Self::Params, Self::SetupError> {
        Ok(())
    }

    fn fund(
        _params: &Self::Params,
        value: u64,
        _rng: &mut impl RngCore,
    ) -> (Self::Commitment, Self::Opening, Self::FundProof) {
        (
            MockCommitment::new(value, 0),
            MockOpening { value, blind: 0 },
            MockProof,
        )
    }

    fn transfer(
        _params: &Self::Params,
        _input_commitment: &Self::Commitment,
        _input_opening: &Self::Opening,
        amount: u64,
        rng: &mut impl RngCore,
    ) -> (Self::Commitment, Self::Opening, Self::TransferProof) {
        let blind = rng.next_u64();
        (
            MockCommitment::new(amount, blind),
            MockOpening {
                value: amount,
                blind,
            },
            MockProof,
        )
    }

    fn burn(
        _params: &Self::Params,
        commitment: &Self::Commitment,
        _opening: &Self::Opening,
        _rng: &mut impl RngCore,
    ) -> Self::BurnProof {
        *commitment
    }

    fn batch_verify(
        _params: &Self::Params,
        txs: &[PrivateTransaction<Self>],
        sender_currents: &[Self::Commitment],
        _rng: &mut impl RngCore,
    ) -> bool {
        let expected_currents = txs
            .iter()
            .filter(|tx| {
                matches!(
                    tx,
                    PrivateTransaction::Transfer { .. } | PrivateTransaction::Burn { .. }
                )
            })
            .count();
        if sender_currents.len() != expected_currents {
            return false;
        }

        let mut currents = sender_currents.iter();
        txs.iter().all(|tx| match tx {
            PrivateTransaction::Fund {
                value,
                fund_commitment,
                ..
            } => *fund_commitment == MockCommitment::new(*value, 0),
            PrivateTransaction::Transfer {
                amount_commitment, ..
            } => currents
                .next()
                .is_some_and(|current| current.value >= amount_commitment.value),
            PrivateTransaction::Burn { value, proof, .. } => currents
                .next()
                .is_some_and(|current| current == proof && proof.value == *value),
        })
    }
}

impl PrivatePaymentBackend for MockPrivatePaymentBackend {
    const NAME: &'static str = "mock";

    fn params() -> &'static Self::Params {
        static PARAMS: OnceLock<()> = OnceLock::new();
        PARAMS.get_or_init(|| ())
    }
}
