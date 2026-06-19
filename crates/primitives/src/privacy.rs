//! Chain-facing private payment backend adapter.
//!
//! Constantinople uses the `commonware-privacy` payments API, while this module
//! owns the chain-specific wire/state requirements and the local mock backend
//! used by the current executable chain configuration.

use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_privacy::payments::{Backend, Commitment, Opening};
use rand_core::CryptoRngCore;
use std::sync::OnceLock;

/// Backend used by Constantinople's executable chain types.
pub type ChainPrivatePaymentBackend = MockPrivatePaymentBackend;

/// Backend requirements imposed by Constantinople's wire/state codecs.
pub trait PrivatePaymentBackend:
    Clone
    + Eq
    + core::hash::Hash
    + Send
    + Sync
    + 'static
    + Backend<
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
    >
{
    /// Low-cardinality backend name for tracing.
    const NAME: &'static str;

    /// Verifier/prover parameters used by chain execution.
    fn params() -> &'static Self::Params;
}

/// Stored private commitment state for one Constantinople account.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PrivateAccount<B: PrivatePaymentBackend = ChainPrivatePaymentBackend>
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

/// Non-cryptographic backend for tests and local load generation.
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

    /// Mock blinding component.
    pub const fn blind(&self) -> u64 {
        self.blind
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
        Ok(Self::new(u64::read(buf)?, u64::read(buf)?))
    }
}

/// Mock opening `(value, blinding)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MockOpening {
    value: u64,
    blind: u64,
}

impl MockOpening {
    /// Construct a mock opening.
    pub const fn new(value: u64, blind: u64) -> Self {
        Self { value, blind }
    }

    /// Opened value.
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// Mock blinding component.
    pub const fn blind(&self) -> u64 {
        self.blind
    }
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

impl FixedSize for MockOpening {
    const SIZE: usize = u64::SIZE + u64::SIZE;
}

impl Write for MockOpening {
    fn write(&self, buf: &mut impl BufMut) {
        self.value.write(buf);
        self.blind.write(buf);
    }
}

impl Read for MockOpening {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self::new(u64::read(buf)?, u64::read(buf)?))
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

    fn commit_public(_params: &Self::Params, value: u64) -> (Self::Commitment, Self::Opening) {
        (MockCommitment::new(value, 0), MockOpening::new(value, 0))
    }

    fn fund(
        _params: &Self::Params,
        value: u64,
        _rng: &mut impl CryptoRngCore,
    ) -> (Self::Commitment, Self::Opening, Self::FundProof) {
        (
            MockCommitment::new(value, 0),
            MockOpening::new(value, 0),
            MockProof,
        )
    }

    fn transfer(
        _params: &Self::Params,
        _input_commitment: &Self::Commitment,
        _input_opening: &Self::Opening,
        amount: u64,
        rng: &mut impl CryptoRngCore,
    ) -> (Self::Commitment, Self::Opening, Self::TransferProof) {
        let blind = rng.next_u64();
        (
            MockCommitment::new(amount, blind),
            MockOpening::new(amount, blind),
            MockProof,
        )
    }

    fn burn(
        _params: &Self::Params,
        commitment: &Self::Commitment,
        opening: &Self::Opening,
        amount: u64,
        _rng: &mut impl CryptoRngCore,
    ) -> Self::BurnProof {
        assert!(amount <= opening.value());
        assert!(amount <= commitment.value());
        MockCommitment::new(amount, 0)
    }

    fn batch_verify(
        _params: &Self::Params,
        funds: &[(u64, Self::Commitment, Self::FundProof)],
        transfers: &[(Self::Commitment, Self::Commitment, Self::TransferProof)],
        burns: &[(Self::Commitment, u64, Self::BurnProof)],
        _rng: &mut impl CryptoRngCore,
    ) -> bool {
        funds
            .iter()
            .all(|(value, commitment, _)| *commitment == MockCommitment::new(*value, 0))
            && transfers
                .iter()
                .all(|(current, amount, _)| current.value >= amount.value)
            && burns.iter().all(|(current, value, proof)| {
                current.value >= *value && *proof == MockCommitment::new(*value, 0)
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

#[cfg(test)]
mod tests {
    use super::{MockCommitment, MockPrivatePaymentBackend as Backend};
    use crate::{Account, Payload};
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_privacy::payments::Backend as _;
    use core::num::NonZeroU64;
    use rand::{SeedableRng as _, rngs::StdRng};

    #[test]
    fn mock_backend_payload_and_account_codec_roundtrip() {
        let mut rng = StdRng::from_seed([9u8; 32]);
        let params = <Backend as super::PrivatePaymentBackend>::params();
        let (commitment, _, proof) = Backend::fund(params, 7, &mut rng);
        let payload = Payload::<Backend>::PrivateFund {
            value: NonZeroU64::new(7).expect("non-zero"),
            commitment,
            proof,
        };

        assert_eq!(
            Payload::<Backend>::decode(payload.encode()).expect("decode"),
            payload
        );

        let account = Account::<Backend>::default();
        assert_eq!(
            Account::<Backend>::decode(account.encode()).expect("decode"),
            account
        );
    }

    #[test]
    fn mock_backend_rejects_invalid_fund_commitment() {
        let mut rng = StdRng::from_seed([7u8; 32]);
        assert!(!Backend::batch_verify(
            &(),
            &[(10, MockCommitment::new(11, 0), super::MockProof)],
            &[],
            &[],
            &mut rng,
        ));
    }
}
