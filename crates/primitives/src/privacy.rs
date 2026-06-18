//! Chain-facing private payment backend adapter.
//!
//! Constantinople execution is generic over [`private_payments::Backend`].
//! This module adds the codec and static-parameter requirements needed to store
//! backend commitments/proofs in consensus state and transaction bytes.

use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use private_payments::{Backend, Commitment, WireBackend};
pub use private_payments_mock::{
    MockBackend as MockPrivatePaymentBackend, MockCommitment, MockOpening, MockProof,
};
use std::sync::OnceLock;
use zkpari::payments::{PaymentsParams, ZkPariBackend};

/// Production ZK-Pari backend over BN254.
pub type ZkPariPrivatePaymentBackend = ZkPariBackend<ark_bn254::Bn254>;

/// Backend used by Constantinople's executable chain types.
pub type ChainPrivatePaymentBackend = ZkPariPrivatePaymentBackend;
// pub type ChainPrivatePaymentBackend = MockPrivatePaymentBackend;

/// Backend requirements imposed by Constantinople's wire/state codecs.
pub trait PrivatePaymentBackend: WireBackend {
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

impl PrivatePaymentBackend for MockPrivatePaymentBackend {
    const NAME: &'static str = "mock";

    fn params() -> &'static Self::Params {
        static PARAMS: OnceLock<()> = OnceLock::new();
        PARAMS.get_or_init(|| ())
    }
}

impl PrivatePaymentBackend for ZkPariPrivatePaymentBackend {
    const NAME: &'static str = "zkpari_bn254";

    fn params() -> &'static Self::Params {
        static PARAMS: OnceLock<PaymentsParams<ark_bn254::Bn254>> = OnceLock::new();
        PARAMS.get_or_init(|| {
            <Self as Backend>::setup(&[0u8; 32]).expect("ZK-Pari BN254 setup is infallible")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ZkPariPrivatePaymentBackend;
    use crate::{Account, Payload};
    use commonware_codec::{DecodeExt as _, Encode as _};
    use core::num::NonZeroU64;
    use private_payments::ClientBalance;
    use rand::{SeedableRng as _, rngs::StdRng};

    #[test]
    fn zkpari_backend_payload_and_account_codec_roundtrip() {
        let mut rng = StdRng::from_seed([9u8; 32]);
        let params = <ZkPariPrivatePaymentBackend as super::PrivatePaymentBackend>::params();
        let mut balance = ClientBalance::<ZkPariPrivatePaymentBackend>::empty();
        let (commitment, proof) = balance.fund(7, params, &mut rng);
        let payload = Payload::<ZkPariPrivatePaymentBackend>::PrivateFund {
            value: NonZeroU64::new(7).expect("non-zero"),
            commitment,
            proof,
        };

        assert_eq!(
            Payload::<ZkPariPrivatePaymentBackend>::decode(payload.encode()).expect("decode"),
            payload
        );

        let account = Account::<ZkPariPrivatePaymentBackend>::default();
        assert_eq!(
            Account::<ZkPariPrivatePaymentBackend>::decode(account.encode()).expect("decode"),
            account
        );
    }
}
