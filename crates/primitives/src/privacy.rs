//! Chain-facing private payment backend adapter.
//!
//! Constantinople uses the `commonware-privacy` payments API, while this module
//! owns the chain-specific wire/state requirements and compile-time backend
//! selection for the executable chain configuration.

use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_privacy::payments::{Backend, Commitment};
use std::sync::OnceLock;

#[cfg(feature = "privacy-backend-zkpari")]
pub type ZkPariBn254Backend =
    commonware_privacy::zkpari::payments::codec::UncompressedCheckedBn254Backend;

/// Backend used for local state-database account encoding.
///
/// The zkpari state path uses uncompressed, unchecked points because these bytes
/// are read from authenticated local state rather than directly from clients.
#[cfg(feature = "privacy-backend-zkpari")]
pub type StatePrivatePaymentBackend =
    commonware_privacy::zkpari::payments::codec::UncompressedUncheckedBn254Backend;

/// Backend used by Constantinople's executable chain types.
///
/// The default build uses the monorepo mock backend. Enable
/// `privacy-backend-zkpari` on `constantinople-primitives` to use the ZK-Pari
/// BN254 backend instead.
#[cfg(feature = "privacy-backend-zkpari")]
pub type ChainPrivatePaymentBackend = ZkPariBn254Backend;

/// Backend used by Constantinople's executable chain types.
#[cfg(all(
    not(feature = "privacy-backend-zkpari"),
    feature = "privacy-backend-mock"
))]
pub type ChainPrivatePaymentBackend = commonware_privacy::mocks::MockBackend;

/// Backend used for local state-database account encoding.
#[cfg(all(
    not(feature = "privacy-backend-zkpari"),
    feature = "privacy-backend-mock"
))]
pub type StatePrivatePaymentBackend = commonware_privacy::mocks::MockBackend;

#[cfg(not(any(feature = "privacy-backend-mock", feature = "privacy-backend-zkpari")))]
compile_error!(
    "enable one private payment backend: privacy-backend-mock or privacy-backend-zkpari"
);

#[cfg(feature = "privacy-backend-zkpari")]
const ZKPARI_BN254_SETUP_SEED: [u8; 32] = *b"constantinople-zkpari-bn254-0001";

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

/// Conversion from a decoded transaction backend into the backend used by
/// internal execution/state.
pub trait PrivatePaymentExecutionBackend: PrivatePaymentBackend {
    /// Backend used after transaction decoding has performed any needed checks.
    type ExecutionBackend: PrivatePaymentBackend;

    /// Convert a transaction commitment into the execution representation.
    fn to_execution_commitment(
        commitment: Self::Commitment,
    ) -> <Self::ExecutionBackend as Backend>::Commitment;

    /// Convert a transaction fund proof into the execution representation.
    fn to_execution_fund_proof(
        proof: Self::FundProof,
    ) -> <Self::ExecutionBackend as Backend>::FundProof;

    /// Convert a transaction transfer proof into the execution representation.
    fn to_execution_transfer_proof(
        proof: Self::TransferProof,
    ) -> <Self::ExecutionBackend as Backend>::TransferProof;

    /// Convert a transaction burn proof into the execution representation.
    fn to_execution_burn_proof(
        proof: Self::BurnProof,
    ) -> <Self::ExecutionBackend as Backend>::BurnProof;
}

/// Simulator trapdoor access for trusted benchmarking and load generation.
#[cfg(feature = "privacy-backend-simulator")]
pub trait PrivatePaymentSimulatorBackend: PrivatePaymentBackend {
    /// Toxic-waste trapdoor matching [`PrivatePaymentBackend::params`].
    fn simulator_trapdoor() -> &'static Self::Trapdoor;
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

#[cfg(feature = "privacy-backend-mock")]
impl PrivatePaymentBackend for commonware_privacy::mocks::MockBackend {
    const NAME: &'static str = "mock";

    fn params() -> &'static Self::Params {
        static PARAMS: OnceLock<()> = OnceLock::new();
        PARAMS.get_or_init(|| ())
    }
}

#[cfg(all(
    feature = "privacy-backend-mock",
    feature = "privacy-backend-simulator"
))]
impl PrivatePaymentSimulatorBackend for commonware_privacy::mocks::MockBackend {
    fn simulator_trapdoor() -> &'static Self::Trapdoor {
        static TRAPDOOR: OnceLock<()> = OnceLock::new();
        TRAPDOOR.get_or_init(|| ())
    }
}

#[cfg(feature = "privacy-backend-mock")]
impl PrivatePaymentExecutionBackend for commonware_privacy::mocks::MockBackend {
    type ExecutionBackend = Self;

    fn to_execution_commitment(commitment: Self::Commitment) -> Self::Commitment {
        commitment
    }

    fn to_execution_fund_proof(proof: Self::FundProof) -> Self::FundProof {
        proof
    }

    fn to_execution_transfer_proof(proof: Self::TransferProof) -> Self::TransferProof {
        proof
    }

    fn to_execution_burn_proof(proof: Self::BurnProof) -> Self::BurnProof {
        proof
    }
}

#[cfg(feature = "privacy-backend-zkpari")]
impl PrivatePaymentBackend for ZkPariBn254Backend {
    const NAME: &'static str = "zkpari-bn254";

    fn params() -> &'static Self::Params {
        static PARAMS: OnceLock<<ZkPariBn254Backend as Backend>::Params> = OnceLock::new();
        PARAMS.get_or_init(|| {
            Self::setup(&ZKPARI_BN254_SETUP_SEED).expect("zkpari setup is infallible")
        })
    }
}

#[cfg(all(
    feature = "privacy-backend-zkpari",
    feature = "privacy-backend-simulator"
))]
impl PrivatePaymentSimulatorBackend for ZkPariBn254Backend {
    fn simulator_trapdoor() -> &'static Self::Trapdoor {
        use rand::{SeedableRng as _, rngs::StdRng};

        static TRAPDOOR: OnceLock<<ZkPariBn254Backend as Backend>::Trapdoor> = OnceLock::new();
        TRAPDOOR.get_or_init(|| {
            let mut rng = StdRng::from_seed(ZKPARI_BN254_SETUP_SEED);
            let (_range_pk, _range_vk, trapdoor) = commonware_privacy::zkpari::ZkPari::<
                ark_bn254::Bn254,
            >::keygen_with_trapdoor(&mut rng);
            trapdoor
        })
    }
}

#[cfg(feature = "privacy-backend-zkpari")]
impl PrivatePaymentExecutionBackend for ZkPariBn254Backend {
    type ExecutionBackend = StatePrivatePaymentBackend;

    fn to_execution_commitment(
        commitment: Self::Commitment,
    ) -> <Self::ExecutionBackend as Backend>::Commitment {
        to_state_commitment(commitment)
    }

    fn to_execution_fund_proof(
        proof: Self::FundProof,
    ) -> <Self::ExecutionBackend as Backend>::FundProof {
        to_state_fund_proof(proof)
    }

    fn to_execution_transfer_proof(
        proof: Self::TransferProof,
    ) -> <Self::ExecutionBackend as Backend>::TransferProof {
        to_state_transfer_proof(proof)
    }

    fn to_execution_burn_proof(
        proof: Self::BurnProof,
    ) -> <Self::ExecutionBackend as Backend>::BurnProof {
        to_state_burn_proof(proof)
    }
}

#[cfg(feature = "privacy-backend-zkpari")]
impl PrivatePaymentBackend for StatePrivatePaymentBackend {
    const NAME: &'static str = "zkpari-bn254-state";

    fn params() -> &'static Self::Params {
        static PARAMS: OnceLock<<StatePrivatePaymentBackend as Backend>::Params> = OnceLock::new();
        PARAMS.get_or_init(|| {
            Self::setup(&ZKPARI_BN254_SETUP_SEED).expect("zkpari setup is infallible")
        })
    }
}

/// Convert a transaction-checked commitment into the internal state form.
#[cfg(all(
    not(feature = "privacy-backend-zkpari"),
    feature = "privacy-backend-mock"
))]
pub const fn to_state_commitment(
    commitment: <ChainPrivatePaymentBackend as Backend>::Commitment,
) -> <StatePrivatePaymentBackend as Backend>::Commitment {
    commitment
}

/// Convert a transaction-checked fund proof into the internal state form.
#[cfg(all(
    not(feature = "privacy-backend-zkpari"),
    feature = "privacy-backend-mock"
))]
pub const fn to_state_fund_proof(
    proof: <ChainPrivatePaymentBackend as Backend>::FundProof,
) -> <StatePrivatePaymentBackend as Backend>::FundProof {
    proof
}

/// Convert a transaction-checked transfer proof into the internal state form.
#[cfg(all(
    not(feature = "privacy-backend-zkpari"),
    feature = "privacy-backend-mock"
))]
pub const fn to_state_transfer_proof(
    proof: <ChainPrivatePaymentBackend as Backend>::TransferProof,
) -> <StatePrivatePaymentBackend as Backend>::TransferProof {
    proof
}

/// Convert a transaction-checked burn proof into the internal state form.
#[cfg(all(
    not(feature = "privacy-backend-zkpari"),
    feature = "privacy-backend-mock"
))]
pub const fn to_state_burn_proof(
    proof: <ChainPrivatePaymentBackend as Backend>::BurnProof,
) -> <StatePrivatePaymentBackend as Backend>::BurnProof {
    proof
}

/// Convert a transaction-checked commitment into the internal state form.
#[cfg(feature = "privacy-backend-zkpari")]
pub const fn to_state_commitment(
    commitment: <ChainPrivatePaymentBackend as Backend>::Commitment,
) -> <StatePrivatePaymentBackend as Backend>::Commitment {
    use commonware_privacy::zkpari::payments::{
        PaymentCommitment,
        codec::{UncompressedChecked, UncompressedUnchecked},
    };

    let commitment: UncompressedChecked<PaymentCommitment<ark_bn254::Bn254>> = commitment;
    UncompressedUnchecked(commitment.0)
}

/// Convert a transaction-checked fund proof into the internal state form.
#[cfg(feature = "privacy-backend-zkpari")]
pub const fn to_state_fund_proof(
    proof: <ChainPrivatePaymentBackend as Backend>::FundProof,
) -> <StatePrivatePaymentBackend as Backend>::FundProof {
    proof
}

/// Convert a transaction-checked transfer proof into the internal state form.
#[cfg(feature = "privacy-backend-zkpari")]
pub const fn to_state_transfer_proof(
    proof: <ChainPrivatePaymentBackend as Backend>::TransferProof,
) -> <StatePrivatePaymentBackend as Backend>::TransferProof {
    use commonware_privacy::zkpari::payments::{
        TransferProof,
        codec::{UncompressedChecked, UncompressedUnchecked},
    };

    let proof: UncompressedChecked<TransferProof<ark_bn254::Bn254>> = proof;
    UncompressedUnchecked(proof.0)
}

/// Convert a transaction-checked burn proof into the internal state form.
#[cfg(feature = "privacy-backend-zkpari")]
pub const fn to_state_burn_proof(
    proof: <ChainPrivatePaymentBackend as Backend>::BurnProof,
) -> <StatePrivatePaymentBackend as Backend>::BurnProof {
    use commonware_privacy::zkpari::{
        payments::codec::{UncompressedChecked, UncompressedUnchecked},
        range::RangeProof,
    };

    let proof: UncompressedChecked<RangeProof<ark_bn254::Bn254>> = proof;
    UncompressedUnchecked(proof.0)
}

#[cfg(test)]
mod tests {
    use crate::{Account, Payload};
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_privacy::{
        mocks::{MockBackend as Backend, MockCommitment, MockProof},
        payments::Backend as _,
    };
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
            &[(10, MockCommitment::new(11, 0), MockProof)],
            &[],
            &[],
            &mut rng,
        ));
    }
}
