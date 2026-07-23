//! Constantinople transaction type and transaction wrappers.

use crate::{
    AccountKey, ChainPrivatePaymentBackend, PrivatePaymentBackend, Sealable, Sealed,
    TransactionPublicKey, TransactionSignature,
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error, FixedSize, Read, ReadExt, Write, types::lazy::Lazy,
};
use commonware_cryptography::{Digest, Hasher, Signer};
use core::num::NonZeroU64;

/// Encoding tag for a public transfer.
pub const PUBLIC_TRANSFER_TAG: u8 = 0;
/// Encoding tag for a private fund.
pub const PRIVATE_FUND_TAG: u8 = 1;
/// Encoding tag for a private transfer.
pub const PRIVATE_TRANSFER_TAG: u8 = 2;
/// Encoding tag for a private burn.
pub const PRIVATE_BURN_TAG: u8 = 3;
/// Encoding tag for an explicit private rollover.
pub const PRIVATE_ROLLOVER_TAG: u8 = 4;

/// A signed transaction accepted by the canonical block format.
#[derive(Debug, Clone)]
pub struct SignedTransaction<H, B = ChainPrivatePaymentBackend>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    inner: Sealed<Transaction<H::Digest, B>, H>,
    signature: TransactionSignature,
}

impl<H, B> PartialEq for SignedTransaction<H, B>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.signature == other.signature
    }
}

impl<H, B> Eq for SignedTransaction<H, B>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
}

/// A signed transaction whose signature has been accepted by the caller.
pub type VerifiedTransaction<H, B = ChainPrivatePaymentBackend> = SignedTransaction<H, B>;

impl<H, B> SignedTransaction<H, B>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    /// Creates a signed transaction without checking the signature.
    pub const fn new_unchecked(
        inner: Sealed<Transaction<H::Digest, B>, H>,
        signature: TransactionSignature,
    ) -> Self {
        Self { inner, signature }
    }

    /// Returns the inner sealed transaction.
    pub fn into_inner(self) -> Sealed<Transaction<H::Digest, B>, H> {
        self.inner
    }

    /// Returns a reference to the inner sealed transaction.
    pub const fn inner(&self) -> &Sealed<Transaction<H::Digest, B>, H> {
        &self.inner
    }

    /// Returns a reference to the transaction.
    pub fn value(&self) -> &Transaction<H::Digest, B> {
        self.inner()
    }

    /// Returns the transaction digest that was signed.
    pub const fn message_digest(&self) -> &H::Digest {
        self.inner.seal()
    }

    /// Returns the decoded transaction signature.
    pub const fn signature(&self) -> &TransactionSignature {
        &self.signature
    }
}

impl<H, B> Write for SignedTransaction<H, B>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.inner.write(buf);
        self.signature.write(buf);
    }
}

impl<H, B> EncodeSize for SignedTransaction<H, B>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    fn encode_size(&self) -> usize {
        self.inner.encode_size() + self.signature.encode_size()
    }
}

// Encoding borrowed transactions lets collections like `Vec<&SignedTransaction>`
// encode without cloning each transaction first.
impl<H, B> Write for &SignedTransaction<H, B>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    fn write(&self, buf: &mut impl BufMut) {
        (**self).write(buf);
    }
}

impl<H, B> EncodeSize for &SignedTransaction<H, B>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    fn encode_size(&self) -> usize {
        (**self).encode_size()
    }
}

impl<H, B> Read for SignedTransaction<H, B>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let inner = Sealed::<Transaction<H::Digest, B>, H>::read(buf)?;
        let signature = TransactionSignature::read(buf)?;
        Ok(Self { inner, signature })
    }
}

/// The action performed by a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Payload<B: PrivatePaymentBackend = ChainPrivatePaymentBackend> {
    /// A public transfer.
    PublicTransfer { to: AccountKey, value: NonZeroU64 },
    /// Move public value into private pending balance.
    PrivateFund {
        value: NonZeroU64,
        commitment: B::Commitment,
        proof: B::FundProof,
    },
    /// Confidential private transfer.
    PrivateTransfer {
        to: AccountKey,
        amount: B::Commitment,
        proof: B::TransferProof,
    },
    /// Fully de-shield private current balance.
    PrivateBurn {
        value: NonZeroU64,
        proof: B::BurnProof,
    },
    /// Explicitly fold pending private balance into current.
    PrivateRollover,
}

impl<B> Payload<B>
where
    B: PrivatePaymentBackend,
{
    /// Minimum encoded payload size.
    pub const MIN_SIZE: usize = u8::SIZE;
    /// Maximum encoded payload size.
    pub const MAX_SIZE: usize = u8::SIZE
        + max_usize(
            AccountKey::SIZE + u64::SIZE,
            max_usize(
                u64::SIZE + B::Commitment::SIZE + B::FundProof::SIZE,
                max_usize(
                    AccountKey::SIZE + B::Commitment::SIZE + B::TransferProof::SIZE,
                    u64::SIZE + B::BurnProof::SIZE,
                ),
            ),
        );

    /// Recipient account if this payload has one.
    pub const fn recipient(&self) -> Option<&AccountKey> {
        match self {
            Self::PublicTransfer { to, .. } | Self::PrivateTransfer { to, .. } => Some(to),
            Self::PrivateFund { .. } | Self::PrivateBurn { .. } | Self::PrivateRollover => None,
        }
    }
}

const fn max_usize(left: usize, right: usize) -> usize {
    if left > right { left } else { right }
}

impl<B> Write for Payload<B>
where
    B: PrivatePaymentBackend,
{
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::PublicTransfer { to, value } => {
                PUBLIC_TRANSFER_TAG.write(buf);
                to.write(buf);
                value.get().write(buf);
            }
            Self::PrivateFund {
                value,
                commitment,
                proof,
            } => {
                PRIVATE_FUND_TAG.write(buf);
                value.get().write(buf);
                commitment.write(buf);
                proof.write(buf);
            }
            Self::PrivateTransfer { to, amount, proof } => {
                PRIVATE_TRANSFER_TAG.write(buf);
                to.write(buf);
                amount.write(buf);
                proof.write(buf);
            }
            Self::PrivateBurn { value, proof } => {
                PRIVATE_BURN_TAG.write(buf);
                value.get().write(buf);
                proof.write(buf);
            }
            Self::PrivateRollover => PRIVATE_ROLLOVER_TAG.write(buf),
        }
    }
}

impl<B> EncodeSize for Payload<B>
where
    B: PrivatePaymentBackend,
{
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::PublicTransfer { .. } => AccountKey::SIZE + u64::SIZE,
                Self::PrivateFund { .. } => u64::SIZE + B::Commitment::SIZE + B::FundProof::SIZE,
                Self::PrivateTransfer { .. } => {
                    AccountKey::SIZE + B::Commitment::SIZE + B::TransferProof::SIZE
                }
                Self::PrivateBurn { .. } => u64::SIZE + B::BurnProof::SIZE,
                Self::PrivateRollover => 0,
            }
    }
}

impl<B> Read for Payload<B>
where
    B: PrivatePaymentBackend,
{
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            PUBLIC_TRANSFER_TAG => Ok(Self::PublicTransfer {
                to: AccountKey::read(buf)?,
                value: read_non_zero_value(buf)?,
            }),
            PRIVATE_FUND_TAG => Ok(Self::PrivateFund {
                value: read_non_zero_value(buf)?,
                commitment: B::Commitment::read(buf)?,
                proof: B::FundProof::read(buf)?,
            }),
            PRIVATE_TRANSFER_TAG => Ok(Self::PrivateTransfer {
                to: AccountKey::read(buf)?,
                amount: B::Commitment::read(buf)?,
                proof: B::TransferProof::read(buf)?,
            }),
            PRIVATE_BURN_TAG => Ok(Self::PrivateBurn {
                value: read_non_zero_value(buf)?,
                proof: B::BurnProof::read(buf)?,
            }),
            PRIVATE_ROLLOVER_TAG => Ok(Self::PrivateRollover),
            _ => Err(Error::Invalid("Payload", "unknown payload tag")),
        }
    }
}

fn read_non_zero_value(buf: &mut impl Buf) -> Result<NonZeroU64, Error> {
    NonZeroU64::new(u64::read(buf)?).ok_or(Error::Invalid("Payload", "value must be non-zero"))
}

/// A transaction on the Constantinople blockchain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Transaction<D: Digest, B = ChainPrivatePaymentBackend>
where
    B: PrivatePaymentBackend,
{
    /// The sender public key, decoded lazily on demand.
    pub sender: Lazy<TransactionPublicKey>,
    /// The action performed by the transaction.
    pub payload: Payload<B>,
    /// The sender nonce.
    pub nonce: u64,
    /// The digest type.
    pub _digest: core::marker::PhantomData<D>,
}

impl<D, B> Transaction<D, B>
where
    D: Digest,
    B: PrivatePaymentBackend,
{
    /// Smallest encoded transaction.
    pub const MIN_SIZE: usize = TransactionPublicKey::SIZE + Payload::<B>::MIN_SIZE + u64::SIZE;
    /// Largest encoded transaction.
    pub const MAX_SIZE: usize = TransactionPublicKey::SIZE + Payload::<B>::MAX_SIZE + u64::SIZE;

    /// Creates a new public transfer transaction.
    pub fn new(
        sender: TransactionPublicKey,
        to: TransactionPublicKey,
        value: NonZeroU64,
        nonce: u64,
    ) -> Self {
        Self::from_payload(
            sender,
            Payload::PublicTransfer {
                to: AccountKey::from_public_key(&to),
                value,
            },
            nonce,
        )
    }

    /// Creates a transaction from its payload.
    pub fn from_payload(sender: TransactionPublicKey, payload: Payload<B>, nonce: u64) -> Self {
        Self {
            sender: Lazy::new(sender),
            payload,
            nonce,
            _digest: core::marker::PhantomData,
        }
    }

    /// Returns the decoded sender public key.
    pub fn sender(&self) -> Option<&TransactionPublicKey> {
        self.sender.get()
    }

    /// Returns the lazily decoded sender public key.
    pub const fn sender_lazy(&self) -> &Lazy<TransactionPublicKey> {
        &self.sender
    }

    /// Hashes the consensus-encoded transaction to produce a [`Digest`].
    ///
    /// If you want to cache the hash, consider using the [`Sealable`] trait.
    ///
    /// [`Digest`]: Digest
    pub fn hash_slow<H: Hasher>(&self, hasher: &mut H) -> H::Digest {
        hasher.update(&self.encode());
        hasher.finalize()
    }

    /// Seals and signs this transaction with a supported transaction signer.
    pub fn seal_and_sign<H, S>(
        self,
        signer: &S,
        namespace: &[u8],
        hasher: &mut H,
    ) -> SignedTransaction<H, B>
    where
        H: Hasher<Digest = D>,
        S: Signer,
        TransactionSignature: From<S::Signature>,
    {
        let sealed = self.seal(hasher);
        let signature = TransactionSignature::from(signer.sign(namespace, sealed.seal().as_ref()));
        SignedTransaction::new_unchecked(sealed, signature)
    }
}

impl<D, B> Write for Transaction<D, B>
where
    D: Digest,
    B: PrivatePaymentBackend,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.sender.write(buf);
        self.payload.write(buf);
        self.nonce.write(buf);
    }
}

impl<D, B> EncodeSize for Transaction<D, B>
where
    D: Digest,
    B: PrivatePaymentBackend,
{
    fn encode_size(&self) -> usize {
        TransactionPublicKey::SIZE + self.payload.encode_size() + u64::SIZE
    }
}

impl<D, B> Read for Transaction<D, B>
where
    D: Digest,
    B: PrivatePaymentBackend,
{
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            sender: Lazy::<TransactionPublicKey>::read(buf)?,
            payload: Payload::read(buf)?,
            nonce: u64::read(buf)?,
            _digest: core::marker::PhantomData,
        })
    }
}

impl<D, B> Sealable for Transaction<D, B>
where
    D: Digest,
    B: PrivatePaymentBackend,
{
    type SealDigest = D;

    fn seal<H: Hasher<Digest = Self::SealDigest>>(self, hasher: &mut H) -> Sealed<Self, H> {
        let seal = self.hash_slow(hasher);
        Sealed::new_unchecked(self, seal)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<D, B> arbitrary::Arbitrary<'_> for Transaction<D, B>
where
    D: Digest,
    B: PrivatePaymentBackend,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let sender = commonware_cryptography::ed25519::PublicKey::arbitrary(u)?;
        let to = commonware_cryptography::ed25519::PublicKey::arbitrary(u)?;
        Ok(Self {
            sender: Lazy::new(TransactionPublicKey::ed25519(sender)),
            payload: Payload::PublicTransfer {
                to: AccountKey::from_public_key(&TransactionPublicKey::ed25519(to)),
                value: NonZeroU64::new(u.int_in_range(1..=u64::MAX)?)
                    .expect("arbitrary non-zero value should construct"),
            },
            nonce: u.arbitrary()?,
            _digest: core::marker::PhantomData,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Sealable;
    use arbitrary::{Arbitrary, unstructured::Unstructured};
    use commonware_codec::{DecodeExt, EncodeSize};
    use commonware_cryptography::{Signer, ed25519, sha256};
    use commonware_math::algebra::Random;
    use commonware_privacy::payments::Backend as _;
    use core::num::NonZeroU64;
    use rand::{SeedableRng, rngs::StdRng};

    const NAMESPACE: &[u8] = b"test namespace";

    fn test_sender() -> TransactionPublicKey {
        let mut rng = StdRng::from_seed([7u8; 32]);
        TransactionPublicKey::ed25519(ed25519::PrivateKey::random(&mut rng).public_key())
    }

    /// Seals and signs `payload` from a deterministic ed25519 sender.
    fn sign_payload(payload: Payload, nonce: u64) -> SignedTransaction<sha256::Sha256> {
        let mut rng = StdRng::from_seed([21u8; 32]);
        let signer = ed25519::PrivateKey::random(&mut rng);
        let sender = TransactionPublicKey::ed25519(signer.public_key());
        Transaction::from_payload(sender, payload, nonce).seal_and_sign(
            &signer,
            NAMESPACE,
            &mut sha256::Sha256::default(),
        )
    }

    /// Asserts a signed transaction carrying `payload` decodes back to equal
    /// fields and re-encodes to the exact original bytes.
    fn assert_signed_payload_roundtrip(payload: Payload, nonce: u64) {
        let signed = sign_payload(payload, nonce);

        let encoded = signed.encode();
        let decoded = SignedTransaction::<sha256::Sha256>::decode(&mut &encoded[..])
            .expect("decoding should succeed");

        assert_eq!(
            decoded, signed,
            "decoded signed transaction should match the original"
        );
        assert_eq!(decoded.value().payload, signed.value().payload);
        assert_eq!(decoded.value().nonce, signed.value().nonce);
        assert_eq!(decoded.value().sender(), signed.value().sender());
        assert_eq!(decoded.signature(), signed.signature());
        assert_eq!(
            decoded.encode(),
            encoded,
            "re-encoding must reproduce the original bytes"
        );
    }

    #[test]
    fn test_roundtrip_transaction_consensus() {
        let reference_tx: Transaction<sha256::Digest> =
            Transaction::arbitrary(&mut Unstructured::new(&[])).unwrap();

        let mut encoded = Vec::with_capacity(reference_tx.encode_size());
        reference_tx.write(&mut encoded);

        let decoded = Transaction::<sha256::Digest>::decode(&mut &encoded[..])
            .expect("decoding should succeed");

        assert_eq!(
            decoded, reference_tx,
            "Decoded transaction should match the original"
        );
    }

    #[test]
    fn transaction_hash_slow_deterministic() {
        let tx: Transaction<sha256::Digest> =
            Transaction::arbitrary(&mut Unstructured::new(&[])).unwrap();
        let hasher = &mut sha256::Sha256::default();

        let h1 = tx.hash_slow(hasher);
        let h2 = tx.hash_slow(hasher);
        assert_eq!(h1, h2, "hash_slow should be deterministic");
    }

    #[test]
    fn transaction_seal_matches_hash_slow() {
        let tx: Transaction<sha256::Digest> =
            Transaction::arbitrary(&mut Unstructured::new(&[])).unwrap();
        let hasher = &mut sha256::Sha256::default();

        let expected = tx.hash_slow(hasher);
        let sealed = tx.seal(hasher);
        assert_eq!(*sealed.seal(), expected);
    }

    #[test]
    fn transaction_roundtrip() {
        let tx = Transaction::<sha256::Digest>::new(
            test_sender(),
            test_sender(),
            NonZeroU64::new(12_345).expect("test value should be non-zero"),
            1,
        );

        let mut buf = Vec::with_capacity(tx.encode_size());
        tx.write(&mut buf);

        let decoded =
            Transaction::<sha256::Digest>::decode(&mut &buf[..]).expect("decoding should succeed");
        assert_eq!(decoded, tx);
    }

    #[test]
    fn transaction_encode_size_matches_written() {
        let tx = Transaction::<sha256::Digest>::new(
            test_sender(),
            test_sender(),
            NonZeroU64::new(u64::MAX).expect("max value should be non-zero"),
            u64::MAX,
        );

        let expected = tx.encode_size();
        let mut buf = Vec::new();
        tx.write(&mut buf);
        assert_eq!(buf.len(), expected);
    }

    #[test]
    fn transaction_zero_value_decode_is_rejected() {
        let sender = test_sender();
        let to = AccountKey::from_public_key(&test_sender());

        let mut buf = Vec::new();
        sender.write(&mut buf);
        PUBLIC_TRANSFER_TAG.write(&mut buf);
        to.write(&mut buf);
        0u64.write(&mut buf);
        7u64.write(&mut buf);

        let result = Transaction::<sha256::Digest>::decode(&mut &buf[..]);
        assert!(result.is_err(), "zero-value transactions must be rejected");
    }

    #[test]
    fn payload_rollover_is_min_size() {
        let payload: Payload = Payload::PrivateRollover;
        assert_eq!(
            payload.encode_size(),
            Payload::<crate::ChainPrivatePaymentBackend>::MIN_SIZE
        );

        let decoded =
            Payload::<crate::ChainPrivatePaymentBackend>::decode(&mut &payload.encode()[..])
                .expect("rollover roundtrips");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn payload_unknown_tag_is_rejected() {
        let buf = [200u8];
        let result = Payload::<crate::ChainPrivatePaymentBackend>::decode(&mut &buf[..]);
        assert!(result.is_err(), "unknown payload tags must be rejected");
    }

    #[test]
    fn transaction_decode_defers_sender_validation() {
        let invalid_sender = (0u8..=u8::MAX)
            .flat_map(|first| (0u8..=u8::MAX).map(move |last| (first, last)))
            .find_map(|(first, last)| {
                let mut candidate = [0; TransactionPublicKey::SIZE];
                candidate[0] = 0;
                candidate[1] = first;
                candidate[TransactionPublicKey::SIZE - 1] = last;

                TransactionPublicKey::decode(&mut &candidate[..])
                    .is_err()
                    .then_some(candidate)
            })
            .expect("test should find invalid sender bytes");

        let mut buf = Vec::new();
        invalid_sender.write(&mut buf);
        PUBLIC_TRANSFER_TAG.write(&mut buf);
        AccountKey::from_public_key(&test_sender()).write(&mut buf);
        1u64.write(&mut buf);
        9u64.write(&mut buf);

        let decoded = Transaction::<sha256::Digest>::decode(&mut &buf[..])
            .expect("decoding should defer sender validation");

        assert!(decoded.sender().is_none());
    }

    // -----------------------------------------------------------------------
    // Proof-bearing payload variants, constructed with the configured chain
    // backend (mock under default features, real zkpari BN254 under
    // --all-features) so commitments and proofs are real wire values.
    // -----------------------------------------------------------------------

    #[test]
    fn signed_private_fund_roundtrip() {
        let params = ChainPrivatePaymentBackend::params();
        let mut rng = StdRng::from_seed([22u8; 32]);
        let (commitment, _opening, proof) = ChainPrivatePaymentBackend::fund(params, 9, &mut rng);

        assert_signed_payload_roundtrip(
            Payload::PrivateFund {
                value: NonZeroU64::new(9).expect("test value should be non-zero"),
                commitment,
                proof,
            },
            3,
        );
    }

    #[test]
    fn signed_private_transfer_roundtrip() {
        let params = ChainPrivatePaymentBackend::params();
        let mut rng = StdRng::from_seed([23u8; 32]);
        // Transfer proofs bind to the sender's current commitment, so derive
        // the spend from a funded commitment whose opening is known.
        let (current, current_opening, _proof) =
            ChainPrivatePaymentBackend::fund(params, 7, &mut rng);
        let (amount, _amount_opening, proof) =
            ChainPrivatePaymentBackend::transfer(params, &current, &current_opening, 3, &mut rng);

        assert_signed_payload_roundtrip(
            Payload::PrivateTransfer {
                to: AccountKey::from_public_key(&test_sender()),
                amount,
                proof,
            },
            4,
        );
    }

    #[test]
    fn signed_private_burn_roundtrip() {
        let params = ChainPrivatePaymentBackend::params();
        let mut rng = StdRng::from_seed([24u8; 32]);
        let (current, current_opening, _proof) =
            ChainPrivatePaymentBackend::fund(params, 7, &mut rng);
        let proof =
            ChainPrivatePaymentBackend::burn(params, &current, &current_opening, 4, &mut rng);

        assert_signed_payload_roundtrip(
            Payload::PrivateBurn {
                value: NonZeroU64::new(4).expect("test value should be non-zero"),
                proof,
            },
            5,
        );
    }

    #[test]
    fn signed_private_transfer_truncated_decode_is_rejected() {
        let params = ChainPrivatePaymentBackend::params();
        let mut rng = StdRng::from_seed([25u8; 32]);
        let (current, current_opening, _proof) =
            ChainPrivatePaymentBackend::fund(params, 7, &mut rng);
        let (amount, _amount_opening, proof) =
            ChainPrivatePaymentBackend::transfer(params, &current, &current_opening, 2, &mut rng);

        let signed = sign_payload(
            Payload::PrivateTransfer {
                to: AccountKey::from_public_key(&test_sender()),
                amount,
                proof,
            },
            6,
        );
        let encoded = signed.encode();

        for len in 0..encoded.len() {
            assert!(
                SignedTransaction::<sha256::Sha256>::decode(&mut &encoded[..len]).is_err(),
                "decoding a transaction truncated to {len} bytes must fail"
            );
        }
    }
}
