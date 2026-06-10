//! Constantinople transaction type and transaction wrappers.

use crate::{
    AccountKey, BalanceCommitment, BurnProof, Sealable, Sealed, TransactionPublicKey,
    TransactionSignature, TransferProof,
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error, FixedSize, Read, ReadExt, Write, types::lazy::Lazy,
};
use commonware_cryptography::{Digest, Hasher, Signer};
use core::num::NonZeroU64;

/// A signed transaction accepted by the canonical block format.
#[derive(Debug, Clone)]
pub struct SignedTransaction<H>
where
    H: Hasher,
{
    inner: Sealed<Transaction<H::Digest>, H>,
    signature: TransactionSignature,
}

impl<H> PartialEq for SignedTransaction<H>
where
    H: Hasher,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.signature == other.signature
    }
}

impl<H> Eq for SignedTransaction<H> where H: Hasher {}

/// A signed transaction whose signature has been accepted by the caller.
pub type VerifiedTransaction<H> = SignedTransaction<H>;

impl<H> SignedTransaction<H>
where
    H: Hasher,
{
    /// Creates a signed transaction without checking the signature.
    pub const fn new_unchecked(
        inner: Sealed<Transaction<H::Digest>, H>,
        signature: TransactionSignature,
    ) -> Self {
        Self { inner, signature }
    }

    /// Returns the inner sealed transaction.
    pub fn into_inner(self) -> Sealed<Transaction<H::Digest>, H> {
        self.inner
    }

    /// Returns a reference to the inner sealed transaction.
    pub const fn inner(&self) -> &Sealed<Transaction<H::Digest>, H> {
        &self.inner
    }

    /// Returns a reference to the transaction.
    pub fn value(&self) -> &Transaction<H::Digest> {
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

impl<H> Write for SignedTransaction<H>
where
    H: Hasher,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.inner.write(buf);
        self.signature.write(buf);
    }
}

impl<H> EncodeSize for SignedTransaction<H>
where
    H: Hasher,
{
    fn encode_size(&self) -> usize {
        self.inner.encode_size() + self.signature.encode_size()
    }
}

impl<H> Read for SignedTransaction<H>
where
    H: Hasher,
{
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let inner = Sealed::<Transaction<H::Digest>, H>::read(buf)?;
        let signature = TransactionSignature::read(buf)?;
        Ok(Self { inner, signature })
    }
}

/// Encoding tag for [`Payload::Transfer`].
const TRANSFER_TAG: u8 = 0;
/// Encoding tag for [`Payload::PrivateTransfer`].
const PRIVATE_TRANSFER_TAG: u8 = 1;
/// Encoding tag for [`Payload::Fund`].
const FUND_TAG: u8 = 2;
/// Encoding tag for [`Payload::Burn`].
const BURN_TAG: u8 = 3;

/// The action performed by a [`Transaction`].
// The private-transfer variant carries a 256-byte proof and is the common
// case under private load; boxing it to shrink the enum would add a heap
// allocation on the hot path for no real benefit (transactions are short-lived
// and moved by value).
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Payload {
    /// A public transfer of `value` tokens to `to`.
    Transfer {
        /// The recipient account key.
        to: AccountKey,
        /// The value to send.
        value: NonZeroU64,
    },
    /// A private transfer of a committed amount to `to`.
    ///
    /// `sender_commitment` declares the sender's current private balance
    /// commitment (the input to this link of the sender's outgoing chain).
    /// The proposer must pack a sender's private-side transactions so each
    /// declared input matches the commitment produced by the previous one.
    PrivateTransfer {
        /// The recipient account key.
        to: AccountKey,
        /// The sender's expected private balance commitment before this
        /// transfer.
        sender_commitment: BalanceCommitment,
        /// Pedersen commitment to the transferred amount.
        amount: BalanceCommitment,
        /// Range proofs for the amount and the sender's remaining balance.
        proof: TransferProof,
    },
    /// Moves `value` tokens from the sender's public balance into its private
    /// balance.
    Fund {
        /// The value to move into the private balance.
        value: NonZeroU64,
        /// The sender's expected private balance commitment before funding.
        sender_commitment: BalanceCommitment,
    },
    /// Moves `value` tokens from the sender's private balance back to its
    /// public balance.
    Burn {
        /// The value to move out of the private balance.
        value: NonZeroU64,
        /// The sender's expected private balance commitment before burning.
        sender_commitment: BalanceCommitment,
        /// Range proof for the sender's remaining private balance.
        proof: BurnProof,
    },
}

impl Payload {
    /// Returns the sender's declared input commitment, if this payload acts on
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

    /// Returns the recipient account key, if this payload has a counterparty.
    pub const fn recipient(&self) -> Option<&AccountKey> {
        match self {
            Self::Transfer { to, .. } | Self::PrivateTransfer { to, .. } => Some(to),
            Self::Fund { .. } | Self::Burn { .. } => None,
        }
    }
}

impl Write for Payload {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Transfer { to, value } => {
                TRANSFER_TAG.write(buf);
                to.write(buf);
                value.get().write(buf);
            }
            Self::PrivateTransfer {
                to,
                sender_commitment,
                amount,
                proof,
            } => {
                PRIVATE_TRANSFER_TAG.write(buf);
                to.write(buf);
                sender_commitment.write(buf);
                amount.write(buf);
                proof.write(buf);
            }
            Self::Fund {
                value,
                sender_commitment,
            } => {
                FUND_TAG.write(buf);
                value.get().write(buf);
                sender_commitment.write(buf);
            }
            Self::Burn {
                value,
                sender_commitment,
                proof,
            } => {
                BURN_TAG.write(buf);
                value.get().write(buf);
                sender_commitment.write(buf);
                proof.write(buf);
            }
        }
    }
}

impl EncodeSize for Payload {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Transfer { .. } => AccountKey::SIZE + u64::SIZE,
                Self::PrivateTransfer { .. } => {
                    AccountKey::SIZE
                        + BalanceCommitment::SIZE
                        + BalanceCommitment::SIZE
                        + TransferProof::SIZE
                }
                Self::Fund { .. } => u64::SIZE + BalanceCommitment::SIZE,
                Self::Burn { .. } => u64::SIZE + BalanceCommitment::SIZE + BurnProof::SIZE,
            }
    }
}

impl Read for Payload {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let tag = u8::read(buf)?;
        match tag {
            TRANSFER_TAG => {
                let to = AccountKey::read(buf)?;
                let value = read_non_zero_value(buf)?;
                Ok(Self::Transfer { to, value })
            }
            PRIVATE_TRANSFER_TAG => Ok(Self::PrivateTransfer {
                to: AccountKey::read(buf)?,
                sender_commitment: BalanceCommitment::read(buf)?,
                amount: BalanceCommitment::read(buf)?,
                proof: TransferProof::read(buf)?,
            }),
            FUND_TAG => {
                let value = read_non_zero_value(buf)?;
                Ok(Self::Fund {
                    value,
                    sender_commitment: BalanceCommitment::read(buf)?,
                })
            }
            BURN_TAG => {
                let value = read_non_zero_value(buf)?;
                Ok(Self::Burn {
                    value,
                    sender_commitment: BalanceCommitment::read(buf)?,
                    proof: BurnProof::read(buf)?,
                })
            }
            _ => Err(Error::Invalid("Payload", "unknown payload tag")),
        }
    }
}

fn read_non_zero_value(buf: &mut impl Buf) -> Result<NonZeroU64, Error> {
    NonZeroU64::new(u64::read(buf)?).ok_or(Error::Invalid("Payload", "value must be non-zero"))
}

/// A transaction on the Constantinople blockchain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Transaction<D: Digest> {
    /// The sender public key, decoded lazily on demand.
    pub sender: Lazy<TransactionPublicKey>,
    /// The action performed by this transaction.
    pub payload: Payload,
    /// The sender nonce.
    pub nonce: u64,
    /// The digest type.
    pub _digest: core::marker::PhantomData<D>,
}

impl<D: Digest> Transaction<D> {
    /// Smallest encoded transaction (a [`Payload::Transfer`]).
    pub const MIN_SIZE: usize =
        TransactionPublicKey::SIZE + u8::SIZE + AccountKey::SIZE + u64::SIZE + u64::SIZE;

    /// Largest encoded transaction (a [`Payload::PrivateTransfer`]).
    pub const MAX_SIZE: usize = TransactionPublicKey::SIZE
        + u8::SIZE
        + AccountKey::SIZE
        + BalanceCommitment::SIZE
        + BalanceCommitment::SIZE
        + TransferProof::SIZE
        + u64::SIZE;

    /// Creates a new public transfer transaction.
    pub fn new(
        sender: TransactionPublicKey,
        to: TransactionPublicKey,
        value: NonZeroU64,
        nonce: u64,
    ) -> Self {
        Self::from_payload(
            sender,
            Payload::Transfer {
                to: AccountKey::from_public_key(&to),
                value,
            },
            nonce,
        )
    }

    /// Creates a transaction from its payload.
    pub fn from_payload(sender: TransactionPublicKey, payload: Payload, nonce: u64) -> Self {
        Self {
            sender: Lazy::new(sender),
            payload,
            nonce,
            _digest: core::marker::PhantomData,
        }
    }

    /// Creates a private transfer transaction.
    ///
    /// `sender_commitment` must be the sender's private balance commitment
    /// immediately before this transfer (the previous link of the sender's
    /// outgoing chain). The amount commitment and proof come from the
    /// client-side prover ([`crate::PrivateBalance`]), which holds the secret
    /// balance and opening.
    pub fn private_transfer(
        sender: TransactionPublicKey,
        to: AccountKey,
        sender_commitment: BalanceCommitment,
        amount: BalanceCommitment,
        proof: TransferProof,
        nonce: u64,
    ) -> Self {
        Self::from_payload(
            sender,
            Payload::PrivateTransfer {
                to,
                sender_commitment,
                amount,
                proof,
            },
            nonce,
        )
    }

    /// Creates a fund transaction moving public balance into the private
    /// balance.
    pub fn fund(
        sender: TransactionPublicKey,
        value: NonZeroU64,
        sender_commitment: BalanceCommitment,
        nonce: u64,
    ) -> Self {
        Self::from_payload(
            sender,
            Payload::Fund {
                value,
                sender_commitment,
            },
            nonce,
        )
    }

    /// Creates a burn transaction moving private balance back to the public
    /// balance.
    ///
    /// The proof comes from the client-side prover
    /// ([`crate::PrivateBalance::burn`]).
    pub fn burn(
        sender: TransactionPublicKey,
        value: NonZeroU64,
        sender_commitment: BalanceCommitment,
        proof: BurnProof,
        nonce: u64,
    ) -> Self {
        Self::from_payload(
            sender,
            Payload::Burn {
                value,
                sender_commitment,
                proof,
            },
            nonce,
        )
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
    ) -> SignedTransaction<H>
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

impl<D: Digest> Write for Transaction<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.sender.write(buf);
        self.payload.write(buf);
        self.nonce.write(buf);
    }
}

impl<D: Digest> EncodeSize for Transaction<D> {
    fn encode_size(&self) -> usize {
        TransactionPublicKey::SIZE + self.payload.encode_size() + u64::SIZE
    }
}

impl<D: Digest> Read for Transaction<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let sender = Lazy::<TransactionPublicKey>::read(buf)?;
        let payload = Payload::read(buf)?;

        Ok(Self {
            sender,
            payload,
            nonce: u64::read(buf)?,
            _digest: core::marker::PhantomData,
        })
    }
}

impl<D: Digest> Sealable for Transaction<D> {
    type SealDigest = D;

    fn seal<H: Hasher<Digest = Self::SealDigest>>(self, hasher: &mut H) -> Sealed<Self, H> {
        let seal = self.hash_slow(hasher);
        Sealed::new_unchecked(self, seal)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl arbitrary::Arbitrary<'_> for Payload {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let to = commonware_cryptography::ed25519::PublicKey::arbitrary(u)?;
        let to = AccountKey::from_public_key(&TransactionPublicKey::ed25519(to));
        let value = NonZeroU64::new(u.int_in_range(1..=u64::MAX)?)
            .expect("arbitrary non-zero value should construct");

        Ok(match u.int_in_range(0..=3)? {
            0 => Self::Transfer { to, value },
            1 => Self::PrivateTransfer {
                to,
                sender_commitment: BalanceCommitment::arbitrary(u)?,
                amount: BalanceCommitment::arbitrary(u)?,
                proof: TransferProof::arbitrary(u)?,
            },
            2 => Self::Fund {
                value,
                sender_commitment: BalanceCommitment::arbitrary(u)?,
            },
            _ => Self::Burn {
                value,
                sender_commitment: BalanceCommitment::arbitrary(u)?,
                proof: BurnProof::arbitrary(u)?,
            },
        })
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<D: Digest> arbitrary::Arbitrary<'_> for Transaction<D> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let sender = commonware_cryptography::ed25519::PublicKey::arbitrary(u)?;
        Ok(Self {
            sender: Lazy::new(TransactionPublicKey::ed25519(sender)),
            payload: Payload::arbitrary(u)?,
            nonce: u.arbitrary()?,
            _digest: core::marker::PhantomData,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use arbitrary::{Arbitrary, unstructured::Unstructured};
    use commonware_codec::{DecodeExt, EncodeSize};
    use commonware_cryptography::{Signer, ed25519, sha256};
    use commonware_math::algebra::Random;
    use core::num::NonZeroU64;
    use rand::{SeedableRng, rngs::StdRng};

    fn test_sender() -> TransactionPublicKey {
        let mut rng = StdRng::from_seed([7u8; 32]);
        TransactionPublicKey::ed25519(ed25519::PrivateKey::random(&mut rng).public_key())
    }

    fn test_account_key() -> AccountKey {
        AccountKey::from_public_key(&test_sender())
    }

    fn all_variants() -> Vec<Transaction<sha256::Digest>> {
        let mut rng = commonware_utils::test_rng();
        let sender = test_sender();
        let value = NonZeroU64::new(12_345).expect("test value should be non-zero");

        let mut balance = crate::PrivateBalance::empty();
        balance.fund(value.get());
        let input = balance.commitment();
        let (amount, transfer_proof) = balance
            .transfer(3, &mut rng)
            .expect("transfer amount is in range");
        let burn_input = balance.commitment();
        let burn_proof = balance.burn(1, &mut rng).expect("burn amount is in range");

        vec![
            Transaction::new(sender.clone(), test_sender(), value, 1),
            Transaction::private_transfer(
                sender.clone(),
                test_account_key(),
                input,
                amount,
                transfer_proof,
                2,
            ),
            Transaction::fund(sender.clone(), value, BalanceCommitment::zero(), 3),
            Transaction::burn(
                sender,
                NonZeroU64::new(1).expect("non-zero"),
                burn_input,
                burn_proof,
                4,
            ),
        ]
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
        use crate::Sealable;

        let tx: Transaction<sha256::Digest> =
            Transaction::arbitrary(&mut Unstructured::new(&[])).unwrap();
        let hasher = &mut sha256::Sha256::default();

        let expected = tx.hash_slow(hasher);
        let sealed = tx.seal(hasher);
        assert_eq!(*sealed.seal(), expected);
    }

    #[test]
    fn transaction_roundtrip_all_variants() {
        for tx in all_variants() {
            let mut buf = Vec::with_capacity(tx.encode_size());
            tx.write(&mut buf);

            let decoded = Transaction::<sha256::Digest>::decode(&mut &buf[..])
                .expect("decoding should succeed");
            assert_eq!(decoded, tx);
        }
    }

    #[test]
    fn transaction_encode_size_matches_written() {
        for tx in all_variants() {
            let expected = tx.encode_size();
            let mut buf = Vec::new();
            tx.write(&mut buf);
            assert_eq!(buf.len(), expected);
        }
    }

    #[test]
    fn transaction_size_bounds_match_variants() {
        let sizes: Vec<usize> = all_variants().iter().map(|tx| tx.encode_size()).collect();

        assert_eq!(
            sizes.iter().min().copied(),
            Some(Transaction::<sha256::Digest>::MIN_SIZE)
        );
        assert_eq!(
            sizes.iter().max().copied(),
            Some(Transaction::<sha256::Digest>::MAX_SIZE)
        );
    }

    #[test]
    fn transaction_zero_value_decode_is_rejected() {
        let sender = test_sender();
        let to = test_account_key();

        let mut buf = Vec::new();
        sender.write(&mut buf);
        0u8.write(&mut buf);
        to.write(&mut buf);
        0u64.write(&mut buf);
        7u64.write(&mut buf);

        let result = Transaction::<sha256::Digest>::decode(&mut &buf[..]);
        assert!(result.is_err(), "zero-value transactions must be rejected");
    }

    #[test]
    fn transaction_unknown_payload_tag_is_rejected() {
        let sender = test_sender();

        let mut buf = Vec::new();
        sender.write(&mut buf);
        u8::MAX.write(&mut buf);
        test_account_key().write(&mut buf);
        1u64.write(&mut buf);
        7u64.write(&mut buf);

        let result = Transaction::<sha256::Digest>::decode(&mut &buf[..]);
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
        0u8.write(&mut buf);
        test_account_key().write(&mut buf);
        1u64.write(&mut buf);
        9u64.write(&mut buf);

        let decoded = Transaction::<sha256::Digest>::decode(&mut &buf[..])
            .expect("decoding should defer sender validation");

        assert!(decoded.sender().is_none());
    }

    #[test]
    fn private_transfer_proof_verifies_from_payload() {
        let mut rng = commonware_utils::test_rng();
        let mut balance = crate::PrivateBalance::empty();
        balance.fund(50);
        let input = balance.commitment();
        let (amount, proof) = balance.transfer(5, &mut rng).expect("transfer in range");

        let tx = Transaction::<sha256::Digest>::private_transfer(
            test_sender(),
            test_account_key(),
            input,
            amount,
            proof,
            0,
        );
        let Payload::PrivateTransfer { proof, .. } = &tx.payload else {
            panic!("expected private transfer payload");
        };

        assert!(proof.verify_transfer(&input, &amount));
        assert!(!proof.verify_transfer(&amount, &input));
    }

    #[test]
    fn burn_proof_verifies_from_payload() {
        let mut rng = commonware_utils::test_rng();
        let mut balance = crate::PrivateBalance::empty();
        balance.fund(50);
        let input = balance.commitment();
        let value = NonZeroU64::new(5).expect("test value should be non-zero");
        let proof = balance.burn(value.get(), &mut rng).expect("burn in range");

        let tx = Transaction::<sha256::Digest>::burn(test_sender(), value, input, proof, 0);
        let Payload::Burn { proof, .. } = &tx.payload else {
            panic!("expected burn payload");
        };

        assert!(proof.verify_burn(&input, value.get()));
        assert!(!proof.verify_burn(&input, value.get() + 1));
    }
}
