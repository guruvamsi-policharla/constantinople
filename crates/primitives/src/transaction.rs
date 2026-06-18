//! Constantinople transaction type and transaction wrappers.

use crate::{
    AccountKey, MockPrivatePaymentBackend, PrivatePaymentBackend, Sealable, Sealed,
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
pub struct SignedTransaction<H, B = MockPrivatePaymentBackend>
where
    H: Hasher,
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
    inner: Sealed<Transaction<H::Digest, B>, H>,
    signature: TransactionSignature,
}

impl<H, B> PartialEq for SignedTransaction<H, B>
where
    H: Hasher,
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
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.signature == other.signature
    }
}

impl<H, B> Eq for SignedTransaction<H, B>
where
    H: Hasher,
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
}

/// A signed transaction whose signature has been accepted by the caller.
pub type VerifiedTransaction<H, B = MockPrivatePaymentBackend> = SignedTransaction<H, B>;

impl<H, B> SignedTransaction<H, B>
where
    H: Hasher,
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
        self.inner.write(buf);
        self.signature.write(buf);
    }
}

impl<H, B> EncodeSize for SignedTransaction<H, B>
where
    H: Hasher,
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
    fn encode_size(&self) -> usize {
        self.inner.encode_size() + self.signature.encode_size()
    }
}

impl<H, B> Read for SignedTransaction<H, B>
where
    H: Hasher,
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

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let inner = Sealed::<Transaction<H::Digest, B>, H>::read(buf)?;
        let signature = TransactionSignature::read(buf)?;
        Ok(Self { inner, signature })
    }
}

/// The action performed by a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Payload<B: PrivatePaymentBackend = MockPrivatePaymentBackend>
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
pub struct Transaction<D: Digest, B = MockPrivatePaymentBackend>
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
        self.sender.write(buf);
        self.payload.write(buf);
        self.nonce.write(buf);
    }
}

impl<D, B> EncodeSize for Transaction<D, B>
where
    D: Digest,
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
    fn encode_size(&self) -> usize {
        TransactionPublicKey::SIZE + self.payload.encode_size() + u64::SIZE
    }
}

impl<D, B> Read for Transaction<D, B>
where
    D: Digest,
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
    type SealDigest = D;

    fn seal<H: Hasher<Digest = Self::SealDigest>>(self, hasher: &mut H) -> Sealed<Self, H> {
        let seal = self.hash_slow(hasher);
        Sealed::new_unchecked(self, seal)
    }
}
