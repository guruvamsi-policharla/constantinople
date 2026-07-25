//! Signed value containers.
//!
//! This module builds on the [`Sealed`] wrapper to add cryptographic
//! signatures:
//!
//! - [`Signed`] — A [`Sealed`] value with an attached signature over its seal.
//! - [`Signable`] — A convenience trait for types that are [`Sealable`],
//!   providing a one-step `seal_and_sign` method.

use crate::{
    ChainPrivatePaymentBackend, PrivatePaymentBackend, PublicKeyCache, Sealable, Sealed,
    SignedTransaction, Transaction, TransactionBatchVerifier, TransactionPublicKey,
    TransactionSignature,
};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{
    DecodeExt, Encode, EncodeSize, Error, FixedSize, RangeCfg, Read, ReadExt, Write,
    types::lazy::Lazy,
};
use commonware_cryptography::{Hasher, PublicKey, Signature, Signer, Verifier};
use commonware_parallel::Strategy;
use rand::CryptoRng;
use std::sync::{Arc, OnceLock};

/// A [`Sealed`] object with an attached signature over its seal.
#[derive(Debug, Clone)]
pub struct Signed<T, H, Sig>
where
    H: Hasher,
    Sig: Signature,
{
    inner: Sealed<T, H>,
    signature: Lazy<Sig>,
}

impl<T, H, Sig> PartialEq for Signed<T, H, Sig>
where
    T: PartialEq,
    H: Hasher,
    Sig: Signature,
{
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner && self.signature == other.signature
    }
}

impl<T, H, Sig> Eq for Signed<T, H, Sig>
where
    T: Eq,
    H: Hasher,
    Sig: Signature,
{
}

impl<T, H, Sig> Signed<T, H, Sig>
where
    H: Hasher,
    Sig: Signature,
{
    /// Creates a new [`Signed`] instance by signing the seal of `inner`.
    pub fn new(
        inner: Sealed<T, H>,
        namespace: &[u8],
        signer: &impl Signer<Signature = Sig>,
    ) -> Self {
        let signature = signer.sign(namespace, inner.seal().as_ref());
        Self {
            inner,
            signature: Lazy::new(signature),
        }
    }

    /// Creates a new [`Signed`] instance with the given sealed value and signature.
    ///
    /// The caller must ensure `signature` is a valid signature over `inner.seal()`.
    pub fn new_unchecked(inner: Sealed<T, H>, signature: Sig) -> Self {
        Self {
            inner,
            signature: Lazy::new(signature),
        }
    }

    /// Returns the inner sealed value.
    pub fn into_inner(self) -> Sealed<T, H> {
        self.inner
    }

    /// Returns a reference to the inner sealed value.
    pub const fn inner(&self) -> &Sealed<T, H> {
        &self.inner
    }

    /// Returns a reference to the innermost value.
    pub fn value(&self) -> &T {
        self.inner()
    }

    /// Returns the message digest of the inner value.
    pub const fn message_digest(&self) -> &H::Digest {
        self.inner.seal()
    }

    /// Returns the lazily decoded signature.
    pub const fn signature_lazy(&self) -> &Lazy<Sig> {
        &self.signature
    }

    /// Returns the decoded signature.
    pub fn signature(&self) -> Option<&Sig> {
        self.signature.get()
    }

    /// Verifies the signature against `public_key`.
    pub fn verify<P>(&self, namespace: &[u8], public_key: &P) -> bool
    where
        P: PublicKey + Verifier<Signature = Sig>,
    {
        let Some(signature) = self.signature() else {
            return false;
        };

        public_key.verify(namespace, self.message_digest().as_ref(), signature)
    }
}

impl<T, H, Sig> Write for Signed<T, H, Sig>
where
    T: Write,
    H: Hasher,
    Sig: Signature,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.inner.write(buf);
        self.signature.write(buf);
    }
}

impl<T, H, Sig> FixedSize for Signed<T, H, Sig>
where
    T: FixedSize,
    H: Hasher,
    Sig: Signature,
{
    const SIZE: usize = T::SIZE + Sig::SIZE;
}

impl<T, H, Sig> Read for Signed<T, H, Sig>
where
    T: Read + Sealable<SealDigest = H::Digest>,
    H: Hasher,
    Sig: Signature,
{
    type Cfg = <T as Read>::Cfg;

    fn read_cfg(buf: &mut impl bytes::Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let inner = Sealed::<T, H>::read_cfg(buf, cfg)?;
        let signature = Lazy::<Sig>::read(buf)?;
        Ok(Self { inner, signature })
    }
}

#[cfg(any(feature = "arbitrary", test))]
impl<'a, T, H, Sig> arbitrary::Arbitrary<'a> for Signed<T, H, Sig>
where
    T: arbitrary::Arbitrary<'a> + Sealable<SealDigest = H::Digest>,
    H: Hasher,
    Sig: Signature + arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            inner: u.arbitrary::<T>()?.seal(&mut H::new()),
            signature: Lazy::new(u.arbitrary()?),
        })
    }
}

/// A type that can be sealed and signed.
pub trait Signable: Sealable {
    /// Seals and signs the value.
    fn seal_and_sign<H, S>(
        self,
        signer: &S,
        namespace: &[u8],
        hasher: &mut H,
    ) -> Signed<Self, H, S::Signature>
    where
        H: Hasher<Digest = Self::SealDigest>,
        S: Signer,
        Self: Sized,
    {
        let sealed = self.seal(hasher);
        Signed::new(sealed, namespace, signer)
    }
}

impl<T: Sealable> Signable for T {}

/// A lazily decoded signed transaction.
#[derive(Clone)]
pub struct LazySignedTransaction<H, B = ChainPrivatePaymentBackend>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    pending: Option<Bytes>,
    value: Arc<OnceLock<Option<SignedTransaction<H, B>>>>,
}

impl<H, B> LazySignedTransaction<H, B>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    const MAX_ENCODED_SIZE: usize =
        Transaction::<H::Digest, B>::MAX_SIZE + TransactionSignature::MAX_SIZE;

    /// Creates a lazy transaction from an already decoded value.
    pub fn new(value: SignedTransaction<H, B>) -> Self {
        Self {
            pending: None,
            value: Arc::new(Some(value).into()),
        }
    }

    /// Returns the decoded transaction, if decoding succeeds.
    pub fn get(&self) -> Option<&SignedTransaction<H, B>> {
        self.value
            .get_or_init(|| {
                let bytes = self
                    .pending
                    .as_ref()
                    .expect("pending bytes must exist when value is absent");
                SignedTransaction::decode(bytes.clone()).ok()
            })
            .as_ref()
    }

    /// Consumes the lazy transaction, returning the decoded value if decoding
    /// succeeds.
    ///
    /// Moves the cached value out when this handle is its only owner; clones
    /// only when the decoded value is still shared with another handle.
    pub fn into_value(self) -> Option<SignedTransaction<H, B>> {
        self.get()?;
        match Arc::try_unwrap(self.value) {
            Ok(value) => value.into_inner().flatten(),
            Err(shared) => shared.get().expect("value was forced above").clone(),
        }
    }

    /// Returns the encoded signed transaction bytes without the lazy length prefix.
    ///
    /// If this value came from block decoding, this clones the deferred bytes and
    /// does not materialize the transaction.
    pub fn encoded_signed_transaction(&self) -> Bytes {
        if let Some(bytes) = &self.pending {
            return bytes.clone();
        }

        self.get()
            .expect("lazy signed transaction must have a value")
            .encode()
    }

    fn deferred(bytes: Bytes) -> Self {
        Self {
            pending: Some(bytes),
            value: Default::default(),
        }
    }
}

impl<H, B> Read for LazySignedTransaction<H, B>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let len = usize::read_cfg(buf, &RangeCfg::new(0..=Self::MAX_ENCODED_SIZE))?;
        if len < Transaction::<H::Digest, B>::MIN_SIZE + TransactionSignature::MIN_SIZE {
            return Err(Error::EndOfBuffer);
        }
        if buf.remaining() < len {
            return Err(Error::EndOfBuffer);
        }

        Ok(Self::deferred(buf.copy_to_bytes(len)))
    }
}

impl<H, B> Write for LazySignedTransaction<H, B>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    fn write(&self, buf: &mut impl BufMut) {
        if let Some(pending) = &self.pending {
            pending.len().write(buf);
            buf.put_slice(pending);
            return;
        }
        let transaction = self
            .get()
            .expect("lazy signed transaction must have a value");
        transaction.encode_size().write(buf);
        transaction.write(buf);
    }
}

impl<H, B> EncodeSize for LazySignedTransaction<H, B>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    fn encode_size(&self) -> usize {
        if let Some(pending) = &self.pending {
            return pending.len().encode_size() + pending.len();
        }
        let len = self
            .get()
            .expect("lazy signed transaction must have a value")
            .encode_size();
        len.encode_size() + len
    }
}

impl<H, B> PartialEq for LazySignedTransaction<H, B>
where
    H: Hasher,
    B: PrivatePaymentBackend,
    SignedTransaction<H, B>: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

impl<H, B> Eq for LazySignedTransaction<H, B>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
}

impl<H, B> core::fmt::Debug for LazySignedTransaction<H, B>
where
    H: Hasher,
    B: PrivatePaymentBackend,
    SignedTransaction<H, B>: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.get().fmt(f)
    }
}

/// Materializes lazily-encoded signed transactions in parallel.
///
/// Returns `None` if any transaction fails to decode.
pub fn materialize_transaction_chunks<H, B, St>(
    strategy: &St,
    transactions: Vec<LazySignedTransaction<H, B>>,
) -> Option<Vec<SignedTransaction<H, B>>>
where
    H: Hasher,
    B: PrivatePaymentBackend,
    St: Strategy,
{
    strategy
        .map_collect_vec(transactions, LazySignedTransaction::into_value)
        .into_iter()
        .collect()
}

/// Forces a borrowed slice of lazily encoded signed transactions to decode in
/// parallel.
///
/// Returns `false` if any transaction fails to decode.
pub fn preload_transaction_slice<H, B, St>(
    transactions: &[LazySignedTransaction<H, B>],
    strategy: &St,
) -> bool
where
    H: Hasher,
    B: PrivatePaymentBackend,
    St: Strategy,
{
    strategy.fold(
        transactions,
        || true,
        |decoded, lazy| decoded && signature_inputs_decode(lazy),
        |left, right| left && right,
    )
}

/// Forces lazily encoded signed transactions to decode in parallel.
///
/// Returns the original lazy transactions after warming their cached decoded
/// values, or `None` if any transaction fails to decode.
pub fn preload_transaction_chunks<H, B, St>(
    transactions: Vec<LazySignedTransaction<H, B>>,
    strategy: &St,
) -> Option<Vec<LazySignedTransaction<H, B>>>
where
    H: Hasher,
    B: PrivatePaymentBackend,
    St: Strategy,
{
    preload_transaction_slice(&transactions, strategy).then_some(transactions)
}

/// Splits a bare `Vec<SignedTransaction>` batch body into deferred
/// [`LazySignedTransaction`]s without decoding (and therefore without
/// decompressing any curve points) any transaction.
///
/// Transaction boundaries are found structurally, all cheap: the count
/// prefix, the fixed-size sender and nonce, the payload span (fixed given its
/// tag), and the variable-size but self-delimiting, crypto-free
/// [`TransactionSignature`] decode. Each transaction's exact wire bytes are
/// stored as deferred bytes, identical in shape to the block-body lazy path,
/// so the subsequent [`preload_transaction_slice`] materializes and
/// decompresses them across the strategy pool in parallel rather than
/// serially on the caller.
///
/// This is the compressed-point ingress path: it moves the ~15-20us/point
/// decompression off the single accepting thread and onto the pool.
pub fn frame_signed_batch<H, B>(
    body: &Bytes,
    max_transactions: usize,
) -> Result<Vec<LazySignedTransaction<H, B>>, Error>
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    fn advance_checked(buf: &mut impl Buf, len: usize) -> Result<(), Error> {
        if buf.remaining() < len {
            return Err(Error::EndOfBuffer);
        }
        buf.advance(len);
        Ok(())
    }

    let mut cursor = body.clone();
    let count = usize::read_cfg(&mut cursor, &RangeCfg::new(1..=max_transactions))?;
    let mut framed = Vec::with_capacity(count);
    for _ in 0..count {
        let start = body.len() - cursor.remaining();

        // Sender: `Lazy<TransactionPublicKey>`, a fixed-size read.
        advance_checked(&mut cursor, TransactionPublicKey::SIZE)?;

        // Payload: peek the tag, then skip the whole (tag-determined) span.
        if !cursor.has_remaining() {
            return Err(Error::EndOfBuffer);
        }
        let tag = cursor.chunk()[0];
        let payload_size = crate::transaction::payload_wire_size::<B>(tag)
            .ok_or(Error::Invalid("Payload", "unknown payload tag"))?;
        advance_checked(&mut cursor, payload_size)?;

        // Nonce: fixed `u64`.
        advance_checked(&mut cursor, u64::SIZE)?;

        // Signature: variable, but decoded here only to measure its length
        // (no signature verification, no point decompression).
        TransactionSignature::read(&mut cursor)?;

        let end = body.len() - cursor.remaining();
        framed.push(LazySignedTransaction::deferred(body.slice(start..end)));
    }

    if cursor.has_remaining() {
        return Err(Error::Invalid(
            "SignedTransaction batch",
            "trailing bytes after framed transactions",
        ));
    }

    Ok(framed)
}

/// Forces the lazy transaction to decode and its sender public key to parse, in
/// parallel with its caller. Returns `false` if decode fails or the sender is
/// not present. Decompression is deferred to the batch build, which looks each
/// sender up in the shared cache exactly once.
fn signature_inputs_decode<H, B>(lazy: &LazySignedTransaction<H, B>) -> bool
where
    H: Hasher,
    B: PrivatePaymentBackend,
{
    let Some(transaction) = lazy.get() else {
        return false;
    };
    transaction.value().sender().is_some()
}

/// Verifies a slice of lazily-encoded signed transactions using batch
/// verification.
///
/// Calling `.get()` on each [`Lazy`] forces the underlying
/// [`SignedTransaction`] to be decoded and its seal digest computed.
///
/// Returns `true` if every transaction decodes and all signatures verify,
/// `false` otherwise.
pub fn verify_transaction_batch<H, B, St>(
    namespace: &[u8],
    rng: &mut impl CryptoRng,
    cache: &PublicKeyCache,
    transactions: &[LazySignedTransaction<H, B>],
    signature_strategy: &St,
) -> bool
where
    H: Hasher,
    B: PrivatePaymentBackend,
    St: Strategy,
{
    if transactions.is_empty() {
        return true;
    }

    // Resolve every sender's decompressed key up front: when the active
    // account set exceeds the cache capacity, misses dominate and would
    // otherwise pay their curve decompression serially in the queueing
    // loop below.
    let mut senders = Vec::with_capacity(transactions.len());
    for lazy in transactions {
        let Some(transaction) = lazy.get() else {
            return false;
        };
        let Some(sender) = transaction.value().sender() else {
            return false;
        };
        senders.push(sender);
    }
    let Some(keys) = cache.decompress(&senders, signature_strategy) else {
        return false;
    };

    // Queueing is cheap: transactions are preloaded and sender keys were
    // resolved above. The expensive per-signature challenge hashing and the
    // serial-vs-parallel split happen inside `verify`, which shards the batch
    // across `signature_strategy` internally.
    let mut verifier = TransactionBatchVerifier::new(transactions.len());
    for (lazy, key) in transactions.iter().zip(&keys) {
        let Some(transaction) = lazy.get() else {
            return false;
        };
        if !verifier.add(
            namespace,
            transaction.message_digest().as_ref(),
            key,
            transaction.signature(),
        ) {
            return false;
        }
    }
    verifier.verify(rng, signature_strategy)
}

/// Verifies lazily-encoded transactions.
///
/// First forces each [`Lazy`] to decode and compute its seal digest, then runs
/// batch signature verification over the warmed transactions, both on
/// `strategy`. Returns `None` if any transaction is invalid or undecodable.
pub fn verify_transaction_chunks<H, B, St>(
    namespace: &'static [u8],
    rng: &mut impl CryptoRng,
    cache: &PublicKeyCache,
    transactions: Vec<LazySignedTransaction<H, B>>,
    strategy: &St,
) -> Option<Vec<SignedTransaction<H, B>>>
where
    H: Hasher,
    B: PrivatePaymentBackend,
    St: Strategy,
{
    if transactions.is_empty() {
        return Some(Vec::new());
    }

    let transactions = preload_transaction_chunks(transactions, strategy)?;

    if !verify_transaction_batch::<H, B, _>(namespace, rng, cache, &transactions, strategy) {
        return None;
    }

    // Each lazy was forced during verification above, so materialization cannot fail here.
    transactions
        .into_iter()
        .map(LazySignedTransaction::into_value)
        .collect()
}

#[cfg(test)]
mod test {
    use crate::{
        LazySignedTransaction, PublicKeyCache, Sealable, Sealed, SignedTransaction, Transaction,
        TransactionBatchVerifier, TransactionPublicKey, signed::Signable,
    };
    use commonware_codec::{
        DecodeExt as _, Encode as _, EncodeSize as _, FixedSize as _, ReadExt as _, Write as _,
    };
    use commonware_cryptography::{
        Hasher, Signer, Verifier, ed25519, secp256r1::standard as secp256r1, sha256,
    };
    use commonware_math::algebra::Random;
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::{NZUsize, test_rng};
    use core::num::NonZeroU64;

    const NAMESPACE: &[u8] = b"test namespace";

    #[derive(Debug)]
    struct MockValue([u8; 4]);

    impl Sealable for MockValue {
        type SealDigest = sha256::Digest;

        fn seal<H: Hasher<Digest = Self::SealDigest>>(
            self,
            hasher: &mut H,
        ) -> crate::Sealed<Self, H> {
            hasher.update(&self.0);
            Sealed::new_unchecked(self, hasher.finalize())
        }
    }

    #[test]
    fn signed_verify_works_for_ed25519() {
        let hasher = &mut sha256::Sha256::default();
        let private_key = ed25519::PrivateKey::random(test_rng());
        let signed = MockValue([1, 2, 3, 4]).seal_and_sign(&private_key, NAMESPACE, hasher);

        assert!(signed.verify(NAMESPACE, &private_key.public_key()));
    }

    #[test]
    fn signed_verify_works_for_secp256r1() {
        let hasher = &mut sha256::Sha256::default();
        let private_key = secp256r1::PrivateKey::random(test_rng());
        let signed = MockValue([5, 6, 7, 8]).seal_and_sign(&private_key, NAMESPACE, hasher);

        assert!(signed.verify(NAMESPACE, &private_key.public_key()));
    }

    #[test]
    fn signed_into_inner_returns_sealed() {
        let hasher = &mut sha256::Sha256::default();
        let private_key = ed25519::PrivateKey::random(test_rng());
        let signed = MockValue([9, 10, 11, 12]).seal_and_sign(&private_key, NAMESPACE, hasher);

        let seal = *signed.message_digest();
        let sealed = signed.into_inner();

        assert_eq!(*sealed.seal(), seal);
        assert_eq!(sealed.0, [9, 10, 11, 12]);
    }

    #[test]
    fn wrong_namespace_fails_verification() {
        let hasher = &mut sha256::Sha256::default();
        let private_key = ed25519::PrivateKey::random(test_rng());
        let signed = MockValue([1, 2, 3, 4]).seal_and_sign(&private_key, NAMESPACE, hasher);

        assert!(!signed.verify(b"wrong namespace", &private_key.public_key()));
        assert!(
            private_key.public_key().verify(
                NAMESPACE,
                signed.message_digest().as_ref(),
                signed
                    .signature()
                    .expect("locally created signatures must decode")
            )
        );
    }

    #[test]
    fn signed_transaction_exposes_sender_public_key() {
        deterministic::Runner::default().start(|context| async move {
            let cache = PublicKeyCache::new(context, NZUsize!(16));
            let hasher = &mut sha256::Sha256::default();
            let private_key = ed25519::PrivateKey::random(test_rng());
            let public_key = TransactionPublicKey::ed25519(private_key.public_key());
            let signed: SignedTransaction<sha256::Sha256> = Transaction::new(
                public_key.clone(),
                public_key.clone(),
                NonZeroU64::new(1).expect("test value should be non-zero"),
                0,
            )
            .seal_and_sign(&private_key, NAMESPACE, hasher);

            assert_eq!(signed.value().sender(), Some(&public_key));

            let sender = signed
                .value()
                .sender()
                .expect("signed sender should decode");
            let keys = cache
                .decompress(&[sender], &Sequential)
                .expect("valid sender key");
            let mut verifier = TransactionBatchVerifier::new(1);
            assert!(verifier.add(
                NAMESPACE,
                signed.message_digest().as_ref(),
                &keys[0],
                signed.signature(),
            ));
            assert!(verifier.verify(&mut test_rng(), &Sequential));
        });
    }

    #[test]
    fn preload_transaction_chunks_forces_nested_signature_inputs() {
        let hasher = &mut sha256::Sha256::default();
        let private_key = ed25519::PrivateKey::random(test_rng());
        let public_key = TransactionPublicKey::ed25519(private_key.public_key());
        let signed: SignedTransaction<sha256::Sha256> = Transaction::new(
            public_key.clone(),
            public_key,
            NonZeroU64::new(1).expect("test value should be non-zero"),
            0,
        )
        .seal_and_sign(&private_key, NAMESPACE, hasher);

        let mut transaction = Vec::with_capacity(signed.encode_size());
        signed.write(&mut transaction);
        transaction[..TransactionPublicKey::SIZE].copy_from_slice(&invalid_public_key_bytes());

        let mut encoded = Vec::with_capacity(transaction.len().encode_size() + transaction.len());
        transaction.len().write(&mut encoded);
        encoded.extend_from_slice(&transaction);

        let lazy = LazySignedTransaction::<sha256::Sha256>::read(&mut &encoded[..])
            .expect("outer transaction should decode");
        assert!(
            lazy.get().is_some(),
            "outer transaction decode should defer sender validation"
        );

        assert!(
            super::preload_transaction_chunks(vec![lazy], &Sequential).is_none(),
            "preload must force the nested sender public key"
        );
    }

    #[test]
    fn lazy_signed_transaction_exposes_pending_bytes_without_materializing() {
        let hasher = &mut sha256::Sha256::default();
        let private_key = ed25519::PrivateKey::random(test_rng());
        let public_key = TransactionPublicKey::ed25519(private_key.public_key());
        let signed: SignedTransaction<sha256::Sha256> = Transaction::new(
            public_key.clone(),
            public_key,
            NonZeroU64::new(1).expect("test value should be non-zero"),
            0,
        )
        .seal_and_sign(&private_key, NAMESPACE, hasher);

        let mut transaction = Vec::with_capacity(signed.encode_size());
        signed.write(&mut transaction);
        transaction[0] = u8::MAX;

        let mut encoded = Vec::with_capacity(transaction.len().encode_size() + transaction.len());
        transaction.len().write(&mut encoded);
        encoded.extend_from_slice(&transaction);

        let lazy = LazySignedTransaction::<sha256::Sha256>::read(&mut &encoded[..])
            .expect("outer transaction should decode");

        assert_eq!(lazy.encoded_signed_transaction().as_ref(), transaction);
        assert!(
            lazy.get()
                .expect("signed transaction should decode while sender stays lazy")
                .value()
                .sender()
                .is_none(),
            "nested sender decode should still fail after reading pending bytes"
        );
    }

    fn invalid_public_key_bytes() -> [u8; TransactionPublicKey::SIZE] {
        (0u8..=u8::MAX)
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
            .expect("test should find invalid public key bytes")
    }

    /// A batch spanning every payload variant, built with the configured
    /// chain backend (mock by default, real zkpari under --all-features),
    /// plus its bare-`Vec` wire encoding. Signatures are ed25519 — the only
    /// scheme the spammer emits; the variable-length secp256r1 signature
    /// decode that framing also handles is covered by `auth`'s own tests.
    fn mixed_batch() -> (Vec<SignedTransaction<sha256::Sha256>>, bytes::Bytes) {
        use crate::{ChainPrivatePaymentBackend as Chain, Payload};
        use commonware_privacy::payments::Backend as _;

        let params = <Chain as crate::PrivatePaymentBackend>::params();
        let mut rng = test_rng();
        let ed = ed25519::PrivateKey::random(&mut rng);
        let sender = TransactionPublicKey::ed25519(ed.public_key());
        let to = crate::AccountKey::from_public_key(&sender);

        let (current, current_opening, _fp) = Chain::fund(params, 7, &mut rng);
        let (amount, _ao, transfer_proof) =
            Chain::transfer(params, &current, &current_opening, 3, &mut rng);
        let (fund_commitment, _fo, fund_proof) = Chain::fund(params, 9, &mut rng);
        let (burn_current, burn_opening, _bfp) = Chain::fund(params, 5, &mut rng);
        let burn_proof = Chain::burn(params, &burn_current, &burn_opening, 2, &mut rng);

        let payloads = [
            Payload::PublicTransfer {
                to,
                value: NonZeroU64::new(11).unwrap(),
            },
            Payload::PrivateFund {
                value: NonZeroU64::new(9).unwrap(),
                commitment: fund_commitment,
                proof: fund_proof,
            },
            Payload::PrivateRollover,
            Payload::PrivateTransfer {
                to,
                amount,
                proof: transfer_proof,
            },
            Payload::PrivateBurn {
                value: NonZeroU64::new(2).unwrap(),
                proof: burn_proof,
            },
        ];

        let mut batch = Vec::with_capacity(payloads.len());
        for (nonce, payload) in payloads.into_iter().enumerate() {
            batch.push(
                Transaction::from_payload(sender.clone(), payload, nonce as u64).seal_and_sign(
                    &ed,
                    NAMESPACE,
                    &mut sha256::Sha256::default(),
                ),
            );
        }
        let body = batch.encode();
        (batch, body)
    }

    #[test]
    fn frame_signed_batch_matches_eager_decode() {
        let (batch, body) = mixed_batch();

        let framed = super::frame_signed_batch::<sha256::Sha256, _>(&body, batch.len())
            .expect("framing should succeed");
        assert_eq!(framed.len(), batch.len());

        for (lazy, expected) in framed.into_iter().zip(&batch) {
            // Each deferred slice must be the exact wire bytes of one
            // transaction and materialize back to the original.
            assert_eq!(
                lazy.encoded_signed_transaction().as_ref(),
                expected.encode().as_ref()
            );
            let materialized = lazy.into_value().expect("framed transaction materializes");
            assert_eq!(&materialized, expected);
        }
    }

    #[test]
    fn frame_signed_batch_rejects_truncation() {
        let (batch, body) = mixed_batch();
        // Every strict prefix must fail rather than mis-frame.
        for len in 1..body.len() {
            let truncated = body.slice(0..len);
            assert!(
                super::frame_signed_batch::<sha256::Sha256, crate::ChainPrivatePaymentBackend>(
                    &truncated,
                    batch.len(),
                )
                .is_err(),
                "prefix of length {len} must not frame"
            );
        }
    }

    #[test]
    fn frame_signed_batch_rejects_trailing_bytes() {
        let (batch, body) = mixed_batch();
        let mut extended = body.to_vec();
        extended.push(0);
        assert!(
            super::frame_signed_batch::<sha256::Sha256, crate::ChainPrivatePaymentBackend>(
                &extended.into(),
                batch.len(),
            )
            .is_err(),
            "trailing bytes after the last transaction must be rejected"
        );
    }

    #[test]
    fn frame_signed_batch_enforces_max_transactions() {
        let (batch, body) = mixed_batch();
        assert!(
            super::frame_signed_batch::<sha256::Sha256, crate::ChainPrivatePaymentBackend>(
                &body,
                batch.len() - 1,
            )
            .is_err(),
            "a batch exceeding the transaction cap must be rejected"
        );
    }
}
