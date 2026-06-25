//! Account model for the Constantinople chain.

use crate::{
    ChainPrivatePaymentBackend, PrivateAccount, PrivatePaymentBackend, StatePrivatePaymentBackend,
    TransactionPublicKey,
    auth::{ED25519_SCHEME, SECP256R1_SCHEME},
};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{Hasher, ed25519, sha256};
use commonware_formatting::hex;
use commonware_utils::{Array, Span};
use core::ops::Deref;
use derive_more::{Debug, Display};

/// Default starting balance for accounts that have not been written yet.
pub const DEFAULT_ACCOUNT_BALANCE: u64 = 100;

/// Number of future nonce uses tracked on each account.
pub const NONCE_BITMAP_CAPACITY: u64 = u64::BITS as u64;

/// Fixed-width account identifier derived from a transaction public key.
///
/// Unlike [`commonware_cryptography::PublicKey`] implementations, decoding an
/// [`AccountKey`] does not validate or decompress the curve point. This keeps
/// state-database replay, indexing, and lookup on cheap byte comparisons while
/// preserving the legacy Ed25519 account format.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountKey {
    bytes: Bytes,
}

impl AccountKey {
    /// Creates an account key from a decoded public key.
    pub fn from_public_key(public_key: &TransactionPublicKey) -> Self {
        Self::from_public_key_bytes(public_key.as_ref())
            .expect("decoded transaction public key bytes must derive an account key")
    }

    /// Creates an account key from encoded transaction public-key bytes.
    pub fn from_public_key_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != TransactionPublicKey::SIZE {
            return None;
        }

        match bytes[0] {
            ED25519_SCHEME => Some(Self {
                bytes: Bytes::copy_from_slice(&bytes[1..1 + Self::SIZE]),
            }),
            SECP256R1_SCHEME => Some(Self {
                bytes: Bytes::copy_from_slice(sha256::Sha256::hash(bytes).as_ref()),
            }),
            _ => None,
        }
    }

    /// Creates an account key from canonical account-key bytes.
    pub fn from_bytes(bytes: Bytes) -> Option<Self> {
        if bytes.len() != Self::SIZE {
            return None;
        }

        Some(Self { bytes })
    }
}

impl FixedSize for AccountKey {
    const SIZE: usize = ed25519::PublicKey::SIZE;
}

impl Write for AccountKey {
    fn write(&self, buf: &mut impl BufMut) {
        debug_assert_eq!(self.bytes.len(), Self::SIZE);
        buf.put_slice(&self.bytes);
    }
}

impl Read for AccountKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        if buf.remaining() < Self::SIZE {
            return Err(CodecError::EndOfBuffer);
        }

        Ok(Self {
            bytes: buf.copy_to_bytes(Self::SIZE),
        })
    }
}

impl AsRef<[u8]> for AccountKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Deref for AccountKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl core::fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.bytes))
    }
}

impl core::fmt::Display for AccountKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.bytes))
    }
}

impl Span for AccountKey {}
impl Array for AccountKey {}

/// Account nonce state.
#[derive(Debug, Display, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(any(feature = "arbitrary", test), derive(arbitrary::Arbitrary))]
#[display("Nonce {{ base: {}, bitmap: {} }}", base, bitmap)]
pub struct Nonce {
    /// The next nonce that has not been consumed by this account.
    pub base: u64,
    /// Used future nonces relative to [`Self::base`].
    ///
    /// Bit 0 records `base + 1`, and bit 63 records `base + 64`.
    pub bitmap: u64,
}

impl Nonce {
    /// Creates account nonce state from raw parts.
    pub const fn new(base: u64, bitmap: u64) -> Self {
        Self { base, bitmap }
    }

    /// Records a transaction nonce if it has not already been consumed.
    ///
    /// Nonces below [`Self::base`] are stale. Nonces inside the run-ahead
    /// window set a bitmap bit. Nonces beyond the window clear the bitmap and
    /// advance [`Self::base`] beyond the consumed transaction.
    pub fn consume(&mut self, nonce: u64) -> bool {
        let Some(next) = next_nonce_state(self.base, self.bitmap, nonce) else {
            return false;
        };

        *self = next;
        true
    }
}

impl FixedSize for Nonce {
    const SIZE: usize = u64::SIZE + u64::SIZE;
}

impl Write for Nonce {
    fn write(&self, buf: &mut impl BufMut) {
        self.base.write(buf);
        self.bitmap.write(buf);
    }
}

impl Read for Nonce {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            base: u64::read(buf)?,
            bitmap: u64::read(buf)?,
        })
    }
}

/// An account, as represented in the state of the chain.
///
/// The associated-type bounds on the private-payment backend live on the
/// [`PrivatePaymentBackend`] supertrait, so `B: PrivatePaymentBackend` is the
/// only bound needed here.
#[derive(Debug, Display, Clone, PartialEq, Eq, Hash)]
#[display("Account {{ balance: {}, nonce: {} }}", balance, nonce)]
pub struct Account<B: PrivatePaymentBackend = ChainPrivatePaymentBackend> {
    /// The balance of the account, which is the amount of tokens that the
    /// account holds.
    pub balance: u64,
    /// Consumed and run-ahead transaction nonce state.
    pub nonce: Nonce,
    /// Private-payment commitment state.
    pub private: PrivateAccount<B>,
}

/// Account representation used by local state-database storage.
pub type StateAccount = Account<StatePrivatePaymentBackend>;

/// Convert an execution account into the local state-database representation.
#[cfg(all(
    not(feature = "privacy-backend-zkpari"),
    feature = "privacy-backend-mock"
))]
pub fn to_state_account(account: Account) -> StateAccount {
    account
}

/// Convert a local state-database account into the execution representation.
#[cfg(all(
    not(feature = "privacy-backend-zkpari"),
    feature = "privacy-backend-mock"
))]
pub fn from_state_account(account: StateAccount) -> Account {
    account
}

/// Convert an execution account into the local state-database representation.
#[cfg(feature = "privacy-backend-zkpari")]
pub const fn to_state_account(account: Account) -> StateAccount {
    use commonware_privacy::zkpari::payments::{
        PaymentCommitment,
        codec::{UncompressedChecked, UncompressedUnchecked},
    };

    const fn convert(
        commitment: UncompressedChecked<PaymentCommitment<ark_bn254::Bn254>>,
    ) -> UncompressedUnchecked<PaymentCommitment<ark_bn254::Bn254>> {
        UncompressedUnchecked(commitment.0)
    }

    StateAccount {
        balance: account.balance,
        nonce: account.nonce,
        private: PrivateAccount {
            current: convert(account.private.current),
            pending: convert(account.private.pending),
        },
    }
}

/// Convert a local state-database account into the execution representation.
#[cfg(feature = "privacy-backend-zkpari")]
pub const fn from_state_account(account: StateAccount) -> Account {
    use commonware_privacy::zkpari::payments::{
        PaymentCommitment,
        codec::{UncompressedChecked, UncompressedUnchecked},
    };

    const fn convert(
        commitment: UncompressedUnchecked<PaymentCommitment<ark_bn254::Bn254>>,
    ) -> UncompressedChecked<PaymentCommitment<ark_bn254::Bn254>> {
        UncompressedChecked(commitment.0)
    }

    Account {
        balance: account.balance,
        nonce: account.nonce,
        private: PrivateAccount {
            current: convert(account.private.current),
            pending: convert(account.private.pending),
        },
    }
}

impl<B: PrivatePaymentBackend> Default for Account<B> {
    fn default() -> Self {
        Self {
            balance: DEFAULT_ACCOUNT_BALANCE,
            nonce: Nonce::default(),
            private: PrivateAccount::default(),
        }
    }
}

impl<B: PrivatePaymentBackend> FixedSize for Account<B> {
    const SIZE: usize = u64::SIZE + Nonce::SIZE + PrivateAccount::<B>::SIZE;
}

impl<B: PrivatePaymentBackend> Write for Account<B> {
    fn write(&self, buf: &mut impl BufMut) {
        self.balance.write(buf);
        self.nonce.write(buf);
        self.private.write(buf);
    }
}

impl<B: PrivatePaymentBackend> Read for Account<B> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            balance: u64::read(buf)?,
            nonce: Nonce::read(buf)?,
            private: PrivateAccount::read(buf)?,
        })
    }
}

fn next_nonce_state(base: u64, bitmap: u64, nonce: u64) -> Option<Nonce> {
    let next_used_nonce = nonce.checked_add(1)?;

    if nonce < base {
        return None;
    }

    let delta = nonce - base;
    if delta == 0 {
        return consume_current_nonce(base, bitmap);
    }

    if delta > NONCE_BITMAP_CAPACITY {
        return Some(Nonce::new(next_used_nonce, 0));
    }

    let bit = 1u64 << (delta - 1);
    if bitmap & bit != 0 {
        return None;
    }

    Some(Nonce::new(base, bitmap | bit))
}

fn consume_current_nonce(base: u64, bitmap: u64) -> Option<Nonce> {
    let mut advance = 1;
    while advance <= NONCE_BITMAP_CAPACITY {
        let bit = 1u64 << (advance - 1);
        if bitmap & bit == 0 {
            break;
        }
        advance += 1;
    }

    let nonce = base.checked_add(advance)?;
    let bitmap = if advance >= NONCE_BITMAP_CAPACITY {
        0
    } else {
        bitmap >> advance
    };
    Some(Nonce::new(nonce, bitmap))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockPrivatePaymentBackend;
    use commonware_codec::{DecodeExt, FixedSize};
    use commonware_cryptography::{
        Hasher, Signer, ed25519, secp256r1::standard as secp256r1, sha256,
    };

    #[test]
    fn account_key_roundtrip_does_not_validate_public_key() {
        let mut raw = vec![0u8; AccountKey::SIZE];
        raw[0] = 1;

        let key = AccountKey::decode(&mut &raw[..]).expect("account keys are raw bytes");

        assert_eq!(key.as_ref(), raw.as_slice());
    }

    #[test]
    fn account_key_from_ed25519_public_key_uses_legacy_key_bytes() {
        let private_key = ed25519::PrivateKey::from_seed(1);
        let public_key = TransactionPublicKey::ed25519(private_key.public_key());

        let key = AccountKey::from_public_key(&public_key);

        assert_eq!(key.as_ref(), &public_key.as_ref()[1..1 + AccountKey::SIZE]);
    }

    #[test]
    fn account_key_from_secp256r1_public_key_uses_hash() {
        let private_key = secp256r1::PrivateKey::from_seed(1);
        let public_key = TransactionPublicKey::secp256r1(private_key.public_key());

        let key = AccountKey::from_public_key(&public_key);

        assert_eq!(
            key.as_ref(),
            sha256::Sha256::hash(public_key.as_ref()).as_ref()
        );
    }

    #[test]
    fn account_codec_roundtrip() {
        let account = Account::<MockPrivatePaymentBackend> {
            balance: 42,
            nonce: Nonce::new(7, 3),
            private: PrivateAccount::default(),
        };

        let mut buf = Vec::with_capacity(Account::<MockPrivatePaymentBackend>::SIZE);
        account.write(&mut buf);
        assert_eq!(buf.len(), Account::<MockPrivatePaymentBackend>::SIZE);

        let decoded = Account::decode(&mut &buf[..]).expect("decoding should succeed");
        assert_eq!(decoded, account);
    }

    #[test]
    fn account_default_starts_funded() {
        assert_eq!(
            Account::default(),
            Account::<MockPrivatePaymentBackend> {
                balance: DEFAULT_ACCOUNT_BALANCE,
                nonce: Nonce::default(),
                private: PrivateAccount::default(),
            }
        );
    }

    #[test]
    fn nonce_records_run_ahead_value() {
        let mut nonce = Nonce::default();

        assert!(nonce.consume(2));
        assert_eq!(nonce, Nonce::new(0, 0b10));
    }

    #[test]
    fn nonce_compacts_contiguous_run_ahead() {
        let mut nonce = Nonce::default();

        assert!(nonce.consume(2));
        assert!(nonce.consume(0));
        assert_eq!(nonce, Nonce::new(1, 0b1));

        assert!(nonce.consume(1));
        assert_eq!(nonce, Nonce::new(3, 0));
    }

    #[test]
    fn nonce_rejects_duplicate_run_ahead() {
        let mut nonce = Nonce::default();

        assert!(nonce.consume(2));
        assert!(!nonce.consume(2));
        assert_eq!(nonce, Nonce::new(0, 0b10));
    }

    #[test]
    fn nonce_rejects_run_ahead_value_that_cannot_advance() {
        let mut nonce = Nonce::new(u64::MAX - 1, 0);

        assert!(!nonce.consume(u64::MAX));
        assert_eq!(nonce, Nonce::new(u64::MAX - 1, 0));
    }

    #[test]
    fn nonce_clears_bitmap_after_far_jump() {
        let mut nonce = Nonce::default();

        assert!(nonce.consume(2));
        assert!(nonce.consume(NONCE_BITMAP_CAPACITY + 1));
        assert_eq!(nonce, Nonce::new(NONCE_BITMAP_CAPACITY + 2, 0));
        assert!(!nonce.consume(NONCE_BITMAP_CAPACITY + 1));
    }
}
