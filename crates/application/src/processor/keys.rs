//! Database key derivation for accounts and storage slots.
//!
//! These pure functions map logical account addresses and storage coordinates
//! to the fixed-size database keys used by the backing store. They are shared
//! by both the processor (for changeset export) and the consensus layer (for
//! state loading).

use commonware_codec::FixedSize;
use commonware_cryptography::Hasher;
use constantinople_primitives::{Address, Slot};

/// Builds the database key for an account.
///
/// The address occupies the first `Address::SIZE` bytes. The remaining bytes
/// are zero.
pub fn account_key(address: Address) -> Slot {
    address.as_ref().into()
}

/// Builds the database key for a storage slot.
///
/// The key is `H(address || storage_slot)`.
///
/// # Panics
///
/// Panics if `H` does not produce a 32-byte digest.
pub fn storage_key<H: Hasher>(hasher: &mut H, address: Address, storage_slot: Slot) -> Slot {
    hasher.reset();
    hasher.update(address.as_ref());
    hasher.update(storage_slot.as_ref());

    let digest = hasher.finalize();
    assert_eq!(
        digest.as_ref().len(),
        Slot::SIZE,
        "storage key hash must be 32 bytes",
    );

    Slot::from(digest.as_ref())
}
