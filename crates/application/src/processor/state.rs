//! In-memory processor state.
//!
//! This module contains the state overlay used by the processor during one
//! execution pass. It tracks:
//!
//! - the loaded base account and storage snapshot
//! - per-frame diffs that can be merged or discarded
//! - access-list permissions and access-list construction
//! - deterministic export of the final database changeset
//!
//! The state layer is deliberately persistence-agnostic. It only knows how to
//! represent visible values and produce the slot/value writes that should be
//! applied back to the database.

use commonware_codec::FixedSize;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use constantinople_primitives::{
    Access, AccessList, AccessMode, Account, Address, Slot, StateValue,
};
use std::collections::{BTreeMap, HashMap};

type StorageKey = (Address, Slot);

/// Tracks one value that changed during execution.
///
/// The processor keeps both the original value and the latest visible value.
/// This lets frames merge child changes, discard reverted children, and omit
/// values that were changed and then restored back to their original state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tracked<T> {
    original: T,
    current: T,
}

impl<T> Tracked<T>
where
    T: Copy + Eq,
{
    /// Creates a tracked entry from the original and current values.
    const fn new(original: T, current: T) -> Self {
        Self { original, current }
    }

    /// Returns the latest visible value.
    const fn current(&self) -> T {
        self.current
    }

    /// Returns whether the value still differs from its original value.
    fn is_changed(&self) -> bool {
        self.original != self.current
    }
}

/// Stores the changes owned by one frame.
///
/// Each entry records both its original and current value. A value disappears
/// from the diff once it is restored to its original state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FrameDiff {
    accounts: HashMap<Address, Tracked<Account>>,
    storage: HashMap<StorageKey, Tracked<Slot>>,
}

impl FrameDiff {
    /// Returns the changed account value for `address`, if present.
    pub(crate) fn account(&self, address: Address) -> Option<Account> {
        self.accounts.get(&address).map(Tracked::current)
    }

    /// Returns the changed storage value for `(address, slot)`, if present.
    pub(crate) fn storage(&self, address: Address, slot: Slot) -> Option<Slot> {
        self.storage.get(&(address, slot)).map(Tracked::current)
    }

    /// Records an account change.
    ///
    /// If the latest value equals the original value, the tracked entry is
    /// removed so the diff contains only persistent changes.
    pub(crate) fn set_account(&mut self, address: Address, original: Account, current: Account) {
        if let Some(tracked) = self.accounts.get_mut(&address) {
            tracked.current = current;

            if !tracked.is_changed() {
                self.accounts.remove(&address);
            }
            return;
        }

        if original == current {
            return;
        }

        self.accounts
            .insert(address, Tracked::new(original, current));
    }

    /// Records a storage change.
    ///
    /// If the latest value equals the original value, the tracked entry is
    /// removed so the diff contains only persistent changes.
    pub(crate) fn set_storage(
        &mut self,
        address: Address,
        slot: Slot,
        original: Slot,
        current: Slot,
    ) {
        let key = (address, slot);

        if let Some(tracked) = self.storage.get_mut(&key) {
            tracked.current = current;

            if !tracked.is_changed() {
                self.storage.remove(&key);
            }
            return;
        }

        if original == current {
            return;
        }

        self.storage.insert(key, Tracked::new(original, current));
    }

    /// Merges a child diff into this diff.
    ///
    /// Child values become the latest visible values in the merged result,
    /// while the original values remain anchored to the first write observed in
    /// the parent chain.
    pub(crate) fn merge(&mut self, child: Self) {
        for (address, tracked) in child.accounts {
            self.set_account(address, tracked.original, tracked.current);
        }

        for ((address, slot), tracked) in child.storage {
            self.set_storage(address, slot, tracked.original, tracked.current);
        }
    }

    /// Produces a database changeset for the changed values in this diff.
    ///
    /// Accounts are emitted at their account keys and storage values are
    /// emitted at their hashed storage keys. Only values that still differ from
    /// their originals are included.
    ///
    /// # Panics
    ///
    /// Panics if two changed entries map to the same database key.
    pub(crate) fn changeset<H: Hasher>(
        &self,
        strategy: &impl Strategy,
    ) -> BTreeMap<Slot, StateValue> {
        let mut changeset = BTreeMap::new();

        for (address, tracked) in &self.accounts {
            let key = account_key(*address);
            let value = StateValue::Account(tracked.current());
            let previous = changeset.insert(key, value);
            assert!(previous.is_none(), "duplicate account key in changeset");
        }

        let storage_entries = strategy.map_init_collect_vec(
            self.storage.iter(),
            H::default,
            |hasher, ((address, slot), tracked)| {
                let key = storage_key(hasher, *address, *slot);
                let value = StateValue::Storage(tracked.current());
                (key, value)
            },
        );

        for (key, value) in storage_entries {
            let previous = changeset.insert(key, value);
            assert!(previous.is_none(), "duplicate storage key in changeset");
        }

        changeset
    }
}

/// Declared account and storage access for one transaction.
///
/// The processor builds this once from the transaction's explicit access list
/// plus implicit top-level account accesses. Frames use it to reject reads and
/// writes that were not declared up front.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AccessSet {
    accounts: HashMap<Address, AccessMode>,
    storage: HashMap<StorageKey, AccessMode>,
}

impl AccessSet {
    /// Creates an access set from a transaction access list.
    pub(crate) fn new(sender: Address, recipient: Address, access_list: &AccessList) -> Self {
        let mut access = Self::default();
        access.allow_account(sender, AccessMode::Write);
        access.allow_account(recipient, AccessMode::Write);

        for entry in access_list {
            match entry {
                Access::Account(address, mode) => access.allow_account(*address, *mode),
                Access::Storage(address, slot, mode) => {
                    access.allow_storage(*address, *slot, *mode)
                }
            }
        }

        access
    }

    /// Returns whether `address` may be read.
    pub(crate) fn can_read_account(&self, address: Address) -> bool {
        self.accounts.contains_key(&address)
    }

    /// Returns whether `address` may be written.
    pub(crate) fn can_write_account(&self, address: Address) -> bool {
        self.accounts.get(&address) == Some(&AccessMode::Write)
    }

    /// Returns whether `(address, slot)` may be read.
    pub(crate) fn can_read_storage(&self, address: Address, slot: Slot) -> bool {
        self.storage.contains_key(&(address, slot))
    }

    /// Returns whether `(address, slot)` may be written.
    pub(crate) fn can_write_storage(&self, address: Address, slot: Slot) -> bool {
        self.storage.get(&(address, slot)) == Some(&AccessMode::Write)
    }

    /// Iterates the declared account accesses.
    pub(crate) fn accounts(&self) -> impl Iterator<Item = (Address, AccessMode)> + '_ {
        self.accounts
            .iter()
            .map(|(address, mode)| (*address, *mode))
    }

    /// Iterates the declared storage accesses.
    pub(crate) fn storage(&self) -> impl Iterator<Item = (Address, Slot, AccessMode)> + '_ {
        self.storage
            .iter()
            .map(|((address, slot), mode)| (*address, *slot, *mode))
    }

    fn allow_account(&mut self, address: Address, mode: AccessMode) {
        match self.accounts.get_mut(&address) {
            Some(existing) if *existing == AccessMode::Write => {}
            Some(existing) => *existing = mode,
            None => {
                self.accounts.insert(address, mode);
            }
        }
    }

    fn allow_storage(&mut self, address: Address, slot: Slot, mode: AccessMode) {
        match self.storage.get_mut(&(address, slot)) {
            Some(existing) if *existing == AccessMode::Write => {}
            Some(existing) => *existing = mode,
            None => {
                self.storage.insert((address, slot), mode);
            }
        }
    }
}

/// Observed account and storage accesses during one transaction.
///
/// This collects the strongest mode seen for each accessed item so the
/// resulting access list can be reused for future execution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AccessListBuilder {
    accounts: BTreeMap<Address, AccessMode>,
    storage: BTreeMap<StorageKey, AccessMode>,
}

impl AccessListBuilder {
    /// Records account access for `address`.
    pub(crate) fn record_account(&mut self, address: Address, mode: AccessMode) {
        match self.accounts.get_mut(&address) {
            Some(existing) if *existing == AccessMode::Write => {}
            Some(existing) => *existing = mode,
            None => {
                self.accounts.insert(address, mode);
            }
        }
    }

    /// Records storage access for `(address, slot)`.
    pub(crate) fn record_storage(&mut self, address: Address, slot: Slot, mode: AccessMode) {
        match self.storage.get_mut(&(address, slot)) {
            Some(existing) if *existing == AccessMode::Write => {}
            Some(existing) => *existing = mode,
            None => {
                self.storage.insert((address, slot), mode);
            }
        }
    }

    /// Merges another builder into this one.
    pub(crate) fn merge(&mut self, other: Self) {
        for (address, mode) in other.accounts {
            self.record_account(address, mode);
        }

        for ((address, slot), mode) in other.storage {
            self.record_storage(address, slot, mode);
        }
    }

    /// Converts the collected accesses into a deterministic access list.
    pub(crate) fn into_access_list(self) -> AccessList {
        let mut access_list = Vec::with_capacity(self.accounts.len() + self.storage.len());

        for (address, mode) in self.accounts {
            access_list.push(Access::Account(address, mode));
        }

        for ((address, slot), mode) in self.storage {
            access_list.push(Access::Storage(address, slot, mode));
        }

        access_list
    }
}

/// In-memory processor state.
///
/// `State` combines the loaded base state with the committed in-memory diff
/// accumulated during execution. Reads first consult the committed diff and
/// then fall back to the loaded base state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    base_accounts: HashMap<Address, Account>,
    base_storage: HashMap<StorageKey, Slot>,
    diff: FrameDiff,
}

impl State {
    /// Creates in-memory processor state from loaded accounts and storage.
    ///
    /// The input maps use logical account and storage coordinates rather than
    /// database keys so callers can prepare state from any source, including
    /// database reads, proofs, or other execution witnesses.
    pub fn new(
        base_accounts: HashMap<Address, Account>,
        base_storage: HashMap<(Address, Slot), Slot>,
    ) -> Self {
        Self {
            base_accounts,
            base_storage,
            diff: FrameDiff::default(),
        }
    }

    /// Returns the visible account value for `address`.
    ///
    /// Missing accounts read as the default account value.
    pub(crate) fn account(&self, address: Address) -> Account {
        if let Some(account) = self.diff.account(address) {
            return account;
        }

        self.base_accounts
            .get(&address)
            .copied()
            .unwrap_or_default()
    }

    /// Returns the visible storage value for `(address, slot)`.
    ///
    /// Missing storage values read as the default slot value.
    pub(crate) fn storage(&self, address: Address, slot: Slot) -> Slot {
        if let Some(value) = self.diff.storage(address, slot) {
            return value;
        }

        self.base_storage
            .get(&(address, slot))
            .copied()
            .unwrap_or_default()
    }

    /// Commits a frame diff into the state.
    pub(crate) fn apply(&mut self, diff: FrameDiff) {
        self.diff.merge(diff);
    }

    /// Produces a database changeset for the committed state diff.
    pub(crate) fn changeset<H: Hasher>(
        &self,
        strategy: &impl Strategy,
    ) -> BTreeMap<Slot, StateValue> {
        self.diff.changeset::<H>(strategy)
    }
}

/// Builds the database key for an account.
///
/// The address occupies the first `Address::SIZE` bytes. The remaining bytes
/// are zero.
pub(crate) fn account_key(address: Address) -> Slot {
    address.as_ref().into()
}

/// Builds the database key for a storage slot.
///
/// The key is `H(address || storage_slot)`.
///
/// # Panics
///
/// Panics if `H` does not produce a 32-byte digest.
pub(crate) fn storage_key<H: Hasher>(hasher: &mut H, address: Address, storage_slot: Slot) -> Slot {
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
