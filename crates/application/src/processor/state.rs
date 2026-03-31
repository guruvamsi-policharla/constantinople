//! In-memory processor state.
//!
//! This module contains the state overlay used by the processor during one
//! execution pass. It tracks:
//!
//! - the loaded base account and storage snapshot
//! - per-frame diffs that can be merged or discarded
//! - deterministic export of the final database changeset
//!
//! The state layer is deliberately persistence-agnostic. It only knows how to
//! represent visible values and produce the slot/value writes that should be
//! applied back to the database.
//!
//! Access-list declarations and observed-access tracking live in the sibling
//! `access` module.

use super::keys::{account_key, storage_key};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use constantinople_primitives::{Account, Address, Slot, StateValue};
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
