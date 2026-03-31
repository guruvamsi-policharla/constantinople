//! Declared and observed access tracking.
//!
//! The verifier executes transactions against the accesses declared in the
//! block access list (BAL), while the proposer runs a permissive discovery pass
//! that records the accesses that actually occurred.

use constantinople_primitives::{Access, AccessList, AccessMode, Address, Slot};
use std::collections::{BTreeMap, HashMap};

type StorageKey = (Address, Slot);

/// Declared account and storage access for one transaction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AccessSet {
    permissive: bool,
    accounts: HashMap<Address, AccessMode>,
    storage: HashMap<StorageKey, AccessMode>,
    total: usize,
}

impl AccessSet {
    /// Creates an exact access set from a declared access list.
    pub(crate) fn new(access_list: &[Access]) -> Self {
        let mut access = Self {
            permissive: false,
            accounts: HashMap::with_capacity(access_list.len()),
            storage: HashMap::with_capacity(access_list.len()),
            total: 0,
        };

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

    /// Creates a permissive access set for proposer-side discovery.
    pub(crate) fn permissive() -> Self {
        Self {
            permissive: true,
            accounts: HashMap::new(),
            storage: HashMap::new(),
            total: 0,
        }
    }

    /// Returns whether `address` may be read.
    pub(crate) fn can_read_account(&self, address: Address) -> bool {
        self.permissive || self.accounts.contains_key(&address)
    }

    /// Returns whether `address` may be written.
    pub(crate) fn can_write_account(&self, address: Address) -> bool {
        self.permissive
            || self
                .accounts
                .get(&address)
                .is_some_and(|mode| *mode == AccessMode::Write)
    }

    /// Returns whether `(address, slot)` may be read.
    pub(crate) fn can_read_storage(&self, address: Address, slot: Slot) -> bool {
        self.permissive || self.storage.contains_key(&(address, slot))
    }

    /// Returns whether `(address, slot)` may be written.
    pub(crate) fn can_write_storage(&self, address: Address, slot: Slot) -> bool {
        self.permissive
            || self
                .storage
                .get(&(address, slot))
                .is_some_and(|mode| *mode == AccessMode::Write)
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

    /// Returns the total number of declared entries.
    pub(crate) const fn len(&self) -> usize {
        self.total
    }

    fn allow_account(&mut self, address: Address, mode: AccessMode) {
        match self.accounts.get_mut(&address) {
            Some(existing) if *existing == AccessMode::Write => {}
            Some(existing) => *existing = mode,
            None => {
                self.total += 1;
                self.accounts.insert(address, mode);
            }
        }
    }

    fn allow_storage(&mut self, address: Address, slot: Slot, mode: AccessMode) {
        match self.storage.get_mut(&(address, slot)) {
            Some(existing) if *existing == AccessMode::Write => {}
            Some(existing) => *existing = mode,
            None => {
                self.total += 1;
                self.storage.insert((address, slot), mode);
            }
        }
    }
}

/// Observed account and storage accesses during one transaction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AccessListBuilder {
    pub(super) accounts: BTreeMap<Address, AccessMode>,
    pub(super) storage: BTreeMap<StorageKey, AccessMode>,
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
    ///
    /// The ordering here is part of block validity. Verification compares the
    /// declared BAL slice against this canonical layout byte-for-byte.
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
