//! Declared and observed access tracking.
//!
//! Every transaction carries an access list that declares exactly which
//! accounts and storage slots it will touch. The processor enforces these
//! declarations at runtime:
//!
//! - [`AccessSet`] holds the declared permissions built from the transaction's
//!   access list plus the implicit sender and recipient entries.
//! - [`AccessListBuilder`] records the accesses that actually occur during
//!   execution so the result can be compared against the declaration.
//!
//! After a successful execution the two must match exactly: every declared
//! entry must be observed with the same mode, and no undeclared entries may
//! appear.

use constantinople_primitives::{Access, AccessList, AccessMode, Address, Slot};
use std::collections::{BTreeMap, HashMap};

type StorageKey = (Address, Slot);

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
    ///
    /// The sender is always declared Write (nonce bump). The recipient mode
    /// is caller-determined: Write when a value transfer occurs, Read for
    /// zero-value calls.
    pub(crate) fn new(
        sender: Address,
        recipient: Address,
        recipient_mode: AccessMode,
        access_list: &AccessList,
    ) -> Self {
        let mut access = Self::default();
        access.allow_account(sender, AccessMode::Write);
        access.allow_account(recipient, recipient_mode);

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

    /// Returns whether the observed accesses exactly match the declared set.
    ///
    /// Every declared entry must appear in the observed set with the same mode,
    /// and the observed set must not contain entries absent from the declared
    /// set. The second condition is already enforced at runtime by the frame
    /// access checks, so this method only verifies the first direction.
    pub(crate) fn is_exact_match(&self, observed: &AccessListBuilder) -> bool {
        if self.accounts.len() != observed.accounts.len()
            || self.storage.len() != observed.storage.len()
        {
            return false;
        }

        for (address, declared_mode) in &self.accounts {
            match observed.accounts.get(address) {
                Some(observed_mode) if observed_mode == declared_mode => {}
                _ => return false,
            }
        }

        for ((address, slot), declared_mode) in &self.storage {
            match observed.storage.get(&(*address, *slot)) {
                Some(observed_mode) if observed_mode == declared_mode => {}
                _ => return false,
            }
        }

        true
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
/// Records the strongest access mode seen for each item during execution.
/// After execution, the processor compares this against the [`AccessSet`] to
/// verify that the declared and observed accesses match exactly.
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
