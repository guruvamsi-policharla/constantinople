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
    accounts: HashMap<Address, (AccessMode, usize)>,
    storage: HashMap<StorageKey, (AccessMode, usize)>,
    /// Total number of entries (accounts + storage).
    total: usize,
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
        let mut access = Self {
            accounts: HashMap::with_capacity(access_list.len() + 2),
            storage: HashMap::with_capacity(access_list.len()),
            total: 0,
        };
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
        self.accounts
            .get(&address)
            .is_some_and(|(mode, _)| *mode == AccessMode::Write)
    }

    /// Returns whether `(address, slot)` may be read.
    pub(crate) fn can_read_storage(&self, address: Address, slot: Slot) -> bool {
        self.storage.contains_key(&(address, slot))
    }

    /// Returns whether `(address, slot)` may be written.
    pub(crate) fn can_write_storage(&self, address: Address, slot: Slot) -> bool {
        self.storage
            .get(&(address, slot))
            .is_some_and(|(mode, _)| *mode == AccessMode::Write)
    }

    /// Returns the bitset index for `address`, if declared.
    pub(crate) fn account_index(&self, address: Address) -> Option<usize> {
        self.accounts.get(&address).map(|(_, idx)| *idx)
    }

    /// Returns the bitset index for `(address, slot)`, if declared.
    pub(crate) fn storage_index(&self, address: Address, slot: Slot) -> Option<usize> {
        self.storage.get(&(address, slot)).map(|(_, idx)| *idx)
    }

    /// Iterates the declared account accesses.
    pub(crate) fn accounts(&self) -> impl Iterator<Item = (Address, AccessMode)> + '_ {
        self.accounts
            .iter()
            .map(|(address, (mode, _))| (*address, *mode))
    }

    /// Iterates the declared storage accesses.
    pub(crate) fn storage(&self) -> impl Iterator<Item = (Address, Slot, AccessMode)> + '_ {
        self.storage
            .iter()
            .map(|((address, slot), (mode, _))| (*address, *slot, *mode))
    }

    /// Returns the total number of declared entries (accounts + storage).
    pub(crate) const fn len(&self) -> usize {
        self.total
    }

    /// Returns whether every declared entry was accessed.
    ///
    /// For the `Counter` observer, checks that all bits in the bitset are set.
    /// For the `Builder` observer, compares every entry by key and mode.
    pub(crate) fn is_exact_match(&self, observer: &AccessObserver) -> bool {
        match observer {
            AccessObserver::Counter(bits) => {
                let total = self.len();
                if total == 0 {
                    return true;
                }
                // Check all full words are all-ones.
                let full_words = total / 64;
                for word in &bits[..full_words] {
                    if *word != u64::MAX {
                        return false;
                    }
                }
                // Check the partial last word has the right bits set.
                let remainder = total % 64;
                if remainder > 0 {
                    let mask = (1u64 << remainder) - 1;
                    if bits[full_words] & mask != mask {
                        return false;
                    }
                }
                true
            }
            AccessObserver::Builder(builder) => {
                if self.accounts.len() != builder.accounts.len()
                    || self.storage.len() != builder.storage.len()
                {
                    return false;
                }

                for (address, (declared_mode, _)) in &self.accounts {
                    match builder.accounts.get(address) {
                        Some(observed_mode) if observed_mode == declared_mode => {}
                        _ => return false,
                    }
                }

                for ((address, slot), (declared_mode, _)) in &self.storage {
                    match builder.storage.get(&(*address, *slot)) {
                        Some(observed_mode) if observed_mode == declared_mode => {}
                        _ => return false,
                    }
                }

                true
            }
        }
    }

    fn allow_account(&mut self, address: Address, mode: AccessMode) {
        match self.accounts.get_mut(&address) {
            Some((existing, _)) if *existing == AccessMode::Write => {}
            Some((existing, _)) => *existing = mode,
            None => {
                let index = self.total;
                self.total += 1;
                self.accounts.insert(address, (mode, index));
            }
        }
    }

    fn allow_storage(&mut self, address: Address, slot: Slot, mode: AccessMode) {
        match self.storage.get_mut(&(address, slot)) {
            Some((existing, _)) if *existing == AccessMode::Write => {}
            Some((existing, _)) => *existing = mode,
            None => {
                let index = self.total;
                self.total += 1;
                self.storage.insert((address, slot), (mode, index));
            }
        }
    }
}

/// Tracks observed accesses during execution.
///
/// The `Counter` variant is the fast path: it uses a bitset indexed by the
/// sequential position of each entry in the [`AccessSet`]. After execution,
/// the processor checks that all bits are set.
///
/// The `Builder` variant records full access details for simulation, allowing
/// the observed access list to be returned to the caller.
#[derive(Debug, Clone)]
pub(crate) enum AccessObserver {
    /// Bitset tracking which declared entries have been accessed.
    Counter(Vec<u64>),
    /// Records full access details for access-list construction.
    Builder(AccessListBuilder),
}

impl AccessObserver {
    /// Creates a counter-based observer pre-sized for the given access set.
    pub(crate) fn counter(access: &AccessSet) -> Self {
        let bits_needed = access.len();
        let words = bits_needed.div_ceil(64);
        Self::Counter(vec![0u64; words])
    }

    /// Creates a builder-based observer for access-list construction.
    pub(crate) fn builder() -> Self {
        Self::Builder(AccessListBuilder::default())
    }

    /// Records an account access by its index in the access set.
    pub(crate) fn record_account(
        &mut self,
        address: Address,
        mode: AccessMode,
        access: &AccessSet,
    ) {
        match self {
            Self::Counter(bits) => {
                if let Some(index) = access.account_index(address) {
                    let word = index / 64;
                    let bit = index % 64;
                    bits[word] |= 1u64 << bit;
                }
            }
            Self::Builder(builder) => builder.record_account(address, mode),
        }
    }

    /// Records a storage access by its index in the access set.
    pub(crate) fn record_storage(
        &mut self,
        address: Address,
        slot: Slot,
        mode: AccessMode,
        access: &AccessSet,
    ) {
        match self {
            Self::Counter(bits) => {
                if let Some(index) = access.storage_index(address, slot) {
                    let word = index / 64;
                    let bit = index % 64;
                    bits[word] |= 1u64 << bit;
                }
            }
            Self::Builder(builder) => builder.record_storage(address, slot, mode),
        }
    }

    /// Merges a child observer into this one.
    pub(crate) fn merge(&mut self, child: Self) {
        match (self, child) {
            (Self::Counter(parent), Self::Counter(child)) => {
                for (p, c) in parent.iter_mut().zip(child.iter()) {
                    *p |= c;
                }
            }
            (Self::Builder(parent), Self::Builder(child)) => parent.merge(child),
            _ => unreachable!("counter and builder observers cannot be mixed"),
        }
    }

    /// Converts to an access list, if this is a builder.
    pub(crate) fn into_access_list(self) -> Option<AccessList> {
        match self {
            Self::Counter(_) => None,
            Self::Builder(builder) => Some(builder.into_access_list()),
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
