//! In-memory processor state.

use super::executor::Changeset;
use commonware_cryptography::PublicKey;
use constantinople_primitives::{Account, AccountKey};
use std::collections::HashMap;

/// Fully loaded account state for one execution batch.
pub type State<P> = HashMap<AccountKey<P>, Account>;

/// Mutable overlay on top of a base [`State`] snapshot.
///
/// Reads fall through to the base when an account key has not been modified.
/// Only modified accounts are stored, so the changeset is the overlay itself.
#[derive(Debug)]
pub(crate) struct Overlay<'a, P>
where
    P: PublicKey,
{
    base: &'a State<P>,
    overlay: HashMap<AccountKey<P>, Account>,
}

impl<'a, P> Overlay<'a, P>
where
    P: PublicKey,
{
    /// Creates an overlay on top of the given base state.
    pub(crate) fn new(base: &'a State<P>) -> Self {
        Self {
            base,
            overlay: HashMap::new(),
        }
    }

    /// Returns the current account for `account_key`.
    pub(crate) fn get(&self, account_key: &AccountKey<P>) -> Option<&Account> {
        self.overlay
            .get(account_key)
            .or_else(|| self.base.get(account_key))
    }

    /// Returns a mutable reference to the account for `account_key`.
    ///
    /// Copies the account from base into the overlay on first mutation.
    pub(crate) fn get_mut(&mut self, account_key: &AccountKey<P>) -> Option<&mut Account> {
        if !self.overlay.contains_key(account_key) {
            let account = *self.base.get(account_key)?;
            self.overlay.insert(account_key.clone(), account);
        }
        self.overlay.get_mut(account_key)
    }

    /// Returns the overlay as a deterministically ordered changeset.
    pub(crate) fn into_changeset(self) -> Changeset<P> {
        let mut changeset: Changeset<P> = self.overlay.into_iter().collect();
        changeset.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        changeset
    }
}
