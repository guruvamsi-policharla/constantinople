//! Read-only account lookup for the mempool HTTP server.

use commonware_cryptography::PublicKey;
use constantinople_primitives::Account;
use futures::future::BoxFuture;

/// Reads committed account state. Backed by the validator's state database.
pub trait AccountReader<P>: Send + Sync + 'static
where
    P: PublicKey,
{
    /// Returns the account for `public_key`, or `None` if it has not been written.
    fn get<'a>(&'a self, public_key: P) -> BoxFuture<'a, Option<Account>>;
}
