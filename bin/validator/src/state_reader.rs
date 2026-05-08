//! [`AccountReader`] adapter that forwards lookups to the validator's state
//! database.

use commonware_cryptography::{Hasher, PublicKey};
use commonware_runtime::{Clock, Metrics, Storage};
use constantinople_engine::types::StateSyncDb;
use constantinople_mempool::webserver::AccountReader;
use constantinople_primitives::{Account, AccountKey};
use futures::future::{BoxFuture, FutureExt};

/// Forwards [`AccountReader::get`] to the attached state database.
pub struct StateDbReader<E, H, P>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
    H: Hasher,
    P: PublicKey,
{
    db: StateSyncDb<E, H, P>,
}

impl<E, H, P> StateDbReader<E, H, P>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
    H: Hasher,
    P: PublicKey,
{
    pub const fn new(db: StateSyncDb<E, H, P>) -> Self {
        Self { db }
    }
}

impl<E, H, P> AccountReader<P> for StateDbReader<E, H, P>
where
    E: Storage + Clock + Metrics + Send + Sync + 'static,
    H: Hasher,
    P: PublicKey,
{
    fn get<'a>(&'a self, public_key: P) -> BoxFuture<'a, Option<Account>> {
        async move {
            let db = self.db.read().await;
            db.get(&AccountKey::from_public_key(&public_key))
                .await
                .ok()
                .flatten()
        }
        .boxed()
    }
}
