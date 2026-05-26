//! Mailbox for bootstrapper actor control messages.
//!
//! The bootstrapper keeps a fetch request open until it discovers a usable
//! initial state-sync floor.

use super::{EngineMarshalMailbox, InitialTarget};
use commonware_cryptography::{Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_utils::channel::{fallible::AsyncFallibleExt, mpsc, oneshot};

pub(super) enum Message<H, P, V>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    Attach {
        marshal: EngineMarshalMailbox<H, P, V>,
    },
    FetchInitialTarget {
        response: oneshot::Sender<InitialTarget<P, V>>,
    },
}

/// Mailbox for bootstrapper actor control requests.
pub struct Mailbox<H, P, V>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    sender: mpsc::Sender<Message<H, P, V>>,
}

impl<H, P, V> Clone for Mailbox<H, P, V>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<H, P, V> Mailbox<H, P, V>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    pub(super) const fn new(sender: mpsc::Sender<Message<H, P, V>>) -> Self {
        Self { sender }
    }

    /// Attach the local marshal mailbox once the engine has been built.
    pub async fn attach(&self, marshal: EngineMarshalMailbox<H, P, V>) {
        self.sender.send_lossy(Message::Attach { marshal }).await;
    }

    /// Wait until the actor discovers an initial state-sync floor.
    pub async fn fetch_initial_target(&self) -> Option<InitialTarget<P, V>> {
        self.sender
            .request(|response| Message::FetchInitialTarget { response })
            .await
    }
}
