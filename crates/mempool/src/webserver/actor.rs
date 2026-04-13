//! Mempool webserver actor.
//!
//! Owns a byte-bounded FIFO pool of verified transactions. Receives
//! submissions from HTTP handlers and serves batches to the consensus
//! layer via the [`Mailbox`](super::Mailbox).

use super::mailbox::Message;
use commonware_consensus::marshal::Update;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_utils::{Acknowledgement, channel::fallible::OneshotExt};
use constantinople_primitives::VerifiedTransaction;
use std::collections::VecDeque;
use tokio::sync::mpsc;
use tracing::warn;

use super::Mailbox;

/// Mempool actor configuration.
pub struct Config {
    /// Maximum total bytes the pool will hold.
    pub max_pool_bytes: usize,
    /// Maximum bytes returned in a single `propose` call.
    pub max_propose_bytes: usize,
    /// Bounded channel capacity for the actor mailbox.
    pub mailbox_size: usize,
}

/// The mempool actor.
///
/// Create via [`Actor::new`], which returns `(Actor, Mailbox)`. Call
/// [`Actor::start`] to spawn the event loop as a tokio task.
pub struct Actor<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    rx: mpsc::Receiver<Message<C, P, H>>,
    pool: VecDeque<(VerifiedTransaction<P, H>, usize)>,
    pool_bytes: usize,
    max_pool_bytes: usize,
    max_propose_bytes: usize,
}

impl<C, P, H> Actor<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    /// Creates a new mempool actor and its control [`Mailbox`].
    pub fn new(config: Config) -> (Self, Mailbox<C, P, H>) {
        let (tx, rx) = mpsc::channel(config.mailbox_size);
        let mailbox = Mailbox::new(tx);
        (
            Self {
                rx,
                pool: VecDeque::new(),
                pool_bytes: 0,
                max_pool_bytes: config.max_pool_bytes,
                max_propose_bytes: config.max_propose_bytes,
            },
            mailbox,
        )
    }

    /// Spawns the actor event loop on the tokio runtime.
    pub fn start(self) -> tokio::task::JoinHandle<()>
    where
        C: Send + 'static,
        P: Send + 'static,
        H: Send + 'static,
    {
        tokio::spawn(self.run())
    }

    async fn run(mut self) {
        while let Some(message) = self.rx.recv().await {
            match message {
                Message::Submit { transaction, size } => {
                    if self.pool_bytes + size <= self.max_pool_bytes {
                        self.pool_bytes += size;
                        self.pool.push_back((transaction, size));
                    }
                }
                Message::Propose { response } => {
                    let batch = self.drain_propose();
                    response.send_lossy(batch);
                }
                Message::Report(Update::Tip(..)) => {}
                Message::Report(Update::Block(_, acknowledgement)) => {
                    acknowledgement.acknowledge();
                }
            }
        }
        warn!("mempool actor stopped: all senders dropped");
    }

    fn drain_propose(&mut self) -> Vec<VerifiedTransaction<P, H>> {
        let mut batch = Vec::new();
        let mut batch_bytes = 0;
        while let Some((_, size)) = self.pool.front() {
            if batch_bytes + size > self.max_propose_bytes && !batch.is_empty() {
                break;
            }
            let (tx, size) = self.pool.pop_front().expect("front was Some");
            batch_bytes += size;
            self.pool_bytes -= size;
            batch.push(tx);
        }
        batch
    }
}
