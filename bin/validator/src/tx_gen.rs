use commonware_consensus::{Reporter, marshal::Update, simplex::types::Context};
use commonware_cryptography::{Digest, Hasher, PublicKey, Signer};
use commonware_macros::select_loop;
use commonware_parallel::Strategy;
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell};
use commonware_utils::{
    Acknowledgement, NZU64,
    channel::fallible::{AsyncFallibleExt, OneshotExt},
};
use constantinople_mempool::TransactionSource;
use constantinople_primitives::{
    Address, Header, SealedBlock, SignedTransaction, Transaction, VerifiedTransaction,
};
use rand_core::CryptoRngCore;
use std::{collections::HashSet, marker::PhantomData};
use tokio::sync::{mpsc, oneshot};

pub struct TransactionGenerator<E, C, P, H, S>
where
    E: Spawner,
    C: Digest,
    P: Signer,
    H: Hasher,
    S: Strategy,
{
    context: ContextCell<E>,
    mailbox: mpsc::Receiver<Message<C, P::PublicKey, H>>,
    keys: Vec<(P, Address)>,
    owned_addresses: HashSet<Address>,
    strategy: S,
    _marker: PhantomData<C>,
}

impl<E, C, P, H, S> TransactionGenerator<E, C, P, H, S>
where
    E: Spawner + CryptoRngCore,
    C: Digest,
    P: Signer,
    H: Hasher,
    S: Strategy,
{
    pub fn new(mut context: E, n_keys: usize, strategy: S) -> (Self, Mailbox<C, P::PublicKey, H>) {
        let mut hasher = H::default();
        let keys = (0..n_keys)
            .map(|_| {
                let signer = P::random(&mut context);
                let address = Address::from_public_key(&mut hasher, &signer.public_key());
                (signer, address)
            })
            .collect::<Vec<_>>();
        let owned_addresses = keys.iter().map(|(_, address)| *address).collect();
        let (sender, mailbox) = mpsc::channel(1024);

        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                keys,
                owned_addresses,
                strategy,
                _marker: PhantomData,
            },
            Mailbox {
                sender,
                _marker: PhantomData,
            },
        )
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    async fn run(mut self) {
        let mut transactions = TransactionBuffer::new(
            self.owned_addresses.clone(),
            generate_transactions(&self.keys, &self.strategy, 0),
        );

        select_loop! {
            self.context,
            on_stopped => {},
            Some(message) = self.mailbox.recv() else break => {
                match message {
                    Message::GetTransactions { response } => {
                        response.send_lossy(transactions.current_transactions());
                        transactions.schedule_next_with(|generation| {
                            generate_transactions(&self.keys, &self.strategy, generation)
                        });
                    }
                    Message::Report(Update::Tip(..)) => {}
                    Message::Report(Update::Block(block, acknowledgement)) => {
                        if transactions.finalized_current_generation(&block.body) {
                            transactions.advance_with(|generation| {
                                generate_transactions(&self.keys, &self.strategy, generation)
                            });
                        }
                        acknowledgement.acknowledge();
                    }
                }
            }
        }
    }
}

fn generate_transactions<P, H, S>(
    keys: &[(P, Address)],
    strategy: &S,
    generation: u64,
) -> Vec<VerifiedTransaction<P::PublicKey, H>>
where
    P: Signer,
    H: Hasher,
    S: Strategy,
{
    strategy.map_init_collect_vec(
        keys.iter().enumerate(),
        H::default,
        |hasher, (i, (signer, _))| {
            let to = keys[(i + 1) % keys.len()].1;
            Transaction::new(signer.public_key(), to, NZU64!(1), generation).seal_and_sign_verified(
                signer,
                b"constantinople-tx",
                hasher,
            )
        },
    )
}

struct TransactionBuffer<P, H>
where
    P: PublicKey,
    H: Hasher,
{
    current_generation: u64,
    current_transactions: Vec<VerifiedTransaction<P, H>>,
    next_transactions: Option<Vec<VerifiedTransaction<P, H>>>,
    owned_addresses: HashSet<Address>,
}

impl<P, H> TransactionBuffer<P, H>
where
    P: PublicKey,
    H: Hasher,
{
    const fn new(
        owned_addresses: HashSet<Address>,
        current_transactions: Vec<VerifiedTransaction<P, H>>,
    ) -> Self {
        Self {
            current_generation: 0,
            current_transactions,
            next_transactions: None,
            owned_addresses,
        }
    }

    fn current_transactions(&self) -> Vec<VerifiedTransaction<P, H>> {
        self.current_transactions.clone()
    }

    fn schedule_next_with<F>(&mut self, generate: F)
    where
        F: FnOnce(u64) -> Vec<VerifiedTransaction<P, H>>,
    {
        if self.next_transactions.is_some() {
            return;
        }

        let generation = self.current_generation + 1;
        self.next_transactions = Some(generate(generation));
    }

    fn advance_with<F>(&mut self, generate: F)
    where
        F: FnOnce(u64) -> Vec<VerifiedTransaction<P, H>>,
    {
        self.current_generation += 1;
        let generation = self.current_generation;
        self.current_transactions = self
            .next_transactions
            .take()
            .unwrap_or_else(|| generate(generation));
    }

    fn finalized_current_generation(
        &self,
        finalized_transactions: &[SignedTransaction<P, H>],
    ) -> bool {
        if finalized_transactions.len() != self.current_transactions.len() {
            return false;
        }

        finalized_transactions.iter().all(|transaction| {
            transaction.value().nonce == self.current_generation && self.owns_sender(transaction)
        })
    }

    fn owns_sender(&self, transaction: &SignedTransaction<P, H>) -> bool {
        let Some(sender) = transaction.value().sender() else {
            return false;
        };

        let address = Address::from_public_key(&mut H::default(), sender);
        self.owned_addresses.contains(&address)
    }
}

pub enum Message<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    GetTransactions {
        response: oneshot::Sender<Vec<VerifiedTransaction<P, H>>>,
    },
    Report(Update<SealedBlock<C, P, H>>),
}

#[derive(Clone)]
pub struct Mailbox<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    sender: mpsc::Sender<Message<C, P, H>>,
    _marker: PhantomData<(C, P, H)>,
}

impl<C, P, H> TransactionSource<C, P, H> for Mailbox<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    async fn propose(
        &mut self,
        _: &Header<C, H::Digest, P>,
        _: &Context<C, P>,
    ) -> Vec<VerifiedTransaction<P, H>> {
        self.sender
            .request(|response| Message::GetTransactions { response })
            .await
            .expect("mailbox closed")
    }
}

impl<C, P, H> Reporter for Mailbox<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    type Activity = Update<SealedBlock<C, P, H>>;

    async fn report(&mut self, activity: Self::Activity) {
        self.sender.send_lossy(Message::Report(activity)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::{TransactionBuffer, generate_transactions};
    use commonware_cryptography::{Hasher, Sha256, Signer as _, ed25519};
    use commonware_parallel::Sequential;
    use constantinople_primitives::{Address, VerifiedTransaction};

    type TestHasher = Sha256;
    type TestPrivateKey = ed25519::PrivateKey;
    type TestPublicKey = ed25519::PublicKey;

    fn test_keys(start_seed: u64, count: u64) -> Vec<(TestPrivateKey, Address)> {
        (start_seed..start_seed + count)
            .map(|seed| {
                let signer = TestPrivateKey::from_seed(seed);
                let address =
                    Address::from_public_key(&mut TestHasher::default(), &signer.public_key());
                (signer, address)
            })
            .collect()
    }

    fn transaction_buffer(
        keys: &[(TestPrivateKey, Address)],
    ) -> TransactionBuffer<TestPublicKey, TestHasher> {
        let owned_addresses = keys.iter().map(|(_, address)| *address).collect();
        let current_transactions = generate_transactions(keys, &Sequential, 0);
        TransactionBuffer::new(owned_addresses, current_transactions)
    }

    fn transaction_digests(
        transactions: &[VerifiedTransaction<TestPublicKey, TestHasher>],
    ) -> Vec<<TestHasher as Hasher>::Digest> {
        transactions
            .iter()
            .map(|transaction| *transaction.message_digest())
            .collect()
    }

    #[test]
    fn first_fetch_returns_transactions_and_primes_the_next_batch() {
        let keys = test_keys(0, 4);
        let mut transactions = transaction_buffer(&keys);

        let first = transactions.current_transactions();
        transactions
            .schedule_next_with(|generation| generate_transactions(&keys, &Sequential, generation));

        assert_eq!(first.len(), keys.len());
        assert!(
            first
                .iter()
                .all(|transaction| transaction.value().nonce == 0)
        );
        assert!(
            transactions
                .next_transactions
                .as_ref()
                .expect("next batch should be prepared")
                .iter()
                .all(|transaction| transaction.value().nonce == 1)
        );
    }

    #[test]
    fn proposal_requests_reuse_the_current_batch_until_it_finalizes() {
        let keys = test_keys(0, 4);
        let mut transactions = transaction_buffer(&keys);

        let first = transactions.current_transactions();
        transactions
            .schedule_next_with(|generation| generate_transactions(&keys, &Sequential, generation));
        let second = transactions.current_transactions();

        assert_eq!(transaction_digests(&first), transaction_digests(&second));
        assert!(
            first
                .iter()
                .all(|transaction| transaction.value().nonce == 0)
        );
    }

    #[test]
    fn finalized_current_batch_promotes_the_prepared_next_batch() {
        let keys = test_keys(0, 4);
        let mut transactions = transaction_buffer(&keys);

        let current = transactions.current_transactions();
        transactions
            .schedule_next_with(|generation| generate_transactions(&keys, &Sequential, generation));
        let finalized = current
            .into_iter()
            .map(|transaction| transaction.into_inner())
            .collect::<Vec<_>>();

        assert!(transactions.finalized_current_generation(&finalized));

        transactions
            .advance_with(|generation| generate_transactions(&keys, &Sequential, generation));

        assert_eq!(transactions.current_generation, 1);
        assert!(
            transactions
                .current_transactions
                .iter()
                .all(|transaction| transaction.value().nonce == 1)
        );
        assert!(transactions.next_transactions.is_none());
    }

    #[test]
    fn unrelated_finalized_blocks_do_not_advance_the_current_batch() {
        let keys = test_keys(0, 4);
        let transactions = transaction_buffer(&keys);
        let other_keys = test_keys(100, 4);
        let finalized = generate_transactions(&other_keys, &Sequential, 0)
            .into_iter()
            .map(|transaction| transaction.into_inner())
            .collect::<Vec<_>>();

        assert!(!transactions.finalized_current_generation(&finalized));
    }
}
