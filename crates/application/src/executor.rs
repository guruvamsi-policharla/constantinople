//! Transfer execution for the Constantinople account model.

use bytes::BytesMut;
use commonware_codec::Write as _;
use commonware_cryptography::{Hasher, PublicKey};
use constantinople_primitives::{Account, AccountKey, SignedTransaction};
use hashbrown::HashMap;

/// Fully loaded account state for one execution batch.
pub type State<P> = HashMap<AccountKey<P>, Account>;

/// Deterministic account writes produced by execution.
pub type Changeset<P> = Vec<(AccountKey<P>, Account)>;

/// Transfer data used by the executor.
#[derive(Debug, Clone)]
pub struct PreparedTransfer<P, H>
where
    H: Hasher,
    P: PublicKey,
{
    /// Sender account key.
    pub sender: AccountKey<P>,
    /// Recipient account key.
    pub recipient: AccountKey<P>,
    /// Amount transferred.
    pub value: u64,
    /// Sender nonce required by the transaction.
    pub nonce: u64,
    /// Transaction digest written to the transaction history.
    pub digest: H::Digest,
}

/// Transaction paired with its prepared execution data.
#[derive(Debug, Clone)]
pub struct PreparedTransaction<P, H>
where
    H: Hasher,
    P: PublicKey,
{
    /// Original signed transaction.
    pub transaction: SignedTransaction<P, H>,
    /// Prepared transfer data.
    pub transfer: PreparedTransfer<P, H>,
}

/// Proposal-side transaction preparation.
#[derive(Debug)]
pub struct ProposalInput<P, H>
where
    H: Hasher,
    P: PublicKey,
{
    /// Transactions with decodable execution metadata.
    pub candidates: Vec<PreparedTransaction<P, H>>,
    /// Transactions rejected before account execution.
    pub invalid: Vec<SignedTransaction<P, H>>,
}

/// The result of proposal-side filtering and execution.
#[derive(Debug)]
pub struct ProposalOutput<P, H>
where
    H: Hasher,
    P: PublicKey,
{
    /// Transactions included in the proposed block.
    pub valid: Vec<SignedTransaction<P, H>>,
    /// Transactions excluded from the proposed block.
    pub invalid: Vec<SignedTransaction<P, H>>,
    /// Persistent account writes produced by included transactions.
    pub changeset: Changeset<P>,
}

/// Prepares transactions for proposal-side execution.
pub fn prepare_proposal<P, H>(transactions: Vec<SignedTransaction<P, H>>) -> ProposalInput<P, H>
where
    H: Hasher,
    P: PublicKey,
{
    let mut candidates = Vec::with_capacity(transactions.len());
    let mut invalid = Vec::new();

    for transaction in transactions {
        let Some(transfer) = prepare_transfer(&transaction) else {
            invalid.push(transaction);
            continue;
        };
        candidates.push(PreparedTransaction {
            transaction,
            transfer,
        });
    }

    ProposalInput {
        candidates,
        invalid,
    }
}

/// Executes proposal candidates and filters statically invalid transfers.
pub fn propose_prepared<P, H>(state: &State<P>, input: ProposalInput<P, H>) -> ProposalOutput<P, H>
where
    H: Hasher,
    P: PublicKey,
{
    let mut overlay = Overlay::new(state, input.candidates.len());
    let mut valid = Vec::with_capacity(input.candidates.len());
    let mut invalid = input.invalid;

    for candidate in input.candidates {
        if apply_transfer(&mut overlay, &candidate.transfer) {
            valid.push(candidate.transaction);
        } else {
            invalid.push(candidate.transaction);
        }
    }

    ProposalOutput {
        valid,
        invalid,
        changeset: overlay.into_changeset(),
    }
}

/// Prepares and executes proposal transactions.
pub fn propose<P, H>(
    state: &State<P>,
    transactions: Vec<SignedTransaction<P, H>>,
) -> ProposalOutput<P, H>
where
    H: Hasher,
    P: PublicKey,
{
    propose_prepared(state, prepare_proposal(transactions))
}

/// Prepares one transaction for account execution.
pub fn prepare_transfer<P, H>(
    transaction: &SignedTransaction<P, H>,
) -> Option<PreparedTransfer<P, H>>
where
    H: Hasher,
    P: PublicKey,
{
    let transfer = transaction.value();
    Some(PreparedTransfer {
        sender: account_key_from_sender(transfer.sender_lazy())?,
        recipient: transfer.to.clone(),
        value: transfer.value.get(),
        nonce: transfer.nonce,
        digest: *transaction.message_digest(),
    })
}

/// Executes already prepared transfers.
pub fn execute<P, H>(state: &State<P>, transfers: &[PreparedTransfer<P, H>]) -> Option<Changeset<P>>
where
    H: Hasher,
    P: PublicKey,
{
    let mut overlay = Overlay::new(state, transfers.len());

    for transfer in transfers {
        if !apply_transfer(&mut overlay, transfer) {
            return None;
        }
    }

    Some(overlay.into_changeset())
}

/// Prepares and executes signed transactions.
pub fn execute_transactions<P, H>(
    state: &State<P>,
    transactions: &[SignedTransaction<P, H>],
) -> Option<Changeset<P>>
where
    H: Hasher,
    P: PublicKey,
{
    let transfers = transactions
        .iter()
        .map(prepare_transfer)
        .collect::<Option<Vec<_>>>()?;
    execute(state, &transfers)
}

fn account_key_from_sender<P>(
    sender: &commonware_codec::types::lazy::Lazy<P>,
) -> Option<AccountKey<P>>
where
    P: PublicKey,
{
    let mut bytes = BytesMut::with_capacity(P::SIZE);
    sender.write(&mut bytes);
    AccountKey::from_bytes(bytes.freeze())
}

#[derive(Debug)]
struct Overlay<'a, P>
where
    P: PublicKey,
{
    base: &'a State<P>,
    writes: HashMap<AccountKey<P>, Account>,
}

impl<'a, P> Overlay<'a, P>
where
    P: PublicKey,
{
    fn new(base: &'a State<P>, transaction_count: usize) -> Self {
        let capacity = base.len().min(transaction_count.saturating_mul(2));
        Self {
            base,
            writes: HashMap::with_capacity(capacity),
        }
    }

    fn get(&self, account_key: &AccountKey<P>) -> Option<Account> {
        self.writes
            .get(account_key)
            .or_else(|| self.base.get(account_key))
            .copied()
    }

    fn set(&mut self, account_key: AccountKey<P>, account: Account) {
        self.writes.insert(account_key, account);
    }

    fn into_changeset(self) -> Changeset<P> {
        let mut changeset: Changeset<P> = self.writes.into_iter().collect();
        changeset.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        changeset
    }
}

fn apply_transfer<P, H>(state: &mut Overlay<'_, P>, transfer: &PreparedTransfer<P, H>) -> bool
where
    H: Hasher,
    P: PublicKey,
{
    let Some(mut sender) = state.get(&transfer.sender) else {
        return false;
    };
    if sender.nonce != transfer.nonce || sender.balance < transfer.value {
        return false;
    }
    let Some(next_nonce) = sender.nonce.checked_add(1) else {
        return false;
    };

    sender.nonce = next_nonce;
    if transfer.sender == transfer.recipient {
        state.set(transfer.sender.clone(), sender);
        return true;
    }

    let Some(mut recipient) = state.get(&transfer.recipient) else {
        return false;
    };
    let Some(recipient_balance) = recipient.balance.checked_add(transfer.value) else {
        return false;
    };

    sender.balance -= transfer.value;
    recipient.balance = recipient_balance;
    state.set(transfer.sender.clone(), sender);
    state.set(transfer.recipient.clone(), recipient);

    true
}

#[cfg(test)]
mod tests {
    use super::{ProposalOutput, State, execute_transactions, propose};
    use commonware_cryptography::{Signer, ed25519, sha256};
    use constantinople_primitives::{
        Account, AccountKey, Signable, Transaction, VerifiedTransaction,
    };
    use core::num::NonZeroU64;

    const NAMESPACE: &[u8] = b"executor-test";

    type TestHasher = sha256::Sha256;
    type TestTransaction = VerifiedTransaction<ed25519::PublicKey, TestHasher>;
    type TestProposal = ProposalOutput<ed25519::PublicKey, TestHasher>;

    #[derive(Debug, Clone)]
    struct TestSigner {
        key: ed25519::PrivateKey,
        public_key: ed25519::PublicKey,
    }

    impl TestSigner {
        fn from_seed(seed: u64) -> Self {
            let key = ed25519::PrivateKey::from_seed(seed);
            let public_key = key.public_key();
            Self { key, public_key }
        }

        fn sign(&self, to: ed25519::PublicKey, value: u64, nonce: u64) -> TestTransaction {
            Transaction::new(
                self.key.public_key(),
                to,
                NonZeroU64::new(value).expect("test values must be non-zero"),
                nonce,
            )
            .seal_and_sign(&self.key, NAMESPACE, &mut TestHasher::default())
        }
    }

    fn account(balance: u64, nonce: u64) -> Account {
        Account { balance, nonce }
    }

    fn account_key(public_key: &ed25519::PublicKey) -> AccountKey<ed25519::PublicKey> {
        AccountKey::from_public_key(public_key)
    }

    fn changeset_account(
        changeset: &[(AccountKey<ed25519::PublicKey>, Account)],
        public_key: ed25519::PublicKey,
    ) -> Option<Account> {
        let account_key = account_key(&public_key);
        changeset
            .iter()
            .find_map(|(candidate, account)| (candidate == &account_key).then_some(*account))
    }

    #[test]
    fn proposal_tracks_pending_nonce_and_balance() {
        let signer = TestSigner::from_seed(0);
        let recipient = TestSigner::from_seed(1);
        let mut accounts = State::new();
        accounts.insert(account_key(&signer.public_key), account(10, 0));
        accounts.insert(account_key(&recipient.public_key), Account::default());

        let transactions = vec![
            signer.sign(recipient.public_key.clone(), 4, 0),
            signer.sign(recipient.public_key.clone(), 7, 1),
            signer.sign(recipient.public_key, 6, 1),
        ];
        let proposal: TestProposal = propose(&accounts, transactions);

        assert_eq!(proposal.valid.len(), 2);
        assert_eq!(proposal.invalid.len(), 1);
        assert_eq!(proposal.valid[0].value().nonce, 0);
        assert_eq!(proposal.valid[1].value().nonce, 1);
        assert_eq!(proposal.invalid[0].value().value.get(), 7);
    }

    #[test]
    fn proposal_and_replay_match_for_transfer_batch() {
        let sender_a = TestSigner::from_seed(10);
        let sender_b = TestSigner::from_seed(11);
        let recipient = TestSigner::from_seed(12);

        let mut accounts = State::new();
        accounts.insert(account_key(&sender_a.public_key), account(11, 0));
        accounts.insert(account_key(&sender_b.public_key), account(13, 0));
        accounts.insert(account_key(&recipient.public_key), account(5, 0));

        let transactions = vec![
            sender_a.sign(recipient.public_key.clone(), 4, 0),
            sender_b.sign(recipient.public_key.clone(), 6, 0),
        ];

        let proposal = propose(&accounts, transactions);
        let changeset = execute_transactions(&accounts, &proposal.valid)
            .expect("valid proposal transactions should execute");

        assert_eq!(proposal.changeset, changeset);
        assert_eq!(
            changeset_account(&changeset, sender_a.public_key),
            Some(account(7, 1))
        );
        assert_eq!(
            changeset_account(&changeset, sender_b.public_key),
            Some(account(7, 1))
        );
        assert_eq!(
            changeset_account(&changeset, recipient.public_key),
            Some(account(15, 0))
        );
    }

    #[test]
    fn self_transfer_only_bumps_nonce() {
        let signer = TestSigner::from_seed(0);
        let mut accounts = State::new();
        accounts.insert(account_key(&signer.public_key), account(9, 3));

        let transactions = vec![signer.sign(signer.public_key.clone(), 4, 3)];
        let proposal = propose(&accounts, transactions);
        let changeset = execute_transactions(&accounts, &proposal.valid)
            .expect("valid proposal transactions should execute");

        assert_eq!(
            changeset_account(&changeset, signer.public_key),
            Some(account(9, 4))
        );
    }

    #[test]
    fn invalid_transfer_does_not_mutate_overlay() {
        let signer = TestSigner::from_seed(30);
        let recipient = TestSigner::from_seed(31);
        let mut accounts = State::new();
        accounts.insert(account_key(&signer.public_key), account(5, 0));
        accounts.insert(account_key(&recipient.public_key), account(0, 0));

        let transactions = vec![
            signer.sign(recipient.public_key.clone(), 6, 0),
            signer.sign(recipient.public_key.clone(), 4, 0),
        ];
        let proposal = propose(&accounts, transactions);

        assert_eq!(proposal.invalid.len(), 1);
        assert_eq!(proposal.valid.len(), 1);
        assert_eq!(
            changeset_account(&proposal.changeset, signer.public_key),
            Some(account(1, 1))
        );
        assert_eq!(
            changeset_account(&proposal.changeset, recipient.public_key),
            Some(account(4, 0))
        );
    }

    #[test]
    fn recipient_overflow_rejects_without_charging_sender() {
        let signer = TestSigner::from_seed(40);
        let recipient = TestSigner::from_seed(41);
        let mut accounts = State::new();
        accounts.insert(account_key(&signer.public_key), account(10, 0));
        accounts.insert(account_key(&recipient.public_key), account(u64::MAX, 0));

        let transactions = vec![signer.sign(recipient.public_key, 1, 0)];
        let proposal = propose(&accounts, transactions);

        assert!(proposal.valid.is_empty());
        assert_eq!(proposal.invalid.len(), 1);
        assert!(proposal.changeset.is_empty());
        assert!(execute_transactions(&accounts, &proposal.invalid).is_none());
    }
}
