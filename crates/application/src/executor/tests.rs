use super::{
    ProposalOutput, State, execute, execute_unique, prepare_transfer, propose, verify_proofs,
};
use commonware_cryptography::{Signer, ed25519, sha256};
use constantinople_primitives::{
    Account, AccountKey, BalanceCommitment, DEFAULT_ACCOUNT_BALANCE, NONCE_BITMAP_CAPACITY, Nonce,
    Payload, PrivateBalance, Transaction, TransactionPublicKey, VerifiedTransaction,
};
use core::num::NonZeroU64;
use rand_core::RngCore;

const NAMESPACE: &[u8] = b"executor-test";

type TestHasher = sha256::Sha256;
type TestTransaction = VerifiedTransaction<TestHasher>;
type TestProposal = ProposalOutput<TestHasher>;

fn test_rng() -> impl RngCore {
    commonware_utils::test_rng()
}

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

    fn public_key(&self) -> TransactionPublicKey {
        TransactionPublicKey::ed25519(self.public_key.clone())
    }

    fn seal(&self, tx: Transaction<sha256::Digest>) -> TestTransaction {
        tx.seal_and_sign(&self.key, NAMESPACE, &mut TestHasher::default())
    }

    fn sign(&self, to: ed25519::PublicKey, value: u64, nonce: u64) -> TestTransaction {
        self.seal(Transaction::new(
            self.public_key(),
            TransactionPublicKey::ed25519(to),
            NonZeroU64::new(value).expect("test values must be non-zero"),
            nonce,
        ))
    }

    /// Funds `balance` by `value`, returning the on-chain fund transaction
    /// declaring the pre-fund commitment.
    fn sign_fund(&self, balance: &mut PrivateBalance, value: u64, nonce: u64) -> TestTransaction {
        let input = balance.commitment();
        balance.fund(value);
        self.seal(Transaction::fund(
            self.public_key(),
            NonZeroU64::new(value).expect("test values must be non-zero"),
            input,
            nonce,
        ))
    }

    /// Proves a private transfer of `amount` out of `balance` to `to`,
    /// returning the transaction and the published amount commitment.
    fn sign_private(
        &self,
        balance: &mut PrivateBalance,
        to: &ed25519::PublicKey,
        amount: u64,
        nonce: u64,
        rng: &mut impl RngCore,
    ) -> (TestTransaction, BalanceCommitment) {
        let input = balance.commitment();
        let (amount_com, proof) = balance.transfer(amount, rng).expect("amount in range");
        let tx = self.seal(Transaction::private_transfer(
            self.public_key(),
            account_key(to),
            input,
            amount_com,
            proof,
            nonce,
        ));
        (tx, amount_com)
    }

    /// Proves a burn of `value` from `balance` back to the public balance.
    fn sign_burn(
        &self,
        balance: &mut PrivateBalance,
        value: u64,
        nonce: u64,
        rng: &mut impl RngCore,
    ) -> TestTransaction {
        let input = balance.commitment();
        let proof = balance.burn(value, rng).expect("burn in range");
        self.seal(Transaction::burn(
            self.public_key(),
            NonZeroU64::new(value).expect("test values must be non-zero"),
            input,
            proof,
            nonce,
        ))
    }
}

fn account(balance: u64, nonce: u64) -> Account {
    Account {
        balance,
        nonce: Nonce::new(nonce, 0),
        private: BalanceCommitment::zero(),
        pending: BalanceCommitment::zero(),
    }
}

fn account_key(public_key: &ed25519::PublicKey) -> AccountKey {
    AccountKey::from_public_key(&TransactionPublicKey::ed25519(public_key.clone()))
}

fn changeset_account(
    changeset: &[(AccountKey, Account)],
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
    let Payload::Transfer { value, .. } = &proposal.invalid[0].value().payload else {
        panic!("expected public transfer payload");
    };
    assert_eq!(value.get(), 7);
}

#[test]
fn proposal_accepts_nonce_inside_run_ahead_window() {
    let signer = TestSigner::from_seed(2);
    let recipient = TestSigner::from_seed(3);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(10, 0));
    accounts.insert(account_key(&recipient.public_key), Account::default());

    let transactions = vec![
        signer.sign(recipient.public_key.clone(), 3, 2),
        signer.sign(recipient.public_key.clone(), 4, 0),
        signer.sign(recipient.public_key.clone(), 2, 1),
    ];
    let proposal = propose(&accounts, transactions);
    let sender = changeset_account(&proposal.changeset, signer.public_key)
        .expect("sender should be updated");
    let recipient = changeset_account(&proposal.changeset, recipient.public_key)
        .expect("recipient should be updated");

    assert_eq!(proposal.valid.len(), 3);
    assert!(proposal.invalid.is_empty());
    assert_eq!(sender.balance, 1);
    assert_eq!(sender.nonce.base, 3);
    assert_eq!(recipient.balance, DEFAULT_ACCOUNT_BALANCE + 9);
}

#[test]
fn proposal_rejects_duplicate_run_ahead_nonce() {
    let signer = TestSigner::from_seed(4);
    let recipient = TestSigner::from_seed(5);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(10, 0));
    accounts.insert(account_key(&recipient.public_key), Account::default());

    let transactions = vec![
        signer.sign(recipient.public_key.clone(), 3, 2),
        signer.sign(recipient.public_key, 4, 2),
    ];
    let proposal = propose(&accounts, transactions);
    let sender = changeset_account(&proposal.changeset, signer.public_key)
        .expect("sender should be updated");

    assert_eq!(proposal.valid.len(), 1);
    assert_eq!(proposal.invalid.len(), 1);
    assert_eq!(sender.balance, 7);
    assert_eq!(sender.nonce.base, 0);
}

#[test]
fn proposal_accepts_far_ahead_nonce_and_rejects_duplicate() {
    let signer = TestSigner::from_seed(6);
    let recipient = TestSigner::from_seed(7);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(10, 0));
    accounts.insert(account_key(&recipient.public_key), Account::default());

    let nonce = NONCE_BITMAP_CAPACITY + 1;
    let transactions = vec![
        signer.sign(recipient.public_key.clone(), 3, nonce),
        signer.sign(recipient.public_key, 4, nonce),
    ];
    let proposal = propose(&accounts, transactions);
    let sender = changeset_account(&proposal.changeset, signer.public_key)
        .expect("sender should be updated");

    assert_eq!(proposal.valid.len(), 1);
    assert_eq!(proposal.invalid.len(), 1);
    assert_eq!(sender.balance, 7);
    assert_eq!(sender.nonce.base, NONCE_BITMAP_CAPACITY + 2);
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
    let changeset = execute_prepared(&accounts, &proposal.valid)
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
fn unique_loaded_execution_matches_overlay_execution() {
    let sender_a = TestSigner::from_seed(20);
    let sender_b = TestSigner::from_seed(21);
    let recipient_a = TestSigner::from_seed(22);
    let recipient_b = TestSigner::from_seed(23);

    let mut accounts = State::new();
    accounts.insert(account_key(&sender_a.public_key), account(11, 0));
    accounts.insert(account_key(&sender_b.public_key), account(13, 0));
    accounts.insert(account_key(&recipient_a.public_key), account(5, 0));
    accounts.insert(account_key(&recipient_b.public_key), account(7, 0));

    let transactions = [
        sender_a.sign(recipient_a.public_key, 4, 0),
        sender_b.sign(recipient_b.public_key, 6, 0),
    ];
    let transfers = transactions
        .iter()
        .map(prepare_transfer)
        .collect::<Option<Vec<_>>>()
        .expect("test transactions should prepare");
    let loaded = transfers
        .iter()
        .flat_map(|transfer| {
            [
                accounts[&transfer.sender],
                accounts[transfer
                    .recipient()
                    .expect("public transfers have recipients")],
            ]
        })
        .collect::<Vec<_>>();

    assert_eq!(
        execute_unique(&transfers, &loaded),
        execute(&accounts, &transfers)
    );
}

#[test]
fn self_transfer_only_bumps_nonce() {
    let signer = TestSigner::from_seed(0);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(9, 3));

    let transactions = vec![signer.sign(signer.public_key.clone(), 4, 3)];
    let proposal = propose(&accounts, transactions);
    let changeset = execute_prepared(&accounts, &proposal.valid)
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
    assert!(execute_prepared(&accounts, &proposal.invalid).is_none());
}

#[test]
fn fund_private_transfer_burn_happy_path() {
    let mut rng = test_rng();
    let signer = TestSigner::from_seed(50);
    let recipient = TestSigner::from_seed(51);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(100, 0));
    accounts.insert(account_key(&recipient.public_key), Account::default());

    // Chain: fund 40 -> send committed 15 -> burn 10.
    let mut balance = PrivateBalance::empty();
    let tx_fund = signer.sign_fund(&mut balance, 40, 0);
    let (tx_send, amount) =
        signer.sign_private(&mut balance, &recipient.public_key, 15, 1, &mut rng);
    let tx_burn = signer.sign_burn(&mut balance, 10, 2, &mut rng);
    let expected_private = balance.commitment();

    let proposal = propose(&accounts, vec![tx_fund, tx_send, tx_burn]);

    assert_eq!(proposal.valid.len(), 3);
    assert!(proposal.invalid.is_empty());

    let sender = changeset_account(&proposal.changeset, signer.public_key)
        .expect("sender should be updated");
    assert_eq!(sender.balance, 100 - 40 + 10);
    assert_eq!(sender.nonce.base, 3);
    assert_eq!(sender.private, expected_private);
    assert_eq!(sender.pending, BalanceCommitment::zero());

    let recipient = changeset_account(&proposal.changeset, recipient.public_key)
        .expect("recipient should be updated");
    assert_eq!(recipient.balance, DEFAULT_ACCOUNT_BALANCE);
    assert_eq!(recipient.private, BalanceCommitment::zero());
    assert_eq!(recipient.pending, BalanceCommitment::zero().add(&amount));
}

#[test]
fn proposer_packs_private_chain_submitted_out_of_order() {
    let mut rng = test_rng();
    let signer = TestSigner::from_seed(52);
    let recipient = TestSigner::from_seed(53);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(100, 0));
    accounts.insert(account_key(&recipient.public_key), Account::default());

    // Build the chain in chain order (proving is sequential)...
    let mut balance = PrivateBalance::empty();
    let tx_a = signer.sign_fund(&mut balance, 40, 0);
    let (tx_b, _) = signer.sign_private(&mut balance, &recipient.public_key, 15, 1, &mut rng);
    let tx_c = signer.sign_burn(&mut balance, 10, 2, &mut rng);

    // ...but submit in a scrambled pool order: the proposer must repack to [A, B, C].
    let proposal = propose(&accounts, vec![tx_b.clone(), tx_a.clone(), tx_c.clone()]);

    assert_eq!(
        proposal.valid,
        vec![tx_a.clone(), tx_b.clone(), tx_c.clone()]
    );
    assert!(proposal.invalid.is_empty());

    // The packed block replays strictly in order.
    let in_order =
        execute_prepared(&accounts, &proposal.valid).expect("packed proposal must replay in order");
    assert_eq!(proposal.changeset, in_order);

    let direct = propose(&accounts, vec![tx_a, tx_b, tx_c]);
    assert_eq!(proposal.changeset, direct.changeset);
}

#[test]
fn unlinkable_private_transfer_is_rejected() {
    let mut rng = test_rng();
    let signer = TestSigner::from_seed(54);
    let recipient = TestSigner::from_seed(55);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(100, 0));
    accounts.insert(account_key(&recipient.public_key), Account::default());

    // A valid proof, but against a private balance the account never funded:
    // its declared input commitment has no predecessor on-chain.
    let mut orphan = PrivateBalance::empty();
    orphan.fund(123);
    let (tx, _) = signer.sign_private(&mut orphan, &recipient.public_key, 5, 0, &mut rng);
    let proposal = propose(&accounts, vec![tx]);

    assert!(proposal.valid.is_empty());
    assert_eq!(proposal.invalid.len(), 1);
    assert!(proposal.changeset.is_empty());
}

#[test]
fn bad_proof_is_rejected() {
    let signer = TestSigner::from_seed(56);
    let recipient = TestSigner::from_seed(57);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(100, 0));
    accounts.insert(account_key(&recipient.public_key), Account::default());

    // A proof bound to a different amount commitment than the one published.
    let mut balance = PrivateBalance::empty();
    balance.fund(100);
    let input = balance.commitment();
    let (_, proof) = balance
        .transfer(5, &mut commonware_utils::test_rng())
        .expect("in range");

    let transaction = signer.seal(Transaction::<sha256::Digest>::from_payload(
        signer.public_key(),
        Payload::PrivateTransfer {
            to: account_key(&recipient.public_key),
            sender_commitment: input,
            amount: BalanceCommitment::commit(5),
            proof,
        },
        0,
    ));

    // Preparation no longer verifies proofs — that happens in the batch pass.
    assert!(prepare_transfer(&transaction).is_some());
    assert!(
        !verify_proofs(core::iter::once(&transaction)),
        "a proof not bound to the published commitment must fail batch verification"
    );

    // The proposer's batch filter therefore excludes it from the block.
    let proposal = propose(&accounts, vec![transaction]);
    assert!(proposal.valid.is_empty());
    assert_eq!(proposal.invalid.len(), 1);
    assert!(proposal.changeset.is_empty());
}

#[test]
fn batch_verification_accepts_valid_block_and_rejects_tampered() {
    let mut rng = test_rng();
    let signer = TestSigner::from_seed(70);
    let recipient = TestSigner::from_seed(71);

    // A funded account with a chain of valid private-side transactions.
    let mut balance = PrivateBalance::empty();
    let tx_fund = signer.sign_fund(&mut balance, 40, 0);
    let (tx_send, _) = signer.sign_private(&mut balance, &recipient.public_key, 15, 1, &mut rng);
    let tx_burn = signer.sign_burn(&mut balance, 10, 2, &mut rng);
    let block = [tx_fund, tx_send.clone(), tx_burn];

    assert!(
        verify_proofs(block.iter()),
        "a block of valid proofs must batch-verify"
    );

    // Tamper one transfer's published amount so its proof no longer binds.
    let Payload::PrivateTransfer {
        to,
        sender_commitment,
        proof,
        ..
    } = tx_send.value().payload.clone()
    else {
        panic!("expected a private transfer");
    };
    let tampered = signer.seal(Transaction::<sha256::Digest>::from_payload(
        signer.public_key(),
        Payload::PrivateTransfer {
            to,
            sender_commitment,
            amount: BalanceCommitment::commit(999),
            proof,
        },
        1,
    ));
    assert!(
        !verify_proofs(core::iter::once(&tampered)),
        "tampering any proof must fail the batch"
    );
}

#[test]
fn incoming_payment_does_not_disturb_recipient_chain() {
    let mut rng = test_rng();
    let alice = TestSigner::from_seed(58);
    let bob = TestSigner::from_seed(59);
    let mut accounts = State::new();
    accounts.insert(account_key(&alice.public_key), account(100, 0));
    accounts.insert(account_key(&bob.public_key), account(100, 0));

    // Bob runs his own outgoing chain while Alice pays him mid-chain.
    let mut bob_balance = PrivateBalance::empty();
    let bob_fund = bob.sign_fund(&mut bob_balance, 30, 0);
    let (bob_send, _) = bob.sign_private(&mut bob_balance, &alice.public_key, 10, 1, &mut rng);
    let bob_expected_private = bob_balance.commitment();

    let mut alice_balance = PrivateBalance::empty();
    let alice_fund = alice.sign_fund(&mut alice_balance, 20, 0);
    let (alice_send, alice_amount) =
        alice.sign_private(&mut alice_balance, &bob.public_key, 8, 1, &mut rng);

    let proposal = propose(&accounts, vec![bob_fund, alice_fund, alice_send, bob_send]);

    assert_eq!(proposal.valid.len(), 4);
    assert!(proposal.invalid.is_empty());

    let bob_account =
        changeset_account(&proposal.changeset, bob.public_key).expect("bob should be updated");
    // Bob's outgoing chain advanced as if the incoming payment never happened.
    assert_eq!(bob_account.private, bob_expected_private);
    assert_eq!(
        bob_account.pending,
        BalanceCommitment::zero().add(&alice_amount)
    );
}

#[test]
fn execute_rejects_out_of_chain_order_block() {
    let mut rng = test_rng();
    let signer = TestSigner::from_seed(60);
    let recipient = TestSigner::from_seed(61);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(100, 0));
    accounts.insert(account_key(&recipient.public_key), Account::default());

    let mut balance = PrivateBalance::empty();
    let tx_fund = signer.sign_fund(&mut balance, 40, 0);
    let (tx_send, _) = signer.sign_private(&mut balance, &recipient.public_key, 15, 1, &mut rng);

    // Block order [send, fund] is the reverse of chain order.
    let transfers = [tx_send, tx_fund]
        .iter()
        .map(prepare_transfer)
        .collect::<Option<Vec<_>>>()
        .expect("test transactions should prepare");

    assert!(
        execute(&accounts, &transfers).is_none(),
        "blocks with out-of-chain-order private transfers must be rejected"
    );
}

#[test]
fn unique_execution_matches_overlay_execution_for_private_actions() {
    let mut rng = test_rng();
    let funder = TestSigner::from_seed(62);
    let sender = TestSigner::from_seed(63);
    let recipient = TestSigner::from_seed(64);

    // The sender starts with a funded private balance on-chain.
    let mut sender_state = PrivateBalance::empty();
    sender_state.fund(50);
    let mut sender_account = account(10, 0);
    sender_account.private = sender_state.commitment();

    let mut accounts = State::new();
    accounts.insert(account_key(&funder.public_key), account(100, 0));
    accounts.insert(account_key(&sender.public_key), sender_account);
    accounts.insert(account_key(&recipient.public_key), Account::default());

    let mut funder_balance = PrivateBalance::empty();
    let funder_fund = funder.sign_fund(&mut funder_balance, 25, 0);
    let (sender_send, _) =
        sender.sign_private(&mut sender_state, &recipient.public_key, 5, 0, &mut rng);
    let transactions = [funder_fund, sender_send];
    let transfers = transactions
        .iter()
        .map(prepare_transfer)
        .collect::<Option<Vec<_>>>()
        .expect("test transactions should prepare");
    let loaded = transfers
        .iter()
        .flat_map(|transfer| {
            let mut entries = vec![accounts[&transfer.sender]];
            if let Some(recipient) = transfer.recipient() {
                entries.push(accounts[recipient]);
            }
            entries
        })
        .collect::<Vec<_>>();

    let unique = execute_unique(&transfers, &loaded);
    assert!(unique.is_some());
    assert_eq!(unique, execute(&accounts, &transfers));
}

#[test]
fn unique_execution_rejects_wrong_commitment() {
    let mut rng = test_rng();
    let signer = TestSigner::from_seed(65);
    let recipient = TestSigner::from_seed(66);

    // The proof is valid, but the on-chain account's private commitment does
    // not match the transfer's declared input (the account never funded 99).
    let mut orphan = PrivateBalance::empty();
    orphan.fund(99);
    let (tx, _) = signer.sign_private(&mut orphan, &recipient.public_key, 5, 0, &mut rng);

    let accounts = vec![account(100, 0), Account::default()];
    let transfers = [tx]
        .iter()
        .map(prepare_transfer)
        .collect::<Option<Vec<_>>>()
        .expect("test transactions should prepare");

    assert!(execute_unique(&transfers, &accounts).is_none());
}

fn execute_prepared(
    accounts: &State,
    transactions: &[TestTransaction],
) -> Option<super::Changeset> {
    let transfers = transactions
        .iter()
        .map(prepare_transfer)
        .collect::<Option<Vec<_>>>()?;
    execute(accounts, &transfers)
}
