use super::{
    Changeset, PreparedOperation, PrivateVerifications, State, compute, prepare_operation,
};
use commonware_codec::FixedSize as _;
use commonware_cryptography::{Signer, ed25519, sha256};
use constantinople_primitives::{
    AccountKey, DEFAULT_ACCOUNT_BALANCE, NONCE_BITMAP_CAPACITY, Nonce, StateAccount, Transaction,
    TransactionPublicKey, VerifiedTransaction,
};
use core::num::NonZeroU64;
use std::collections::HashSet;

const NAMESPACE: &[u8] = b"executor-test";

type TestHasher = sha256::Sha256;
type TestTransaction = VerifiedTransaction<TestHasher>;

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
            TransactionPublicKey::ed25519(self.key.public_key()),
            TransactionPublicKey::ed25519(to),
            NonZeroU64::new(value).expect("test values must be non-zero"),
            nonce,
        )
        .seal_and_sign(&self.key, NAMESPACE, &mut TestHasher::default())
    }
}

fn account(balance: u64, nonce: u64) -> StateAccount {
    StateAccount {
        balance,
        nonce: Nonce::new(nonce, 0),
        private: Default::default(),
    }
}

fn account_key(public_key: &ed25519::PublicKey) -> AccountKey {
    AccountKey::from_public_key(&TransactionPublicKey::ed25519(public_key.clone()))
}

fn changeset_account(
    changeset: &[(AccountKey, StateAccount)],
    public_key: ed25519::PublicKey,
) -> StateAccount {
    let account_key = account_key(&public_key);
    changeset
        .iter()
        .find_map(|(candidate, account)| (candidate == &account_key).then(|| account.clone()))
        .expect("account should be in changeset")
}

fn run(accounts: &State, transactions: &[TestTransaction]) -> Option<Changeset> {
    let transfers = transactions
        .iter()
        .map(prepare_operation)
        .collect::<Option<Vec<_>>>()?;
    compute(accounts, &transfers, &mut PrivateVerifications::new())
}

#[test]
fn executes_run_ahead_nonces() {
    let signer = TestSigner::from_seed(2);
    let recipient = TestSigner::from_seed(3);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(10, 0));
    accounts.insert(account_key(&recipient.public_key), StateAccount::default());

    let transactions = vec![
        signer.sign(recipient.public_key.clone(), 3, 2),
        signer.sign(recipient.public_key.clone(), 4, 0),
        signer.sign(recipient.public_key.clone(), 2, 1),
    ];
    let changeset = run(&accounts, &transactions).expect("valid batch should execute");

    let sender = changeset_account(&changeset, signer.public_key);
    let recipient = changeset_account(&changeset, recipient.public_key);
    assert_eq!(sender.balance, 1);
    assert_eq!(sender.nonce.base, 3);
    assert_eq!(recipient.balance, DEFAULT_ACCOUNT_BALANCE + 9);
}

#[test]
fn rejects_insufficient_balance() {
    let signer = TestSigner::from_seed(0);
    let recipient = TestSigner::from_seed(1);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(5, 0));
    accounts.insert(account_key(&recipient.public_key), StateAccount::default());

    let transactions = vec![signer.sign(recipient.public_key, 6, 0)];
    assert!(run(&accounts, &transactions).is_none());
}

#[test]
fn rejects_duplicate_run_ahead_nonce() {
    let signer = TestSigner::from_seed(4);
    let recipient = TestSigner::from_seed(5);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(10, 0));
    accounts.insert(account_key(&recipient.public_key), StateAccount::default());

    let transactions = vec![
        signer.sign(recipient.public_key.clone(), 3, 2),
        signer.sign(recipient.public_key, 4, 2),
    ];
    assert!(run(&accounts, &transactions).is_none());
}

#[test]
fn rejects_far_ahead_duplicate_nonce() {
    let signer = TestSigner::from_seed(6);
    let recipient = TestSigner::from_seed(7);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(10, 0));
    accounts.insert(account_key(&recipient.public_key), StateAccount::default());

    let nonce = NONCE_BITMAP_CAPACITY + 1;
    let transactions = vec![
        signer.sign(recipient.public_key.clone(), 3, nonce),
        signer.sign(recipient.public_key, 4, nonce),
    ];
    assert!(run(&accounts, &transactions).is_none());
}

#[test]
fn executes_multi_sender_batch() {
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
    let changeset = run(&accounts, &transactions).expect("valid batch should execute");

    assert_eq!(
        changeset_account(&changeset, sender_a.public_key),
        account(7, 1)
    );
    assert_eq!(
        changeset_account(&changeset, sender_b.public_key),
        account(7, 1)
    );
    assert_eq!(
        changeset_account(&changeset, recipient.public_key),
        account(15, 0)
    );
}

#[test]
fn credits_apply_to_post_debit_sender_state() {
    let sender_a = TestSigner::from_seed(50);
    let sender_b = TestSigner::from_seed(51);

    let mut accounts = State::new();
    accounts.insert(account_key(&sender_a.public_key), account(10, 0));
    accounts.insert(account_key(&sender_b.public_key), account(10, 0));

    let transactions = vec![
        sender_a.sign(sender_b.public_key.clone(), 4, 0),
        sender_b.sign(sender_a.public_key.clone(), 3, 0),
    ];
    let changeset = run(&accounts, &transactions).expect("valid batch should execute");

    assert_eq!(
        changeset_account(&changeset, sender_a.public_key),
        account(9, 1)
    );
    assert_eq!(
        changeset_account(&changeset, sender_b.public_key),
        account(11, 1)
    );
}

#[test]
fn rejects_spend_funded_by_in_block_credit() {
    let payer = TestSigner::from_seed(52);
    let middle = TestSigner::from_seed(53);
    let sink = TestSigner::from_seed(54);

    let mut accounts = State::new();
    accounts.insert(account_key(&payer.public_key), account(10, 0));
    accounts.insert(account_key(&middle.public_key), account(0, 0));
    accounts.insert(account_key(&sink.public_key), account(0, 0));

    let transactions = vec![
        payer.sign(middle.public_key.clone(), 10, 0),
        middle.sign(sink.public_key, 1, 0),
    ];
    let transfers = prepared(&transactions);

    assert!(compute(&accounts, &transfers, &mut PrivateVerifications::new()).is_none());
}

#[test]
fn self_transfer_only_bumps_nonce() {
    let signer = TestSigner::from_seed(0);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(9, 3));

    let transactions = vec![signer.sign(signer.public_key.clone(), 4, 3)];
    let changeset = run(&accounts, &transactions).expect("self-transfer should execute");

    assert_eq!(
        changeset_account(&changeset, signer.public_key),
        account(9, 4)
    );
}

#[test]
fn rejects_unfunded_self_transfer() {
    let signer = TestSigner::from_seed(42);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(0, 0));

    let transactions = vec![signer.sign(signer.public_key.clone(), 1, 0)];
    let transfers = prepared(&transactions);

    assert!(compute(&accounts, &transfers, &mut PrivateVerifications::new()).is_none());
}

#[test]
fn rejects_recipient_overflow() {
    let signer = TestSigner::from_seed(40);
    let recipient = TestSigner::from_seed(41);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(10, 0));
    accounts.insert(account_key(&recipient.public_key), account(u64::MAX, 0));

    let transactions = vec![signer.sign(recipient.public_key, 1, 0)];
    assert!(run(&accounts, &transactions).is_none());
}

fn contended_accounts(account_count: usize) -> (State, Vec<TestSigner>) {
    let signers: Vec<TestSigner> = (0..account_count as u64)
        .map(TestSigner::from_seed)
        .collect();
    let mut accounts = State::new();
    for signer in &signers {
        accounts.insert(account_key(&signer.public_key), account(1_000, 0));
    }
    (accounts, signers)
}

fn prepared(transactions: &[TestTransaction]) -> Vec<PreparedOperation> {
    transactions
        .iter()
        .map(prepare_operation)
        .collect::<Option<Vec<_>>>()
        .expect("transactions should prepare")
}

#[test]
fn contended_general_account_load_keys_are_deduplicated() {
    let sender = TestSigner::from_seed(80);
    let recipient = TestSigner::from_seed(81);
    let transactions = (0..4)
        .map(|nonce| sender.sign(recipient.public_key.clone(), 1, nonce))
        .collect::<Vec<_>>();
    let transfers = prepared(&transactions);
    let plan = super::execution_plan(&transfers).expect("execution plan");
    let keys = plan.general.account_keys();
    let unique = keys.iter().copied().collect::<HashSet<_>>();

    assert!(plan.discrete.transfers.is_empty());
    assert_eq!(keys.len(), unique.len());
    assert_eq!(keys.len(), 2);
    assert!(unique.contains(&account_key(&sender.public_key)));
    assert!(unique.contains(&account_key(&recipient.public_key)));
}

#[test]
fn execution_plan_keeps_unique_transfers_discrete_in_mixed_batches() {
    let key = |seed| account_key(&TestSigner::from_seed(seed).public_key);
    let transfer =
        |sender, recipient, nonce| PreparedOperation::public_transfer(sender, recipient, 1, nonce);

    let repeated = key(90);
    let transfers = vec![
        transfer(key(80), key(81), 0),
        transfer(repeated, key(82), 0),
        transfer(repeated, key(83), 1),
        transfer(key(84), key(85), 0),
    ];
    let plan = super::execution_plan(&transfers).expect("execution plan");

    assert_eq!(plan.discrete.transfers.len(), 2);
    assert_eq!(plan.discrete.sender_keys.len(), 2);
    assert_eq!(plan.discrete.recipient_keys.len(), 2);
    assert_eq!(plan.general.account_keys().len(), 3);
}

#[test]
fn mixed_discrete_and_general_execution_writes_each_account_once() {
    let discrete_sender = TestSigner::from_seed(100);
    let discrete_recipient = TestSigner::from_seed(101);
    let repeated_sender = TestSigner::from_seed(102);
    let general_recipient = TestSigner::from_seed(103);

    let mut accounts = State::new();
    accounts.insert(account_key(&discrete_sender.public_key), account(10, 0));
    accounts.insert(account_key(&discrete_recipient.public_key), account(5, 0));
    accounts.insert(account_key(&repeated_sender.public_key), account(10, 0));
    accounts.insert(account_key(&general_recipient.public_key), account(7, 0));

    let transactions = vec![
        discrete_sender.sign(discrete_recipient.public_key.clone(), 3, 0),
        repeated_sender.sign(general_recipient.public_key.clone(), 2, 0),
        repeated_sender.sign(general_recipient.public_key.clone(), 2, 1),
    ];
    let changeset = run(&accounts, &transactions).expect("valid mixed batch should execute");
    let unique = changeset.iter().map(|(key, _)| key).collect::<HashSet<_>>();

    assert_eq!(changeset.len(), unique.len());
    assert_eq!(
        changeset_account(&changeset, discrete_sender.public_key),
        account(7, 1)
    );
    assert_eq!(
        changeset_account(&changeset, discrete_recipient.public_key),
        account(8, 0)
    );
    assert_eq!(
        changeset_account(&changeset, repeated_sender.public_key),
        account(6, 2)
    );
    assert_eq!(
        changeset_account(&changeset, general_recipient.public_key),
        account(11, 0)
    );
}

#[test]
fn executes_large_contended_batch() {
    // Contended accounts: senders overlap recipients, each signs several
    // transactions in out-of-order (run-ahead) nonces, and round 2 is a
    // self-transfer for every account. Every transaction is valid.
    let account_count = 600usize;
    let (accounts, signers) = contended_accounts(account_count);

    let mut transactions = Vec::new();
    for round in 0..4u64 {
        for (index, signer) in signers.iter().enumerate() {
            let recipient = if round == 2 {
                signer.public_key.clone()
            } else {
                signers[(index * 7 + 1) % account_count].public_key.clone()
            };
            transactions.push(signer.sign(recipient, 1, round));
        }
    }
    let transfers = prepared(&transactions);

    assert!(compute(&accounts, &transfers, &mut PrivateVerifications::new()).is_some());
}

#[test]
fn rejects_large_duplicate_nonce_batch() {
    // A duplicate nonce makes the batch invalid.
    let account_count = 600usize;
    let (accounts, signers) = contended_accounts(account_count);

    let mut transactions = Vec::new();
    for (index, signer) in signers.iter().enumerate() {
        let recipient = signers[(index + 1) % account_count].public_key.clone();
        transactions.push(signer.sign(recipient.clone(), 1, 0));
        transactions.push(signer.sign(recipient.clone(), 2, 0)); // duplicate nonce
        transactions.push(signer.sign(recipient, 1, 1));
    }
    let transfers = prepared(&transactions);

    assert!(compute(&accounts, &transfers, &mut PrivateVerifications::new()).is_none());
}

#[test]
fn failed_debit_rejects_batch() {
    // A failed debit rejects the whole batch, even when its recipient is near
    // overflow.
    let broke = TestSigner::from_seed(1);
    let funded = TestSigner::from_seed(2);
    let recipient = TestSigner::from_seed(3);

    let mut accounts = State::new();
    accounts.insert(account_key(&broke.public_key), account(0, 0)); // cannot pay
    accounts.insert(account_key(&funded.public_key), account(100, 0));
    accounts.insert(
        account_key(&recipient.public_key),
        StateAccount {
            balance: u64::MAX - 1,
            nonce: Nonce::new(0, 0),
            private: Default::default(),
        },
    );

    let transactions = [
        broke.sign(recipient.public_key.clone(), 1, 0), // debit fails
        funded.sign(recipient.public_key, 1, 0),
    ];
    let transfers = prepared(&transactions);

    assert!(compute(&accounts, &transfers, &mut PrivateVerifications::new()).is_none());
}

#[test]
fn prefix_collision_only_demotes_to_the_general_lane() {
    // Touch counting keys accounts by their 64-bit prefix, so two distinct
    // keys sharing a prefix look contended and route to the general lane.
    // That demotion must not change the computed accounts.
    let key = |bytes: [u8; 2]| {
        let mut raw = [0u8; AccountKey::SIZE];
        raw[..8].copy_from_slice(&[7; 8]);
        raw[8..10].copy_from_slice(&bytes);
        AccountKey::from(raw)
    };
    let sender_a = key([1, 0]);
    let sender_b = key([2, 0]);
    assert_ne!(sender_a, sender_b);
    assert_eq!(sender_a.prefix(), sender_b.prefix());
    let recipient_a = AccountKey::from([3; AccountKey::SIZE]);
    let recipient_b = AccountKey::from([4; AccountKey::SIZE]);

    let transfer = |sender: AccountKey, recipient: AccountKey, value, nonce| {
        PreparedOperation::public_transfer(sender, recipient, value, nonce)
    };
    let transfers = [
        transfer(sender_a, recipient_a, 3, 0),
        transfer(sender_b, recipient_b, 5, 0),
    ];

    let mut accounts = State::new();
    accounts.insert(sender_a, account(10, 0));
    accounts.insert(sender_b, account(20, 0));

    let changeset = compute(&accounts, &transfers, &mut PrivateVerifications::new())
        .expect("collision batch executes");

    let balance = |key: AccountKey| {
        changeset
            .iter()
            .find_map(|(candidate, account)| (*candidate == key).then_some(account.balance))
            .expect("account should be in changeset")
    };
    assert_eq!(changeset.len(), 4);
    assert_eq!(balance(sender_a), 7);
    assert_eq!(balance(sender_b), 15);
    assert_eq!(balance(recipient_a), DEFAULT_ACCOUNT_BALANCE + 3);
    assert_eq!(balance(recipient_b), DEFAULT_ACCOUNT_BALANCE + 5);
}

/// Runs the selective executor over `transfers` against `state`, returning
/// the applied flags and the final account values keyed by account.
fn run_selective(
    state: &State,
    transfers: &[PreparedOperation],
) -> (Vec<bool>, Vec<(AccountKey, StateAccount)>) {
    let mut executor = super::SelectiveExecutor::new();
    let keys = executor.begin_round(transfers);
    let values: Vec<Option<StateAccount>> =
        keys.iter().map(|key| state.get(key).cloned()).collect();
    executor.register(&values);
    let (applied, _verifications) = executor.apply(transfers);
    let changes = executor
        .into_updates()
        .into_iter()
        .map(|(index, account)| (keys[index], account.expect("touched accounts are written")))
        .collect();
    (applied, changes)
}

/// The load-bearing invariant of best-effort proposing: the surviving subset
/// re-executes cleanly under the all-or-nothing path with identical writes.
fn assert_survivors_verify(
    state: &State,
    transfers: &[PreparedOperation],
    applied: &[bool],
    selective_changes: &[(AccountKey, StateAccount)],
) {
    let survivors: Vec<PreparedOperation> = transfers
        .iter()
        .zip(applied)
        .filter_map(|(transfer, applied)| applied.then(|| transfer.clone()))
        .collect();
    let baseline = compute(state, &survivors, &mut PrivateVerifications::new())
        .expect("survivors must verify all-or-nothing");
    let mut selective = selective_changes.to_vec();
    selective.sort_unstable_by_key(|(key, _)| *key);
    assert_eq!(baseline, selective, "proposer and verifier writes diverge");
}

fn one_prepared(
    sender: &TestSigner,
    to: &ed25519::PublicKey,
    value: u64,
    nonce: u64,
) -> PreparedOperation {
    prepare_operation(&sender.sign(to.clone(), value, nonce)).expect("prepare must succeed")
}

#[test]
fn selective_drops_stale_and_duplicate_nonces() {
    let alice = TestSigner::from_seed(1);
    let bob = TestSigner::from_seed(2);
    let carol = TestSigner::from_seed(3);
    let mut state = State::new();
    // Alice's nonce 0 was already consumed upstream.
    state.insert(account_key(&alice.public_key), account(1_000, 1));
    state.insert(account_key(&bob.public_key), account(1_000, 0));

    let transfers = vec![
        one_prepared(&alice, &carol.public_key, 10, 0), // stale: consumed upstream
        one_prepared(&alice, &carol.public_key, 20, 1), // valid
        one_prepared(&bob, &carol.public_key, 30, 0),   // valid
        one_prepared(&bob, &carol.public_key, 40, 0),   // duplicate of the previous nonce
    ];
    let (applied, changes) = run_selective(&state, &transfers);
    assert_eq!(applied, vec![false, true, true, false]);
    assert_survivors_verify(&state, &transfers, &applied, &changes);

    let carol_final = changeset_account(&changes, carol.public_key);
    assert_eq!(carol_final.balance, DEFAULT_ACCOUNT_BALANCE + 50);
}

#[test]
fn selective_enforces_block_start_balances() {
    let alice = TestSigner::from_seed(4);
    let bob = TestSigner::from_seed(5);
    let carol = TestSigner::from_seed(6);
    let mut state = State::new();
    state.insert(account_key(&alice.public_key), account(100, 0));
    state.insert(account_key(&bob.public_key), account(30, 0));

    let transfers = vec![
        // Alice funds Bob, but the credit cannot fund Bob's spend below.
        one_prepared(&alice, &bob.public_key, 100, 0),
        one_prepared(&bob, &carol.public_key, 50, 0), // exceeds Bob's start balance
        one_prepared(&bob, &carol.public_key, 30, 0), // affordable from start
    ];
    let (applied, changes) = run_selective(&state, &transfers);
    assert_eq!(applied, vec![true, false, true]);
    assert_survivors_verify(&state, &transfers, &applied, &changes);

    let bob_final = changeset_account(&changes, bob.public_key);
    assert_eq!(bob_final.balance, 100); // 30 - 30 + 100
}

#[test]
fn selective_drops_unaffordable_self_transfers_and_credit_overflow() {
    let alice = TestSigner::from_seed(7);
    let bob = TestSigner::from_seed(8);
    let rich = TestSigner::from_seed(9);
    let mut state = State::new();
    state.insert(account_key(&alice.public_key), account(50, 0));
    state.insert(account_key(&rich.public_key), account(u64::MAX - 10, 0));
    state.insert(account_key(&bob.public_key), account(100, 0));

    let transfers = vec![
        one_prepared(&alice, &alice.public_key, 60, 0), // self-transfer above start
        one_prepared(&alice, &alice.public_key, 50, 0), // affordable self-transfer
        one_prepared(&bob, &rich.public_key, 20, 0),    // would overflow rich
        one_prepared(&bob, &alice.public_key, 10, 0),   // fine
    ];
    let (applied, changes) = run_selective(&state, &transfers);
    assert_eq!(applied, vec![false, true, false, true]);
    assert_survivors_verify(&state, &transfers, &applied, &changes);

    // The failed self-transfer consumed nothing: nonce 0 stayed available.
    let alice_final = changeset_account(&changes, alice.public_key);
    assert_eq!(alice_final.balance, 60); // 50 + 10
}

#[test]
fn selective_multi_round_matches_single_pass() {
    let alice = TestSigner::from_seed(10);
    let bob = TestSigner::from_seed(11);
    let carol = TestSigner::from_seed(12);
    let mut state = State::new();
    state.insert(account_key(&alice.public_key), account(1_000, 0));
    state.insert(account_key(&bob.public_key), account(1_000, 0));

    let first = vec![
        one_prepared(&alice, &carol.public_key, 10, 0),
        one_prepared(&alice, &carol.public_key, 10, 0), // duplicate: dropped
    ];
    let second = vec![
        one_prepared(&bob, &carol.public_key, 5, 0), // refill round, new accounts
        one_prepared(&alice, &carol.public_key, 7, 1), // refill touching known accounts
    ];

    // Two rounds through one executor (the refill shape)...
    let mut executor = super::SelectiveExecutor::new();
    let keys = executor.begin_round(&first);
    let values: Vec<Option<StateAccount>> =
        keys.iter().map(|key| state.get(key).cloned()).collect();
    executor.register(&values);
    assert_eq!(executor.apply(&first).0, vec![true, false]);
    let more = executor.begin_round(&second);
    assert_eq!(more.len(), 1, "only Bob's account is new");
    let values: Vec<Option<StateAccount>> =
        more.iter().map(|key| state.get(key).cloned()).collect();
    executor.register(&values);
    assert_eq!(executor.apply(&second).0, vec![true, true]);
    let mut all_keys = keys;
    all_keys.extend(more);
    let mut multi: Vec<(AccountKey, StateAccount)> = executor
        .into_updates()
        .into_iter()
        .map(|(index, account)| (all_keys[index], account.expect("written")))
        .collect();
    multi.sort_unstable_by_key(|(key, _)| *key);

    // ...must match the survivors executed in one all-or-nothing pass.
    let survivors = vec![first[0].clone(), second[0].clone(), second[1].clone()];
    let baseline =
        compute(&state, &survivors, &mut PrivateVerifications::new()).expect("survivors verify");
    assert_eq!(baseline, multi);
}

// ---------------------------------------------------------------------------
// Private-payment operations.
//
// These construct payloads with the configured chain backend (mock under
// default features, real zkpari proving under --all-features), so assertions
// on commitment state use homomorphic identities rather than literal values.
// ---------------------------------------------------------------------------

mod private_ops {
    use super::{
        Changeset, State, TestSigner, TestTransaction, account, account_key, changeset_account,
    };
    use crate::executor::{
        PreparedOperation, SelectiveExecutor, execute_with_strategy, prepare_operation,
    };
    use commonware_parallel::Sequential;
    use commonware_privacy::payments::{Backend as _, Commitment as _};
    use constantinople_primitives::{
        ChainPrivatePaymentBackend, Nonce, Payload, PrivatePaymentBackend as _, StateAccount,
        to_state_commitment,
    };
    use core::num::NonZeroU64;
    use rand::{SeedableRng as _, rngs::StdRng};

    type ChainBackend = ChainPrivatePaymentBackend;
    type ChainCommitment = <ChainBackend as commonware_privacy::payments::Backend>::Commitment;
    type StateCommitment =
        <constantinople_primitives::StatePrivatePaymentBackend as commonware_privacy::payments::Backend>::Commitment;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0x9e37_79b9)
    }

    fn state_commitment(commitment: &ChainCommitment) -> StateCommitment {
        to_state_commitment(commitment.clone())
    }

    fn sign_payload(signer: &TestSigner, payload: Payload, nonce: u64) -> TestTransaction {
        constantinople_primitives::Transaction::from_payload(
            constantinople_primitives::TransactionPublicKey::ed25519(signer.public_key.clone()),
            payload,
            nonce,
        )
        .seal_and_sign(
            &signer.key,
            super::NAMESPACE,
            &mut super::TestHasher::default(),
        )
    }

    fn prepare(transactions: &[TestTransaction]) -> Vec<PreparedOperation> {
        transactions
            .iter()
            .map(prepare_operation)
            .collect::<Option<Vec<_>>>()
            .expect("transactions should prepare")
    }

    /// All-or-nothing execution with batch proof verification.
    fn execute(state: &State, transactions: &[TestTransaction]) -> Option<Changeset> {
        execute_with_strategy(state, &prepare(transactions), &Sequential)
    }

    /// Mirrors `execute_proposal`'s select step: trial application with batch
    /// verification, rewinding to per-proof verification on failure.
    fn propose(
        state: &State,
        transactions: &[TestTransaction],
    ) -> (
        Vec<bool>,
        Vec<(constantinople_primitives::AccountKey, StateAccount)>,
    ) {
        let operations = prepare(transactions);
        let mut executor = SelectiveExecutor::new();
        let keys = executor.begin_round(&operations);
        let values: Vec<Option<StateAccount>> =
            keys.iter().map(|key| state.get(key).cloned()).collect();
        executor.register(&values);
        let checkpoint = operations
            .iter()
            .any(PreparedOperation::has_proof)
            .then(|| executor.checkpoint());
        let (mut applied, verifications) = executor.apply(&operations);
        if !verifications.is_empty() && !verifications.verify_with_strategy(&Sequential) {
            executor.restore(checkpoint.expect("proof-bearing batch captured a checkpoint"));
            applied = executor.apply_verifying(&operations);
        }
        let changes = executor
            .into_updates()
            .into_iter()
            .map(|(index, account)| (keys[index], account.expect("touched accounts are written")))
            .collect();
        (applied, changes)
    }

    /// Survivors of a selective proposal must re-execute identically under
    /// the all-or-nothing path.
    fn assert_survivors_match(
        state: &State,
        transactions: &[TestTransaction],
        applied: &[bool],
        selective_changes: &[(constantinople_primitives::AccountKey, StateAccount)],
    ) {
        let survivors: Vec<TestTransaction> = transactions
            .iter()
            .zip(applied)
            .filter_map(|(tx, applied)| applied.then(|| tx.clone()))
            .collect();
        let baseline = execute(state, &survivors).expect("survivors must verify all-or-nothing");
        let mut selective = selective_changes.to_vec();
        selective.sort_unstable_by_key(|(key, _)| *key);
        assert_eq!(baseline, selective, "proposer and verifier writes diverge");
    }

    #[test]
    fn private_fund_reduces_public_balance_and_adds_pending() {
        let params = ChainBackend::params();
        let mut rng = rng();
        let signer = TestSigner::from_seed(50);
        let mut accounts = State::new();
        accounts.insert(account_key(&signer.public_key), account(10, 0));

        let (commitment, _opening, proof) = ChainBackend::fund(params, 4, &mut rng);
        let transactions = vec![sign_payload(
            &signer,
            Payload::PrivateFund {
                value: NonZeroU64::new(4).unwrap(),
                commitment: commitment.clone(),
                proof,
            },
            0,
        )];

        let (applied, changes) = propose(&accounts, &transactions);
        assert_eq!(applied, vec![true]);
        assert_survivors_match(&accounts, &transactions, &applied, &changes);

        let written = execute(&accounts, &transactions).expect("fund executes");
        let account = changeset_account(&written, signer.public_key);
        assert_eq!(account.balance, 6);
        assert_eq!(account.nonce, Nonce::new(1, 0));
        assert_eq!(account.private.current, StateCommitment::zero());
        assert_eq!(
            account.private.pending,
            StateCommitment::zero() + &state_commitment(&commitment)
        );
    }

    #[test]
    fn private_rollover_explicitly_moves_pending_to_current() {
        let params = ChainBackend::params();
        let mut rng = rng();
        let signer = TestSigner::from_seed(51);
        let (current, _opening, _proof) = ChainBackend::fund(params, 2, &mut rng);
        let (pending, _opening, _proof) = ChainBackend::fund(params, 4, &mut rng);
        let mut accounts = State::new();
        let mut start = account(10, 0);
        start.private.current = state_commitment(&current);
        start.private.pending = state_commitment(&pending);
        accounts.insert(account_key(&signer.public_key), start);

        let transactions = vec![sign_payload(&signer, Payload::PrivateRollover, 0)];

        let (applied, changes) = propose(&accounts, &transactions);
        assert_eq!(applied, vec![true]);
        assert_survivors_match(&accounts, &transactions, &applied, &changes);

        let written = execute(&accounts, &transactions).expect("rollover executes");
        let account = changeset_account(&written, signer.public_key);
        assert_eq!(account.balance, 10);
        assert_eq!(account.nonce, Nonce::new(1, 0));
        assert_eq!(
            account.private.current,
            state_commitment(&current) + &state_commitment(&pending)
        );
        assert_eq!(account.private.pending, StateCommitment::zero());
    }

    #[test]
    fn private_transfer_spends_current_and_credits_recipient_pending() {
        let params = ChainBackend::params();
        let mut rng = rng();
        let signer = TestSigner::from_seed(52);
        let recipient = TestSigner::from_seed(53);

        // The sender's spendable current is a rolled-over fund of 7 whose
        // opening the client kept.
        let (current, current_opening, _proof) = ChainBackend::fund(params, 7, &mut rng);
        let (amount, _amount_opening, proof) =
            ChainBackend::transfer(params, &current, &current_opening, 3, &mut rng);

        let mut accounts = State::new();
        let mut sender_start = account(10, 0);
        sender_start.private.current = state_commitment(&current);
        accounts.insert(account_key(&signer.public_key), sender_start);
        accounts.insert(account_key(&recipient.public_key), account(5, 0));

        let transactions = vec![sign_payload(
            &signer,
            Payload::PrivateTransfer {
                to: account_key(&recipient.public_key),
                amount: amount.clone(),
                proof,
            },
            0,
        )];

        let (applied, changes) = propose(&accounts, &transactions);
        assert_eq!(applied, vec![true]);
        assert_survivors_match(&accounts, &transactions, &applied, &changes);

        let written = execute(&accounts, &transactions).expect("transfer executes");
        let sender_account = changeset_account(&written, signer.public_key);
        assert_eq!(sender_account.balance, 10);
        assert_eq!(sender_account.nonce, Nonce::new(1, 0));
        assert_eq!(
            sender_account.private.current,
            state_commitment(&current) - &state_commitment(&amount)
        );
        let recipient_account = changeset_account(&written, recipient.public_key);
        assert_eq!(recipient_account.balance, 5);
        assert_eq!(recipient_account.nonce, Nonce::new(0, 0));
        assert_eq!(
            recipient_account.private.pending,
            StateCommitment::zero() + &state_commitment(&amount)
        );
    }

    #[test]
    fn private_fund_cannot_be_spent_before_explicit_rollover() {
        let params = ChainBackend::params();
        let mut rng = rng();
        let signer = TestSigner::from_seed(54);
        let recipient = TestSigner::from_seed(55);
        let mut accounts = State::new();
        accounts.insert(account_key(&signer.public_key), account(10, 0));
        accounts.insert(account_key(&recipient.public_key), account(1, 0));

        let (fund_commitment, _opening, fund_proof) = ChainBackend::fund(params, 4, &mut rng);
        // A spend of the just-funded 4 is provable only against a current
        // containing it; the account's working current is still zero, so the
        // claim cannot verify.
        let (wrong_current, wrong_opening) = ChainBackend::commit_public(params, 4);
        let (amount, _amount_opening, proof) =
            ChainBackend::transfer(params, &wrong_current, &wrong_opening, 4, &mut rng);

        let transactions = vec![
            sign_payload(
                &signer,
                Payload::PrivateFund {
                    value: NonZeroU64::new(4).unwrap(),
                    commitment: fund_commitment.clone(),
                    proof: fund_proof,
                },
                0,
            ),
            sign_payload(
                &signer,
                Payload::PrivateTransfer {
                    to: account_key(&recipient.public_key),
                    amount,
                    proof,
                },
                1,
            ),
        ];

        let (applied, changes) = propose(&accounts, &transactions);
        assert_eq!(applied, vec![true, false]);
        assert_survivors_match(&accounts, &transactions, &applied, &changes);

        // The whole batch is rejected under all-or-nothing verification.
        assert!(execute(&accounts, &transactions).is_none());

        let (_, account) = changes
            .iter()
            .find(|(key, _)| *key == account_key(&signer.public_key))
            .expect("sender was written");
        assert_eq!(account.balance, 6);
        assert_eq!(account.nonce, Nonce::new(1, 0));
        assert_eq!(account.private.current, StateCommitment::zero());
        assert_eq!(
            account.private.pending,
            StateCommitment::zero() + &state_commitment(&fund_commitment)
        );
    }

    #[test]
    fn private_fund_rollover_then_transfer_is_valid() {
        let params = ChainBackend::params();
        let mut rng = rng();
        let signer = TestSigner::from_seed(56);
        let recipient = TestSigner::from_seed(57);
        let mut accounts = State::new();
        accounts.insert(account_key(&signer.public_key), account(10, 0));
        accounts.insert(account_key(&recipient.public_key), account(1, 0));

        let (fund_commitment, fund_opening, fund_proof) = ChainBackend::fund(params, 4, &mut rng);
        // After the rollover the working current equals the fund commitment,
        // so the spend is provable with the fund's opening.
        let (amount, _amount_opening, proof) =
            ChainBackend::transfer(params, &fund_commitment, &fund_opening, 4, &mut rng);

        // Three sends from one account contend, so this batch exercises the
        // general lane's ordered private replay.
        let transactions = vec![
            sign_payload(
                &signer,
                Payload::PrivateFund {
                    value: NonZeroU64::new(4).unwrap(),
                    commitment: fund_commitment.clone(),
                    proof: fund_proof,
                },
                0,
            ),
            sign_payload(&signer, Payload::PrivateRollover, 1),
            sign_payload(
                &signer,
                Payload::PrivateTransfer {
                    to: account_key(&recipient.public_key),
                    amount: amount.clone(),
                    proof,
                },
                2,
            ),
        ];

        let (applied, changes) = propose(&accounts, &transactions);
        assert_eq!(applied, vec![true, true, true]);
        assert_survivors_match(&accounts, &transactions, &applied, &changes);

        let written = execute(&accounts, &transactions).expect("pipeline executes");
        let sender_account = changeset_account(&written, signer.public_key);
        assert_eq!(sender_account.balance, 6);
        assert_eq!(sender_account.nonce, Nonce::new(3, 0));
        assert_eq!(
            sender_account.private.current,
            state_commitment(&fund_commitment) - &state_commitment(&amount)
        );
        assert_eq!(sender_account.private.pending, StateCommitment::zero());
        let recipient_account = changeset_account(&written, recipient.public_key);
        assert_eq!(
            recipient_account.private.pending,
            StateCommitment::zero() + &state_commitment(&amount)
        );
    }

    #[test]
    fn private_burn_resets_current_and_credits_public_balance() {
        let params = ChainBackend::params();
        let mut rng = rng();
        let signer = TestSigner::from_seed(58);

        let (current, current_opening, _proof) = ChainBackend::fund(params, 7, &mut rng);
        let (pending, _pending_opening, _proof) = ChainBackend::fund(params, 2, &mut rng);
        let burn_proof = ChainBackend::burn(params, &current, &current_opening, 4, &mut rng);

        let mut accounts = State::new();
        let mut start = account(10, 0);
        start.private.current = state_commitment(&current);
        start.private.pending = state_commitment(&pending);
        accounts.insert(account_key(&signer.public_key), start);

        let transactions = vec![sign_payload(
            &signer,
            Payload::PrivateBurn {
                value: NonZeroU64::new(4).unwrap(),
                proof: burn_proof,
            },
            0,
        )];

        let (applied, changes) = propose(&accounts, &transactions);
        assert_eq!(applied, vec![true]);
        assert_survivors_match(&accounts, &transactions, &applied, &changes);

        let written = execute(&accounts, &transactions).expect("burn executes");
        let account = changeset_account(&written, signer.public_key);
        assert_eq!(account.balance, 14);
        assert_eq!(account.nonce, Nonce::new(1, 0));
        assert_eq!(account.private.current, StateCommitment::zero());
        assert_eq!(account.private.pending, state_commitment(&pending));
    }

    #[test]
    fn invalid_private_fund_proof_does_not_mutate_state() {
        let params = ChainBackend::params();
        let mut rng = rng();
        let signer = TestSigner::from_seed(59);
        let mut accounts = State::new();
        accounts.insert(account_key(&signer.public_key), account(10, 0));

        // A commitment to 5 cannot fund a claimed value of 4.
        let (commitment, _opening, proof) = ChainBackend::fund(params, 5, &mut rng);
        let transactions = vec![sign_payload(
            &signer,
            Payload::PrivateFund {
                value: NonZeroU64::new(4).unwrap(),
                commitment,
                proof,
            },
            0,
        )];

        let (applied, changes) = propose(&accounts, &transactions);
        assert_eq!(applied, vec![false]);
        assert!(changes.is_empty(), "dropped operations leave no writes");

        assert!(execute(&accounts, &transactions).is_none());
    }
}
