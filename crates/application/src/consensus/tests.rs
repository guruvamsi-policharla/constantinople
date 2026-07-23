use super::{
    Application, Databases, StateSyncTarget, TransactionHistoryTarget, genesis_block,
    history::parent_transactions_inactivity_floor,
};
use commonware_consensus::{
    simplex::{
        scheme::bls12381_threshold::standard as threshold, types::Context as SimplexContext,
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    Digest as _, Hasher as _, Signer as _, bls12381::primitives::variant::MinSig, ed25519, sha256,
};
use commonware_glue::stateful::db::{DatabaseSet as _, Merkleized as _, Unmerkleized as _};
use commonware_parallel::Sequential;
use commonware_privacy::payments::Backend as _;
use commonware_runtime::{
    Clock as _, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{
    journal::contiguous::{
        fixed::Config as FixedJournalConfig, variable::Config as VariableJournalConfig,
    },
    merkle::{full::Config as MmrConfig, mmr},
    qmdb::{any::FixedConfig, batch_chain::Bounds, keyless::fixed as keyless_fixed},
    translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range};
use constantinople_mempool::mocks::StaticTransactionSource;
use constantinople_primitives::{
    Account, AccountKey, Block, ChainPrivatePaymentBackend, DEFAULT_ACCOUNT_BALANCE, Header, Nonce,
    Payload, PrivateAccount, PrivatePaymentBackend as _, PublicKeyCache, Sealable, SealedBlock,
    SignedTransaction, StateAccount, StatePrivatePaymentBackend, Transaction, TransactionPublicKey,
    to_state_commitment,
};
use rand::{SeedableRng as _, rngs::StdRng};
use std::{num::NonZeroU64, sync::Arc, time::Duration};

type TestApp = Application<
    deterministic::Context,
    sha256::Sha256,
    sha256::Digest,
    threshold::Scheme<ed25519::PublicKey, MinSig>,
    ed25519::PublicKey,
    StaticTransactionSource<sha256::Digest, ed25519::PublicKey, sha256::Sha256>,
    (),
    Sequential,
>;
type TestDbs = Databases<deterministic::Context, sha256::Sha256, EightCap, Sequential>;

const TEST_TX_NS: &[u8] = b"constantinople-application-test-transactions";

fn empty_state_target() -> StateSyncTarget<sha256::Digest> {
    StateSyncTarget::new(
        sha256::Digest::EMPTY,
        non_empty_range!(mmr::Location::new(0), mmr::Location::new(1)),
    )
}

fn state_config(cache: CacheRef) -> FixedConfig<EightCap, Sequential> {
    FixedConfig {
        merkle_config: MmrConfig {
            journal_partition: "verify-invalid-state-merkle-journal".into(),
            metadata_partition: "verify-invalid-state-merkle-metadata".into(),
            items_per_blob: NZU64!(1024),
            write_buffer: NZUsize!(4096),
            strategy: Sequential,
            page_cache: cache.clone(),
        },
        journal_config: FixedJournalConfig {
            partition: "verify-invalid-state-log".into(),
            items_per_blob: NZU64!(1024),
            page_cache: cache,
            write_buffer: NZUsize!(4096),
        },
        translator: EightCap,
        init_cache_size: Some(NZUsize!(1024)),
    }
}

fn transaction_config(cache: CacheRef) -> keyless_fixed::CompactConfig<Sequential> {
    keyless_fixed::CompactConfig {
        strategy: Sequential,
        witness: VariableJournalConfig {
            partition: "verify-invalid-transactions-witness".into(),
            items_per_section: NZU64!(1024),
            compression: None,
            codec_config: (),
            page_cache: cache,
            write_buffer: NZUsize!(4096),
        },
        commit_codec_config: (),
    }
}

fn sync_range_from_bounds(
    bounds: &Bounds<mmr::Family>,
) -> commonware_utils::range::NonEmptyRange<mmr::Location> {
    non_empty_range!(
        bounds.inactivity_floor,
        mmr::Location::new(bounds.total_size)
    )
}

type TestBlock = SealedBlock<sha256::Digest, ed25519::PublicKey, sha256::Sha256>;

/// Genesis-backed fixture shared by the propose/verify tests.
///
/// `sender` and `alt_sender` are funded at genesis so tests can execute real
/// transfers; `recipient` starts empty.
struct VerifyHarness {
    app: TestApp,
    dbs: TestDbs,
    parent: TestBlock,
    leader: ed25519::PrivateKey,
    sender: ed25519::PrivateKey,
    alt_sender: ed25519::PrivateKey,
    recipient: ed25519::PrivateKey,
    state_target: StateSyncTarget<sha256::Digest>,
    transaction_target: TransactionHistoryTarget<sha256::Digest>,
}

async fn verify_harness(context: &deterministic::Context) -> VerifyHarness {
    let cache = CacheRef::from_pooler(context, NZU16!(16), NZUsize!(4096));
    let dbs = TestDbs::init(
        context.child("dbs"),
        (
            state_config(cache.clone()),
            transaction_config(cache.clone()),
        ),
    )
    .await;

    let leader = ed25519::PrivateKey::from_seed(21);
    let sender = ed25519::PrivateKey::from_seed(22);
    let recipient = ed25519::PrivateKey::from_seed(23);
    let alt_sender = ed25519::PrivateKey::from_seed(24);

    let (mut state_batch, transaction_batch) = dbs.new_batches().await;
    for funded in [&sender, &alt_sender] {
        state_batch = state_batch.write(
            AccountKey::from_public_key(&TransactionPublicKey::ed25519(funded.public_key())),
            Some(Account {
                balance: 1_000_000,
                nonce: Nonce::default(),
                private: Default::default(),
            }),
        );
    }
    let state = state_batch.merkleize().await.expect("genesis state");
    let transactions = transaction_batch
        .merkleize()
        .await
        .expect("genesis transactions");
    let state_target = StateSyncTarget::new(state.root(), sync_range_from_bounds(state.bounds()));
    let transaction_target = TransactionHistoryTarget::new(
        transactions.root(),
        mmr::Location::new(transactions.bounds().total_size),
    );
    dbs.finalize((state, transactions)).await;

    let parent = genesis_block::<sha256::Digest, _, sha256::Sha256>(
        &mut sha256::Sha256::default(),
        leader.public_key(),
        0,
        state_target.clone(),
        transaction_target.clone(),
    );
    VerifyHarness {
        app: TestApp::new(
            context.child("app"),
            Sequential,
            leader.public_key(),
            sha256::Digest::EMPTY,
            TEST_TX_NS,
            PublicKeyCache::new(context.child("public_key_cache"), NZUsize!(64)),
            state_target.clone(),
            transaction_target.clone(),
            None,
        ),
        dbs,
        parent,
        leader,
        sender,
        alt_sender,
        recipient,
        state_target,
        transaction_target,
    }
}

type TestSource = StaticTransactionSource<sha256::Digest, ed25519::PublicKey, sha256::Sha256>;

fn transfer(
    sender: &ed25519::PrivateKey,
    recipient: &ed25519::PrivateKey,
    value: u64,
) -> SignedTransaction<sha256::Sha256> {
    Transaction::new(
        TransactionPublicKey::ed25519(sender.public_key()),
        TransactionPublicKey::ed25519(recipient.public_key()),
        NonZeroU64::new(value).expect("test value should be non-zero"),
        0,
    )
    .seal_and_sign(sender, TEST_TX_NS, &mut sha256::Sha256::default())
}

/// Builds a child header that reuses the parent's commitments.
fn unexecuted_child_header(
    parent: &TestBlock,
    consensus_context: &SimplexContext<sha256::Digest, ed25519::PublicKey>,
) -> Header<sha256::Digest, sha256::Digest, ed25519::PublicKey> {
    Header {
        context: consensus_context.clone(),
        parent: *parent.seal(),
        height: 1,
        timestamp: 1,
        state_root: parent.header.state_root,
        state_range: parent.header.state_range.clone(),
        transactions_root: parent.header.transactions_root,
        transactions_range: parent.header.transactions_range.clone(),
    }
}

#[test]
fn verify_rejects_invalid_body() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent,
            leader,
            sender,
            recipient,
            ..
        } = verify_harness(&context).await;

        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };
        let header = unexecuted_child_header(&parent, &consensus_context);
        let block = Block::<sha256::Digest, _, sha256::Sha256>::new(
            header,
            vec![
                transfer(&sender, &recipient, 1),
                transfer(&sender, &recipient, 2),
            ],
        )
        .seal(&mut sha256::Sha256::default());

        let result = app
            .verify_child(
                (context.child("verify"), consensus_context),
                Arc::new(block),
                std::future::ready(Some(Arc::new(parent))),
                dbs.new_batches().await,
            )
            .await;

        assert!(result.is_none());
    });
}

#[test]
fn verify_rejects_missing_parent() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent,
            leader,
            sender,
            recipient,
            ..
        } = verify_harness(&context).await;

        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };
        let header = unexecuted_child_header(&parent, &consensus_context);
        let block = Block::<sha256::Digest, _, sha256::Sha256>::new(
            header,
            vec![transfer(&sender, &recipient, 1)],
        )
        .seal(&mut sha256::Sha256::default());

        // Signature verification dispatches before the parent resolves; a
        // parent that never arrives must still reject the block.
        let result = app
            .verify_child(
                (context.child("verify"), consensus_context),
                Arc::new(block),
                std::future::ready(None),
                dbs.new_batches().await,
            )
            .await;

        assert!(result.is_none());
    });
}

#[test]
fn propose_drops_inapplicable_and_refills() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent,
            leader,
            sender,
            alt_sender,
            recipient,
            ..
        } = verify_harness(&context).await;

        context.sleep(Duration::from_millis(10)).await;

        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };

        // Both selected transfers consume the same nonce: proposing keeps the
        // first, drops the duplicate, and tops the block up from the mempool
        // toward the proposal budget. The proposed block is the applicable
        // subset plus the top-up.
        let keep = transfer(&sender, &recipient, 1);
        let duplicate = transfer(&sender, &recipient, 2);
        let refill = transfer(&alt_sender, &recipient, 3);
        let mut input =
            StaticTransactionSource::new(vec![vec![keep.clone(), duplicate], vec![refill.clone()]]);
        let proposed = app
            .propose_child(
                (context.child("propose"), consensus_context.clone()),
                Arc::new(parent.clone()),
                dbs.new_batches().await,
                &mut input,
            )
            .await
            .expect("best-effort proposal must succeed");
        assert_eq!(
            body_digests(&proposed.block),
            vec![*keep.message_digest(), *refill.message_digest()]
        );

        // The surviving subset re-executes cleanly under all-or-nothing
        // verification.
        let accepted = app
            .verify_child(
                (context.child("verify"), consensus_context),
                Arc::new(proposed.block.clone()),
                std::future::ready(Some(Arc::new(parent))),
                dbs.new_batches().await,
            )
            .await;
        assert!(accepted.is_some());
    });
}

#[test]
fn verify_accepts_proposed_child_and_rejects_stale_timestamp() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent,
            leader,
            ..
        } = verify_harness(&context).await;

        // Advance past the genesis timestamp so the proposal's clock-derived
        // timestamp is strictly greater than the parent's.
        context.sleep(Duration::from_millis(10)).await;

        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };
        let mut input = StaticTransactionSource::new(Vec::new());
        let proposed = app
            .propose_child(
                (context.child("propose"), consensus_context.clone()),
                Arc::new(parent.clone()),
                dbs.new_batches().await,
                &mut input,
            )
            .await
            .expect("empty proposal must succeed");

        // The freshly proposed child verifies against the same parent.
        let accepted = app
            .verify_child(
                (context.child("verify"), consensus_context.clone()),
                Arc::new(proposed.block.clone()),
                std::future::ready(Some(Arc::new(parent.clone()))),
                dbs.new_batches().await,
            )
            .await;
        assert!(accepted.is_some());

        // The identical block with its timestamp rewound to the parent's is
        // rejected by the timestamp check alone.
        let Block { mut header, body } = proposed.block.into_inner();
        assert!(
            body.is_empty(),
            "stale block must mirror the empty proposal"
        );
        header.timestamp = parent.header.timestamp;
        let stale = Block::<sha256::Digest, _, sha256::Sha256>::new(header, Vec::new())
            .seal(&mut sha256::Sha256::default());
        let rejected = app
            .verify_child(
                (context.child("verify_stale"), consensus_context),
                Arc::new(stale),
                std::future::ready(Some(Arc::new(parent))),
                dbs.new_batches().await,
            )
            .await;
        assert!(rejected.is_none());
    });
}

#[test]
fn parent_inactivity_floor_skips_the_parent_commit() {
    let leader = ed25519::PrivateKey::from_seed(7);
    let recipient = ed25519::PrivateKey::from_seed(8);
    let genesis_target = TransactionHistoryTarget {
        root: sha256::Digest::EMPTY,
        leaf_count: commonware_storage::mmr::Location::new(1),
    };
    let mut header = genesis_block::<sha256::Digest, _, sha256::Sha256>(
        &mut sha256::Sha256::default(),
        leader.public_key(),
        0,
        empty_state_target(),
        genesis_target,
    )
    .into_inner()
    .header;
    header.transactions_range = non_empty_range!(5, 10);

    let to = recipient.public_key();
    let parent = Block::<sha256::Digest, _, sha256::Sha256>::new(
        header,
        (0..3)
            .map(|nonce| {
                Transaction::new(
                    TransactionPublicKey::ed25519(leader.public_key()),
                    TransactionPublicKey::ed25519(to.clone()),
                    NonZeroU64::new(nonce + 1).expect("test value should be non-zero"),
                    nonce,
                )
                .seal_and_sign(
                    &leader,
                    constantinople_primitives::TRANSACTION_NAMESPACE,
                    &mut sha256::Sha256::default(),
                )
            })
            .collect(),
    )
    .seal(&mut sha256::Sha256::default());

    assert_eq!(
        parent_transactions_inactivity_floor(&parent),
        commonware_storage::mmr::Location::new(6)
    );
}

#[test]
fn genesis_block_uses_the_initialized_transaction_target() {
    let leader = ed25519::PrivateKey::from_seed(11).public_key();
    let target = TransactionHistoryTarget {
        root: sha256::Sha256::hash(b"genesis"),
        leaf_count: commonware_storage::mmr::Location::new(1),
    };

    let block = genesis_block::<sha256::Digest, _, sha256::Sha256>(
        &mut sha256::Sha256::default(),
        leader,
        0,
        empty_state_target(),
        target.clone(),
    );

    assert_eq!(block.header.transactions_root, target.root);
    assert_eq!(block.header.transactions_range, non_empty_range!(0, 1));
}

/// Digests of a sealed block's body transactions.
fn body_digests(block: &TestBlock) -> Vec<sha256::Digest> {
    block
        .body
        .iter()
        .map(|tx| {
            *tx.get()
                .expect("test bodies are materialized")
                .message_digest()
        })
        .collect()
}

/// Wraps a static source with a virtual-time delay so a test can control how
/// much of the build budget each mempool round trip consumes.
struct DelayedSource {
    context: deterministic::Context,
    delay: Duration,
    inner: TestSource,
}

// Required by `TransactionSource`'s `Reporter: Clone` supertrait; never
// invoked in these tests.
impl Clone for DelayedSource {
    fn clone(&self) -> Self {
        Self {
            context: self.context.child("clone"),
            delay: self.delay,
            inner: self.inner.clone(),
        }
    }
}

impl constantinople_mempool::TransactionSource<sha256::Digest, ed25519::PublicKey, sha256::Sha256>
    for DelayedSource
{
    async fn propose(
        &mut self,
        parent: &Header<sha256::Digest, sha256::Digest, ed25519::PublicKey>,
        round: Round,
        filled: usize,
    ) -> Vec<constantinople_primitives::VerifiedTransaction<sha256::Sha256>> {
        self.context.sleep(self.delay).await;
        self.inner.propose(parent, round, filled).await
    }
}

impl commonware_consensus::Reporter for DelayedSource {
    type Activity = commonware_consensus::marshal::Update<TestBlock>;

    fn report(&mut self, activity: Self::Activity) -> commonware_actor::Feedback {
        self.inner.report(activity)
    }
}

#[test]
fn build_timeout_bounds_refill_rounds() {
    deterministic::Runner::default().start(|context| async move {
        let harness = verify_harness(&context).await;
        let seed_keep = transfer(&harness.sender, &harness.recipient, 1);
        let seed_dup = transfer(&harness.sender, &harness.recipient, 2);
        let refill_one = transfer(&harness.alt_sender, &harness.recipient, 3);
        let never_pulled = transfer(&harness.recipient, &harness.sender, 4);

        // Each mempool round trip burns 60ms of virtual time — past the 50ms
        // build deadline after one refill.
        let slow = |batches| DelayedSource {
            context: context.child("slow_clock"),
            delay: Duration::from_millis(60),
            inner: StaticTransactionSource::new(batches),
        };
        let mut app: Application<
            deterministic::Context,
            sha256::Sha256,
            sha256::Digest,
            threshold::Scheme<ed25519::PublicKey, MinSig>,
            ed25519::PublicKey,
            DelayedSource,
            (),
            Sequential,
        > = Application::new(
            context.child("deadline_app"),
            Sequential,
            harness.leader.public_key(),
            sha256::Digest::EMPTY,
            TEST_TX_NS,
            PublicKeyCache::new(context.child("deadline_pkc"), NZUsize!(64)),
            harness.state_target.clone(),
            harness.transaction_target.clone(),
            None,
        );

        context.sleep(Duration::from_millis(10)).await;

        // The seed pull happens before the build deadline starts; the first
        // refill (delayed 60ms) lands past the deadline, so a second refill
        // is never requested even though headroom and candidates remain.
        let mut input = slow(vec![
            vec![seed_keep.clone(), seed_dup],
            vec![refill_one.clone()],
            vec![never_pulled],
        ]);
        let ctx1 = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: harness.leader.public_key(),
            parent: (View::zero(), *harness.parent.seal()),
        };
        let proposed = app
            .propose_child(
                (context.child("propose_deadline"), ctx1),
                Arc::new(harness.parent.clone()),
                harness.dbs.new_batches().await,
                &mut input,
            )
            .await
            .expect("proposal must succeed");

        assert_eq!(
            body_digests(&proposed.block),
            vec![*seed_keep.message_digest(), *refill_one.message_digest()],
            "the deadline must stop the loop after the first refill"
        );
    });
}

// ---------------------------------------------------------------------------
// Private-payment blocks through the QMDB-backed consensus path.
//
// Payloads are built with the configured chain backend (mock under default
// features, real zkpari proving under --all-features), so expected commitment
// state replays the executor's own homomorphic operations instead of
// asserting literal values.
// ---------------------------------------------------------------------------

type ChainBackend = ChainPrivatePaymentBackend;
type StatePrivateAccount = PrivateAccount<StatePrivatePaymentBackend>;

fn account_key(key: &ed25519::PrivateKey) -> AccountKey {
    AccountKey::from_public_key(&TransactionPublicKey::ed25519(key.public_key()))
}

fn private_payload(
    signer: &ed25519::PrivateKey,
    payload: Payload,
    nonce: u64,
) -> SignedTransaction<sha256::Sha256> {
    Transaction::from_payload(
        TransactionPublicKey::ed25519(signer.public_key()),
        payload,
        nonce,
    )
    .seal_and_sign(signer, TEST_TX_NS, &mut sha256::Sha256::default())
}

/// Reads one account out of the finalized state database.
async fn read_account(dbs: &TestDbs, key: &AccountKey) -> Option<StateAccount> {
    let (state_batch, _) = dbs.new_batches().await;
    let (mut values, _) = state_batch
        .stage(&[key])
        .await
        .expect("staging the account read must succeed");
    values.pop().expect("one staged value per key")
}

/// Proposes a block seeded with exactly `transactions`, verifies it against
/// the same parent, finalizes the verified databases, and returns the sealed
/// block as the next parent.
async fn seal_private_block(
    context: &deterministic::Context,
    app: &mut TestApp,
    dbs: &TestDbs,
    parent: &TestBlock,
    leader: &ed25519::PrivateKey,
    view: u64,
    transactions: Vec<SignedTransaction<sha256::Sha256>>,
) -> TestBlock {
    // Advance the deterministic clock so the child's clock-derived timestamp
    // is strictly greater than the parent's.
    context.sleep(Duration::from_millis(10)).await;

    let consensus_context = SimplexContext {
        round: Round::new(Epoch::zero(), View::new(view)),
        leader: leader.public_key(),
        parent: (View::new(view - 1), *parent.seal()),
    };
    let expected: Vec<sha256::Digest> =
        transactions.iter().map(|tx| *tx.message_digest()).collect();
    let mut input = StaticTransactionSource::new(vec![transactions]);
    let proposed = app
        .propose_child(
            (context.child("propose_private"), consensus_context.clone()),
            Arc::new(parent.clone()),
            dbs.new_batches().await,
            &mut input,
        )
        .await
        .expect("private proposal must succeed");
    assert_eq!(
        body_digests(&proposed.block),
        expected,
        "every private payload must survive selection"
    );

    let verified = app
        .verify_child(
            (context.child("verify_private"), consensus_context),
            Arc::new(proposed.block.clone()),
            std::future::ready(Some(Arc::new(parent.clone()))),
            dbs.new_batches().await,
        )
        .await
        .expect("private block must verify");
    dbs.finalize(verified).await;
    proposed.block
}

#[test]
fn private_fund_rollover_transfer_sequence_verifies_and_commits() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent,
            leader,
            sender,
            recipient,
            ..
        } = verify_harness(&context).await;

        // The client funds 400 into a fresh commitment, rolls it over, then
        // spends 150 of it; after the rollover the working current equals the
        // fund commitment, so the spend is provable with the fund's opening.
        let params = ChainBackend::params();
        let mut rng = StdRng::seed_from_u64(0x5eed_0001);
        let (fund_commitment, fund_opening, fund_proof) = ChainBackend::fund(params, 400, &mut rng);
        let (amount, _amount_opening, transfer_proof) =
            ChainBackend::transfer(params, &fund_commitment, &fund_opening, 150, &mut rng);

        let fund = private_payload(
            &sender,
            Payload::PrivateFund {
                value: NonZeroU64::new(400).expect("test value should be non-zero"),
                commitment: fund_commitment.clone(),
                proof: fund_proof,
            },
            0,
        );
        let rollover = private_payload(&sender, Payload::PrivateRollover, 1);
        let transfer = private_payload(
            &sender,
            Payload::PrivateTransfer {
                to: account_key(&recipient),
                amount: amount.clone(),
                proof: transfer_proof,
            },
            2,
        );

        let sender_key = account_key(&sender);
        let recipient_key = account_key(&recipient);
        let mut expected_private = StatePrivateAccount::zero();

        // Block 1: the fund drains public balance into the pending
        // commitment.
        let parent =
            seal_private_block(&context, &mut app, &dbs, &parent, &leader, 1, vec![fund]).await;
        expected_private.deposit(&to_state_commitment(fund_commitment));
        let account = read_account(&dbs, &sender_key)
            .await
            .expect("the sender is genesis funded");
        assert_eq!(
            account.balance,
            1_000_000 - 400,
            "the fund must drain the public balance"
        );
        assert_eq!(account.nonce, Nonce::new(1, 0));
        assert_eq!(account.private, expected_private);

        // Block 2: the rollover folds pending into spendable current.
        let parent = seal_private_block(
            &context,
            &mut app,
            &dbs,
            &parent,
            &leader,
            2,
            vec![rollover],
        )
        .await;
        expected_private.rollover();
        let account = read_account(&dbs, &sender_key)
            .await
            .expect("the sender is genesis funded");
        assert_eq!(account.balance, 1_000_000 - 400);
        assert_eq!(account.nonce, Nonce::new(2, 0));
        assert_eq!(account.private, expected_private);
        assert!(
            read_account(&dbs, &recipient_key).await.is_none(),
            "the recipient is untouched until the transfer lands"
        );

        // Block 3: the transfer spends current and credits the recipient's
        // pending commitment.
        seal_private_block(
            &context,
            &mut app,
            &dbs,
            &parent,
            &leader,
            3,
            vec![transfer],
        )
        .await;
        expected_private.withdraw(&to_state_commitment(amount.clone()));
        let account = read_account(&dbs, &sender_key)
            .await
            .expect("the sender is genesis funded");
        assert_eq!(
            account.balance,
            1_000_000 - 400,
            "a private transfer leaves the public balance alone"
        );
        assert_eq!(account.nonce, Nonce::new(3, 0));
        assert_eq!(account.private, expected_private);

        let mut expected_recipient = StatePrivateAccount::zero();
        expected_recipient.deposit(&to_state_commitment(amount));
        let account = read_account(&dbs, &recipient_key)
            .await
            .expect("the pending credit writes the recipient");
        assert_eq!(
            account.balance, DEFAULT_ACCOUNT_BALANCE,
            "an absent recipient materializes with the default balance"
        );
        assert_eq!(account.nonce, Nonce::default());
        assert_eq!(account.private, expected_recipient);
    });
}

#[test]
fn stale_private_transfer_proof_is_filtered_and_fails_verification() {
    deterministic::Runner::default().start(|context| async move {
        let VerifyHarness {
            mut app,
            dbs,
            parent,
            leader,
            sender,
            recipient,
            ..
        } = verify_harness(&context).await;

        // A spend of the just-funded 4 is provable only against a current
        // containing it; without a rollover the sender's working current is
        // still zero, so a proof bound to any other commitment cannot verify.
        let params = ChainBackend::params();
        let mut rng = StdRng::seed_from_u64(0x5eed_0002);
        let (fund_commitment, _fund_opening, fund_proof) = ChainBackend::fund(params, 4, &mut rng);
        let (stale_current, stale_opening) = ChainBackend::commit_public(params, 4);
        let (amount, _amount_opening, proof) =
            ChainBackend::transfer(params, &stale_current, &stale_opening, 4, &mut rng);

        let fund = private_payload(
            &sender,
            Payload::PrivateFund {
                value: NonZeroU64::new(4).expect("test value should be non-zero"),
                commitment: fund_commitment,
                proof: fund_proof,
            },
            0,
        );
        let stale = private_payload(
            &sender,
            Payload::PrivateTransfer {
                to: account_key(&recipient),
                amount,
                proof,
            },
            1,
        );

        context.sleep(Duration::from_millis(10)).await;
        let consensus_context = SimplexContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader: leader.public_key(),
            parent: (View::zero(), *parent.seal()),
        };

        // Proposing keeps the fund and filters the unprovable transfer.
        let mut input = StaticTransactionSource::new(vec![vec![fund.clone(), stale.clone()]]);
        let proposed = app
            .propose_child(
                (context.child("propose"), consensus_context.clone()),
                Arc::new(parent.clone()),
                dbs.new_batches().await,
                &mut input,
            )
            .await
            .expect("best-effort proposal must succeed");
        assert_eq!(
            body_digests(&proposed.block),
            vec![*fund.message_digest()],
            "the stale-proof transfer must be filtered out of the proposal"
        );

        // A block that includes the transfer anyway is rejected by
        // all-or-nothing verification.
        let header = unexecuted_child_header(&parent, &consensus_context);
        let block = Block::<sha256::Digest, _, sha256::Sha256>::new(header, vec![fund, stale])
            .seal(&mut sha256::Sha256::default());
        let rejected = app
            .verify_child(
                (context.child("verify"), consensus_context),
                Arc::new(block),
                std::future::ready(Some(Arc::new(parent))),
                dbs.new_batches().await,
            )
            .await;
        assert!(rejected.is_none());
    });
}
