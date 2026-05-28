use bytes::Bytes;
use commonware_codec::FixedSize;
use commonware_consensus::{
    simplex::types::Context,
    types::{Round, View, coding::Commitment},
};
use commonware_cryptography::{
    Digest as _, Signer as _,
    certificate::{Attestation, Scheme as CertificateScheme, Subject},
    ed25519, sha256,
};
use commonware_glue::stateful::db::DatabaseSet;
use commonware_parallel::Rayon;
use commonware_runtime::{
    Error as RuntimeError, Storage as _, Supervisor, ThreadPooler,
    benchmarks::{context as bench_context, tokio as bench_tokio},
    buffer::paged::CacheRef,
    tokio::{Config as RuntimeConfig, Context as RuntimeContext},
};
use commonware_storage::{
    journal::contiguous::fixed::Config as FixedJournalConfig,
    merkle::{Location, compact::Config as CompactMerkleConfig, full::Config as MmrConfig, mmr},
    qmdb::{
        any::{FixedConfig, value::FixedEncoding},
        keyless::fixed as keyless_fixed,
    },
    translator::EightCap,
};
use commonware_utils::{
    Faults, NZU16, NZU64, NZUsize, non_empty_range,
    sequence::{FixedBytes, U64},
};
use constantinople_application::consensus::{Application, Databases, TransactionHistoryTarget};
use constantinople_engine::types::EngineBlock;
use constantinople_indexer::publisher::{
    QmdbPublisher,
    qmdb::{state_qmdb_client, transactions_qmdb_client},
};
use constantinople_mempool::mocks::StaticTransactionSource;
use constantinople_primitives::{
    Account, AccountKey, Block, Header, Sealable, TRANSACTION_NAMESPACE, Transaction,
    TransactionPublicKey, VerifiedTransaction,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use exoware_qmdb::{KeylessClient, UnorderedClient};
use exoware_sdk::{RetryConfig, StoreClient};
use std::{
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::{Duration, Instant},
};
use tempfile::TempDir;
use tokio::time::sleep;

type TestHasher = sha256::Sha256;
type TestCommitment = Commitment;
type TestPublicKey = ed25519::PublicKey;
type TestTransaction = VerifiedTransaction<TestHasher>;
type TestTransactionSource = StaticTransactionSource<TestCommitment, TestPublicKey, TestHasher>;
type TestApplication = Application<
    RuntimeContext,
    TestHasher,
    TestCommitment,
    BenchScheme,
    TestPublicKey,
    TestTransactionSource,
    ed25519::Batch,
    Rayon,
    Rayon,
>;
type TestDatabases = Databases<RuntimeContext, TestHasher, EightCap, Rayon>;
type TestBlock = EngineBlock<TestHasher, TestPublicKey>;
type TestConsensusContext = Context<TestCommitment, TestPublicKey>;
type TestQmdbPublisher = QmdbPublisher<TestHasher, TestPublicKey>;
type QmdbFamily = mmr::Family;
type AccountValue = FixedBytes<{ Account::SIZE }>;
type StateReader =
    UnorderedClient<QmdbFamily, TestHasher, AccountKey, AccountValue, FixedEncoding<AccountValue>>;
type TransactionReader =
    KeylessClient<QmdbFamily, TestHasher, sha256::Digest, FixedEncoding<sha256::Digest>>;

const TX_PER_BLOCK: usize = 16_384;
const WARM_NONCE: u64 = 0;
const MEASURED_NONCE: u64 = 1;
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(1_048_576);
const WRITE_BUFFER: NonZeroUsize = NZUsize!(1024 * 1024);
const PAGE_CACHE_PAGE_SIZE: NonZeroU16 = NZU16!(8192);
const PAGE_CACHE_CAPACITY: NonZeroUsize = NZUsize!(16_384);

#[derive(Clone, Copy, Debug)]
struct BenchSubject<'a> {
    message: &'a [u8],
}

impl Subject for BenchSubject<'_> {
    type Namespace = Vec<u8>;

    fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
        derived
    }

    fn message(&self) -> Bytes {
        Bytes::copy_from_slice(self.message)
    }
}

#[derive(Clone, Debug)]
struct BenchScheme;

impl CertificateScheme for BenchScheme {
    type Subject<'a, D: commonware_cryptography::Digest> = BenchSubject<'a>;
    type PublicKey = TestPublicKey;
    type Signature = U64;
    type Certificate = U64;

    fn me(&self) -> Option<commonware_utils::Participant> {
        unreachable!("benchmark scheme is never instantiated")
    }

    fn participants(&self) -> &commonware_utils::ordered::Set<Self::PublicKey> {
        unreachable!("benchmark scheme is never instantiated")
    }

    fn sign<D: commonware_cryptography::Digest>(
        &self,
        _subject: Self::Subject<'_, D>,
    ) -> Option<Attestation<Self>> {
        unreachable!("benchmark scheme is never instantiated")
    }

    fn verify_attestation<R, D>(
        &self,
        _rng: &mut R,
        _subject: Self::Subject<'_, D>,
        _attestation: &Attestation<Self>,
        _strategy: &impl commonware_parallel::Strategy,
    ) -> bool
    where
        R: rand_core::CryptoRngCore,
        D: commonware_cryptography::Digest,
    {
        unreachable!("benchmark scheme is never instantiated")
    }

    fn assemble<I, M>(
        &self,
        _attestations: I,
        _strategy: &impl commonware_parallel::Strategy,
    ) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = Attestation<Self>>,
        I::IntoIter: Send,
        M: Faults,
    {
        unreachable!("benchmark scheme is never instantiated")
    }

    fn verify_certificate<R, D, M>(
        &self,
        _rng: &mut R,
        _subject: Self::Subject<'_, D>,
        _certificate: &Self::Certificate,
        _strategy: &impl commonware_parallel::Strategy,
    ) -> bool
    where
        R: rand_core::CryptoRngCore,
        D: commonware_cryptography::Digest,
        M: Faults,
    {
        unreachable!("benchmark scheme is never instantiated")
    }

    fn is_attributable() -> bool {
        true
    }

    fn is_batchable() -> bool {
        true
    }

    fn certificate_codec_config(&self) {}

    fn certificate_codec_config_unbounded() {}
}

fn secondary(c: &mut Criterion) {
    let runner = bench_tokio::Runner::new(RuntimeConfig::default());
    let mut group = c.benchmark_group("indexer/secondary_uploader");
    group.throughput(Throughput::Elements(TX_PER_BLOCK as u64));
    group.bench_with_input(
        BenchmarkId::new("qmd_finalized_steady_state", TX_PER_BLOCK),
        &TX_PER_BLOCK,
        |bencher, &tx_count| {
            bencher
                .to_async(&runner)
                .iter_custom(move |iterations| measure(tx_count, iterations));
        },
    );
    group.finish();
}

async fn measure(tx_count: usize, iterations: u64) -> Duration {
    let runtime = bench_context::get::<RuntimeContext>();
    let mut total = Duration::ZERO;

    for iteration in 0..iterations {
        let prefix = format!("secondary-uploader-bench-{tx_count}-{iteration}");
        cleanup_partitions(&runtime, &prefix).await;

        let scenario = UploadScenario::new(&runtime, tx_count, &prefix).await;
        total += scenario.upload_measured_block().await;

        drop(scenario);
        cleanup_partitions(&runtime, &prefix).await;
    }

    total
}

struct UploadScenario {
    publisher: TestQmdbPublisher,
    databases: TestDatabases,
    block: TestBlock,
    state_reader: StateReader,
    transaction_reader: TransactionReader,
    state_target: Location<QmdbFamily>,
    transaction_target: Location<QmdbFamily>,
    _store: BenchStore,
}

impl UploadScenario {
    async fn new(runtime: &RuntimeContext, tx_count: usize, prefix: &str) -> Self {
        let store = BenchStore::spawn().await;
        let publisher = TestQmdbPublisher::connect(store.url(), 8)
            .await
            .expect("qmd publisher connects to benchmark store");
        let state_reader = StateReader::from_client(
            state_qmdb_client(store.client()).expect("state qmd client"),
            (),
            ((), ()),
        );
        let transaction_reader = TransactionReader::from_client(
            transactions_qmdb_client(store.client()).expect("transaction qmd client"),
            (),
        );

        let mut chain = ChainFixture::new(runtime, tx_count, prefix).await;
        let warm = chain.finalize_next_block(runtime, WARM_NONCE).await;
        publisher
            .upload_finalized(&warm, &chain.databases)
            .await
            .expect("warm qmd upload enqueues");
        wait_for_watermarks(
            &state_reader,
            &transaction_reader,
            watermark_target(warm.header.state_range.end()),
            watermark_target(warm.header.transactions_range.end()),
        )
        .await;

        let block = chain.finalize_next_block(runtime, MEASURED_NONCE).await;
        let state_target = watermark_target(block.header.state_range.end());
        let transaction_target = watermark_target(block.header.transactions_range.end());

        Self {
            publisher,
            databases: chain.databases,
            block,
            state_reader,
            transaction_reader,
            state_target,
            transaction_target,
            _store: store,
        }
    }

    async fn upload_measured_block(&self) -> Duration {
        let started_at = Instant::now();
        self.publisher
            .upload_finalized(&self.block, &self.databases)
            .await
            .expect("measured qmd upload enqueues");
        wait_for_watermarks(
            &self.state_reader,
            &self.transaction_reader,
            self.state_target,
            self.transaction_target,
        )
        .await;
        started_at.elapsed()
    }
}

struct BenchStore {
    url: String,
    client: StoreClient,
    _handle: tokio::task::JoinHandle<()>,
    _dir: TempDir,
}

impl BenchStore {
    async fn spawn() -> Self {
        let dir = TempDir::new().expect("tempdir");
        let (handle, url) = exoware_simulator::spawn_for_test(dir.path())
            .await
            .expect("spawn simulator");
        let client = StoreClient::with_retry_config(&url, RetryConfig::disabled());
        Self {
            url,
            client,
            _handle: handle,
            _dir: dir,
        }
    }

    fn url(&self) -> &str {
        &self.url
    }

    const fn client(&self) -> &StoreClient {
        &self.client
    }
}

struct ChainFixture {
    app: TestApplication,
    databases: TestDatabases,
    parent: TestBlock,
    workload: GeneratedWorkload,
}

impl ChainFixture {
    async fn new(runtime: &RuntimeContext, tx_count: usize, prefix: &str) -> Self {
        let workload = GeneratedWorkload::new(tx_count);
        let hash_strategy = bench_strategy(runtime);
        let signature_strategy = bench_strategy(runtime);
        let databases = init_databases(runtime, prefix, hash_strategy.clone()).await;
        let parent = parent_block(workload.leader.clone(), &databases).await;
        let app = new_application(
            runtime,
            workload.leader.clone(),
            &databases,
            signature_strategy,
            hash_strategy,
        )
        .await;

        Self {
            app,
            databases,
            parent,
            workload,
        }
    }

    async fn finalize_next_block(&mut self, runtime: &RuntimeContext, nonce: u64) -> TestBlock {
        let transactions = self.workload.transactions(nonce);
        let mut input = TestTransactionSource::new(vec![transactions]);
        let batches = self.databases.new_batches().await;
        let proposed = self
            .app
            .propose_child(
                (
                    runtime.child("propose"),
                    block_context(self.workload.leader.clone()),
                ),
                &self.parent,
                batches,
                &mut input,
            )
            .await
            .expect("proposal should succeed");
        let block = proposed.block;
        self.databases.finalize(proposed.merkleized).await;
        self.parent = block.clone();
        block
    }
}

struct GeneratedWorkload {
    senders: Vec<TestSigner>,
    leader: TestPublicKey,
}

impl GeneratedWorkload {
    fn new(tx_count: usize) -> Self {
        let leader = TestSigner::new(u64::MAX).public_key;
        let mut senders = Vec::with_capacity(tx_count);

        for index in 0..tx_count {
            let sender = TestSigner::new(index as u64);
            senders.push(sender);
        }

        Self { senders, leader }
    }

    fn transactions(&self, nonce: u64) -> Vec<TestTransaction> {
        self.senders
            .iter()
            .enumerate()
            .map(|(index, sender)| {
                let recipient = self.senders[(index + 1) % self.senders.len()]
                    .public_key
                    .clone();
                sender.sign(recipient, 1, nonce)
            })
            .collect()
    }
}

struct TestSigner {
    key: ed25519::PrivateKey,
    public_key: ed25519::PublicKey,
}

impl TestSigner {
    fn new(seed: u64) -> Self {
        let key = ed25519::PrivateKey::from_seed(seed);
        let public_key = key.public_key();
        Self { key, public_key }
    }

    fn sign(&self, to: ed25519::PublicKey, value: u64, nonce: u64) -> TestTransaction {
        Transaction::new(
            TransactionPublicKey::ed25519(self.key.public_key()),
            TransactionPublicKey::ed25519(to),
            NonZeroU64::new(value).expect("bench value must be non-zero"),
            nonce,
        )
        .seal_and_sign(&self.key, TRANSACTION_NAMESPACE, &mut TestHasher::default())
    }
}

async fn init_databases(runtime: &RuntimeContext, prefix: &str, strategy: Rayon) -> TestDatabases {
    TestDatabases::init(
        runtime.child("databases"),
        (
            state_db_config(runtime, prefix, strategy.clone()),
            transaction_db_config(prefix, strategy),
        ),
    )
    .await
}

async fn new_application(
    runtime: &RuntimeContext,
    leader: TestPublicKey,
    databases: &TestDatabases,
    signature_strategy: Rayon,
    hash_strategy: Rayon,
) -> TestApplication {
    let (state_target, transaction_target) = databases.committed_targets().await;
    let genesis_transactions_target = TransactionHistoryTarget {
        root: transaction_target.root,
        leaf_count: transaction_target.leaf_count,
    };

    TestApplication::new(
        runtime.child("application"),
        signature_strategy,
        hash_strategy,
        leader,
        TestCommitment::EMPTY,
        TRANSACTION_NAMESPACE,
        state_target,
        genesis_transactions_target,
        NZU64!(1024),
        Arc::new(|_| Box::pin(async {})),
        None,
    )
}

fn bench_strategy(runtime: &RuntimeContext) -> Rayon {
    Rayon::with_pool(runtime.create_thread_pool(NZUsize!(8)).unwrap())
}

async fn parent_block(leader: TestPublicKey, databases: &TestDatabases) -> TestBlock {
    let (state_target, transaction_target) = databases.committed_targets().await;
    let header = Header {
        context: block_context(leader),
        parent: sha256::Digest::EMPTY,
        height: 0,
        timestamp: 0,
        state_root: state_target.root,
        state_range: non_empty_range!(*state_target.range.start(), *state_target.range.end()),
        transactions_root: transaction_target.root,
        transactions_range: non_empty_range!(0, *transaction_target.leaf_count),
    };

    Block::new(header, Vec::new()).seal(&mut TestHasher::default())
}

const fn block_context(leader: TestPublicKey) -> TestConsensusContext {
    Context {
        round: Round::zero(),
        leader,
        parent: (View::zero(), TestCommitment::EMPTY),
    }
}

fn state_db_config(
    runtime: &RuntimeContext,
    prefix: &str,
    strategy: Rayon,
) -> FixedConfig<EightCap, Rayon> {
    let page_cache = CacheRef::from_pooler(
        &runtime.child("state_page_cache"),
        PAGE_CACHE_PAGE_SIZE,
        PAGE_CACHE_CAPACITY,
    );

    FixedConfig {
        merkle_config: MmrConfig {
            journal_partition: format!("{prefix}-state-journal"),
            metadata_partition: format!("{prefix}-state-metadata"),
            items_per_blob: ITEMS_PER_BLOB,
            write_buffer: WRITE_BUFFER,
            strategy,
            page_cache: page_cache.clone(),
        },
        journal_config: FixedJournalConfig {
            partition: format!("{prefix}-state-log"),
            items_per_blob: ITEMS_PER_BLOB,
            page_cache,
            write_buffer: WRITE_BUFFER,
        },
        translator: EightCap,
    }
}

fn transaction_db_config(prefix: &str, strategy: Rayon) -> keyless_fixed::CompactConfig<Rayon> {
    keyless_fixed::CompactConfig {
        merkle: CompactMerkleConfig {
            partition: format!("{prefix}-transactions-merkle"),
            strategy,
        },
        commit_codec_config: (),
    }
}

async fn wait_for_watermarks(
    state_reader: &StateReader,
    transaction_reader: &TransactionReader,
    state_target: Location<QmdbFamily>,
    transaction_target: Location<QmdbFamily>,
) {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let state = state_reader
            .writer_location_watermark()
            .await
            .expect("state qmd watermark query");
        let transactions = transaction_reader
            .writer_location_watermark()
            .await
            .expect("transaction qmd watermark query");
        if state.is_some_and(|watermark| watermark >= state_target)
            && transactions.is_some_and(|watermark| watermark >= transaction_target)
        {
            return;
        }

        assert!(
            Instant::now() < deadline,
            "timed out waiting for qmd upload through state={state:?}/{state_target:?} transactions={transactions:?}/{transaction_target:?}",
        );
        sleep(Duration::from_millis(10)).await;
    }
}

const fn watermark_target(end: u64) -> Location<QmdbFamily> {
    Location::new(end.checked_sub(1).expect("watermark range is non-empty"))
}

async fn cleanup_partitions(runtime: &RuntimeContext, prefix: &str) {
    for partition in partition_names(prefix) {
        match runtime.remove(&partition, None).await {
            Ok(()) | Err(RuntimeError::PartitionMissing(_)) => {}
            Err(error) => panic!("bench partition cleanup should succeed: {error}"),
        }
    }
}

fn partition_names(prefix: &str) -> [String; 4] {
    [
        format!("{prefix}-state-journal"),
        format!("{prefix}-state-metadata"),
        format!("{prefix}-state-log"),
        format!("{prefix}-transactions-merkle"),
    ]
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(3));
    targets = secondary
}
criterion_main!(benches);
