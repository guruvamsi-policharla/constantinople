//! End-to-end processor test harness.
//!
//! This module builds a deterministic QMDB-backed harness around the
//! processor so tests can:
//!
//! - seed initial account and storage state
//! - define scripted precompile behavior
//! - simulate access lists
//! - execute signed transaction slices
//! - assert receipts and persistent changesets

use super::{Frame, FrameError, Precompiles, Processor, ProcessorOutput, state::AccessListBuilder};
use crate::application::{ProcessorError, StateDatabase, load_state};
use bytes::Bytes;
use commonware_codec::{DecodeExt, FixedSize};
use commonware_cryptography::{Signer, blake3, secp256r1::recoverable};
use commonware_glue::stateful::db::ManagedDb;
use commonware_math::algebra::Random;
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_runtime::{Runner as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig,
    mmr::journaled::Config as MmrConfig,
    qmdb::any::{FixedConfig, unordered::fixed},
    translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, sync::AsyncRwLock};
use constantinople_primitives::{
    Access, AccessList, AccessMode, Account, Address, Receipt, ReceiptStatus, Slot, StateValue,
    Transaction, VerifiedTransaction,
};
use rand::{SeedableRng, rngs::StdRng};
use rstest::rstest;
use std::{
    collections::{BTreeMap, HashSet},
    marker::PhantomData,
    num::NonZeroUsize,
    sync::Arc,
};

const NAMESPACE: &[u8] = b"processor-test";

type TestDigest = blake3::Digest;
type TestHasher = blake3::Blake3;
type TestPublicKey = recoverable::PublicKey;
type TestSigned = VerifiedTransaction<TestPublicKey, TestHasher>;
type TestContext = deterministic::Context;

#[derive(Debug, Clone)]
struct TestSigner {
    seed: [u8; 32],
    address: Address,
}

impl TestSigner {
    fn new(seed: [u8; 32]) -> Self {
        let key = private_key(seed);
        let public_key = key.public_key();
        let address = Address::from_public_key(&mut TestHasher::default(), &public_key);
        Self { seed, address }
    }

    fn sign(
        &self,
        to: Address,
        value: u64,
        nonce: u64,
        input: Bytes,
        access_list: AccessList,
    ) -> TestSigned {
        let key = private_key(self.seed);
        Transaction {
            sender: key.public_key(),
            to,
            input,
            value,
            nonce,
            access_list,
            _digest: PhantomData,
        }
        .seal_and_sign_verified(&key, NAMESPACE, &mut TestHasher::default())
    }
}

#[derive(Debug, Clone)]
enum AccessListSource {
    Simulate,
    Fixed(AccessList),
}

#[derive(Debug, Clone)]
struct TransactionSpec {
    signer: TestSigner,
    to: Address,
    value: u64,
    nonce: u64,
    input: Bytes,
    access_list: AccessListSource,
}

impl TransactionSpec {
    fn transfer(signer: TestSigner, to: Address, value: u64, nonce: u64) -> Self {
        Self {
            signer,
            to,
            value,
            nonce,
            input: Bytes::new(),
            access_list: AccessListSource::Simulate,
        }
    }

    fn call(signer: TestSigner, to: Address, value: u64, nonce: u64, input: Bytes) -> Self {
        Self {
            signer,
            to,
            value,
            nonce,
            input,
            access_list: AccessListSource::Simulate,
        }
    }

    fn with_access_list(mut self, access_list: AccessList) -> Self {
        self.access_list = AccessListSource::Fixed(access_list);
        self
    }

    fn simulation_access_list(&self, precompiles: &TestPrecompiles) -> AccessList {
        match &self.access_list {
            AccessListSource::Simulate => precompiles.simulation_access_list(self.to),
            AccessListSource::Fixed(access_list) => access_list.clone(),
        }
    }

    fn resolved_access_list(
        &self,
        precompiles: &TestPrecompiles,
        simulated_access_lists: &[Option<AccessList>],
        index: usize,
    ) -> AccessList {
        match &self.access_list {
            AccessListSource::Simulate => simulated_access_lists[index]
                .clone()
                .unwrap_or_else(|| self.simulation_access_list(precompiles)),
            AccessListSource::Fixed(access_list) => access_list.clone(),
        }
    }

    fn sign_with_access_list(&self, access_list: AccessList) -> TestSigned {
        self.signer.sign(
            self.to,
            self.value,
            self.nonce,
            self.input.clone(),
            access_list,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PrecompileStep {
    InspectAccount(Address),
    InspectStorage(Address, Slot),
    AssertAccountBalance(Address, u64),
    AssertStorage(Address, Slot, Slot),
    ReadStorage(Slot),
    AssertReadStorage(Slot, Slot),
    WriteStorage(Slot, Slot),
    Transfer(Address, u64),
    Call(Address, u64, Bytes),
    AssertCallReturns(Address, u64, Bytes, Bytes),
    AssertCallReverts(Address, u64, Bytes, Bytes),
    Panic,
    Return(Bytes),
    Revert(Bytes),
}

#[derive(Debug, Clone, Default)]
struct TestPrecompiles {
    programs: BTreeMap<Address, Vec<PrecompileStep>>,
}

impl TestPrecompiles {
    fn insert(&mut self, address: Address, program: Vec<PrecompileStep>) {
        self.programs.insert(address, program);
    }

    fn simulation_access_list(&self, address: Address) -> AccessList {
        let mut builder = AccessListBuilder::default();
        let mut visited = HashSet::new();
        self.record_simulation_accesses(address, &mut builder, &mut visited);
        builder.into_access_list()
    }

    fn record_simulation_accesses(
        &self,
        address: Address,
        builder: &mut AccessListBuilder,
        visited: &mut HashSet<Address>,
    ) {
        if !visited.insert(address) {
            return;
        }

        let Some(program) = self.programs.get(&address) else {
            return;
        };

        for step in program {
            match step {
                PrecompileStep::InspectAccount(address) => {
                    builder.record_account(*address, AccessMode::Read);
                }
                PrecompileStep::InspectStorage(address, slot) => {
                    builder.record_storage(*address, *slot, AccessMode::Read);
                }
                PrecompileStep::AssertAccountBalance(address, _) => {
                    builder.record_account(*address, AccessMode::Read);
                }
                PrecompileStep::AssertStorage(address, slot, _) => {
                    builder.record_storage(*address, *slot, AccessMode::Read);
                }
                PrecompileStep::ReadStorage(slot) => {
                    builder.record_storage(address, *slot, AccessMode::Read);
                }
                PrecompileStep::AssertReadStorage(slot, _) => {
                    builder.record_storage(address, *slot, AccessMode::Read);
                }
                PrecompileStep::WriteStorage(slot, _) => {
                    builder.record_storage(address, *slot, AccessMode::Write);
                }
                PrecompileStep::Transfer(recipient, _) => {
                    builder.record_account(address, AccessMode::Write);
                    builder.record_account(*recipient, AccessMode::Write);
                }
                PrecompileStep::Call(callee, value, _)
                | PrecompileStep::AssertCallReturns(callee, value, _, _)
                | PrecompileStep::AssertCallReverts(callee, value, _, _) => {
                    if *value > 0 {
                        builder.record_account(address, AccessMode::Write);
                        builder.record_account(*callee, AccessMode::Write);
                    } else {
                        builder.record_account(address, AccessMode::Read);
                        builder.record_account(*callee, AccessMode::Read);
                    }

                    self.record_simulation_accesses(*callee, builder, visited);
                }
                PrecompileStep::Panic | PrecompileStep::Return(_) | PrecompileStep::Revert(_) => {}
            }
        }
    }
}

impl Precompiles for TestPrecompiles {
    fn is_precompile(&self, address: Address) -> bool {
        self.programs.contains_key(&address)
    }

    fn execute<S>(
        &self,
        address: Address,
        frame: &mut Frame<'_>,
        processor: &Processor<'_, S, Self>,
    ) -> Result<Bytes, FrameError>
    where
        S: Strategy,
        Self: Sized,
    {
        let program = self.programs.get(&address).cloned();
        let Some(program) = program else {
            return Ok(Bytes::new());
        };

        for step in program {
            match step {
                PrecompileStep::InspectAccount(address) => {
                    let _ = frame.inspect_account(address)?;
                }
                PrecompileStep::InspectStorage(address, slot) => {
                    let _ = frame.inspect_storage(address, slot)?;
                }
                PrecompileStep::AssertAccountBalance(address, expected_balance) => {
                    let account = frame.inspect_account(address)?;
                    assert_eq!(
                        account.balance, expected_balance,
                        "unexpected account balance"
                    );
                }
                PrecompileStep::AssertStorage(address, slot, expected) => {
                    let value = frame.inspect_storage(address, slot)?;
                    assert_eq!(value, expected, "unexpected storage value");
                }
                PrecompileStep::ReadStorage(slot) => {
                    let _ = frame.read_storage(slot)?;
                }
                PrecompileStep::AssertReadStorage(slot, expected) => {
                    let value = frame.read_storage(slot)?;
                    assert_eq!(value, expected, "unexpected owner storage value");
                }
                PrecompileStep::WriteStorage(slot, value) => {
                    frame.write_storage(slot, value)?;
                }
                PrecompileStep::Transfer(address, value) => {
                    frame.transfer(address, value)?;
                }
                PrecompileStep::Call(address, value, input) => {
                    let _ = frame.call(processor, address, value, input)?;
                }
                PrecompileStep::AssertCallReturns(address, value, input, expected) => {
                    let result = frame.call(processor, address, value, input)?;
                    assert_eq!(result, expected, "unexpected child return value");
                }
                PrecompileStep::AssertCallReverts(address, value, input, expected) => {
                    let result = frame.call(processor, address, value, input);
                    assert_eq!(
                        result,
                        Err(FrameError::Revert(expected)),
                        "unexpected child revert result"
                    );
                }
                PrecompileStep::Panic => panic!("scripted precompile panic"),
                PrecompileStep::Return(data) => return Ok(data),
                PrecompileStep::Revert(data) => return Err(FrameError::Revert(data)),
            }
        }

        Ok(Bytes::new())
    }
}

#[derive(Debug)]
struct ProcessorRun {
    transactions: Vec<TestSigned>,
    output: ProcessorOutput<TestDigest>,
}

impl ProcessorRun {
    fn receipt(&self, index: usize) -> &Receipt<TestDigest> {
        &self.output.receipts[index]
    }

    fn built_access_list(&self, index: usize) -> Option<&AccessList> {
        self.output.access_lists.as_ref()?.get(index)?.as_ref()
    }

    fn transaction_access_list(&self, index: usize) -> &AccessList {
        &self.transactions[index].value().access_list
    }

    fn account_change(&self, address: Address) -> Option<Account> {
        match self
            .output
            .changeset
            .get(&super::state::account_key(address))
        {
            Some(StateValue::Account(account)) => Some(*account),
            Some(StateValue::Storage(_)) => panic!("account key stored a storage value"),
            None => None,
        }
    }

    fn storage_change(&self, address: Address, slot: Slot) -> Option<Slot> {
        let mut hasher = TestHasher::default();
        let key = super::state::storage_key(&mut hasher, address, slot);
        match self.output.changeset.get(&key) {
            Some(StateValue::Storage(value)) => Some(*value),
            Some(StateValue::Account(_)) => panic!("storage key stored an account value"),
            None => None,
        }
    }
}

#[derive(Clone)]
struct ProcessorHarness {
    db: StateDatabase<TestContext, TestHasher, EightCap>,
    precompiles: TestPrecompiles,
}

impl ProcessorHarness {
    async fn new(context: TestContext, suffix: &str) -> Self {
        Self {
            db: open_state_db(context, suffix).await,
            precompiles: TestPrecompiles::default(),
        }
    }

    fn signer(&self, seed: [u8; 32]) -> TestSigner {
        TestSigner::new(seed)
    }

    fn insert_precompile(&mut self, address: Address, program: Vec<PrecompileStep>) {
        self.precompiles.insert(address, program);
    }

    async fn set_account(&self, address: Address, account: Account) {
        self.write_state([(
            super::state::account_key(address),
            StateValue::Account(account),
        )])
        .await;
    }

    async fn set_storage(&self, address: Address, slot: Slot, value: Slot) {
        let mut hasher = TestHasher::default();
        let key = super::state::storage_key(&mut hasher, address, slot);
        self.write_state([(key, StateValue::Storage(value))]).await;
    }

    async fn execute_specs(
        &self,
        specs: &[TransactionSpec],
    ) -> Result<ProcessorRun, ProcessorError> {
        let transactions = self.transactions(specs).await?;
        let output = self.process(&transactions).await?;
        Ok(ProcessorRun {
            transactions,
            output,
        })
    }

    async fn execute_specs_with_strategy<S>(
        &self,
        specs: &[TransactionSpec],
        strategy: &S,
    ) -> Result<ProcessorRun, ProcessorError>
    where
        S: Strategy,
    {
        let transactions = self.transactions(specs).await?;
        let output = self.process_with_strategy(&transactions, strategy).await?;
        Ok(ProcessorRun {
            transactions,
            output,
        })
    }

    async fn transactions(
        &self,
        specs: &[TransactionSpec],
    ) -> Result<Vec<TestSigned>, ProcessorError> {
        let provisional = specs
            .iter()
            .map(|spec| spec.sign_with_access_list(spec.simulation_access_list(&self.precompiles)))
            .collect::<Vec<_>>();

        let simulated_access_lists = if specs
            .iter()
            .any(|spec| matches!(spec.access_list, AccessListSource::Simulate))
        {
            self.simulate_access_lists(&provisional).await?
        } else {
            vec![None; specs.len()]
        };

        Ok(specs
            .iter()
            .enumerate()
            .map(|(index, spec)| {
                let access_list =
                    spec.resolved_access_list(&self.precompiles, &simulated_access_lists, index);
                spec.sign_with_access_list(access_list)
            })
            .collect())
    }

    async fn simulate_access_lists(
        &self,
        transactions: &[TestSigned],
    ) -> Result<Vec<Option<AccessList>>, ProcessorError> {
        let batch = ManagedDb::new_batch(&self.db).await;
        let state = load_state(&batch, transactions).await?;
        let precompiles = self.precompiles.clone();
        let processor = Processor::new(&Sequential, &precompiles).with_access_list_builder();
        let output = processor.process(state, transactions);
        Ok(output
            .access_lists
            .expect("access-list builder should be enabled"))
    }

    async fn process(
        &self,
        transactions: &[TestSigned],
    ) -> Result<ProcessorOutput<TestDigest>, ProcessorError> {
        self.process_with_strategy(transactions, &Sequential).await
    }

    async fn process_with_strategy<S>(
        &self,
        transactions: &[TestSigned],
        strategy: &S,
    ) -> Result<ProcessorOutput<TestDigest>, ProcessorError>
    where
        S: Strategy,
    {
        let batch = ManagedDb::new_batch(&self.db).await;
        let state = load_state(&batch, transactions).await?;
        let precompiles = self.precompiles.clone();
        let processor = Processor::new(strategy, &precompiles).with_access_list_builder();
        Ok(processor.process(state, transactions))
    }

    async fn filter_invalid(
        &self,
        transactions: &[TestSigned],
    ) -> Result<Vec<TestSigned>, ProcessorError> {
        let batch = ManagedDb::new_batch(&self.db).await;
        let state = load_state(&batch, transactions).await?;
        let precompiles = self.precompiles.clone();
        let processor = Processor::new(&Sequential, &precompiles);
        let (filtered, _output) = processor.filter_and_execute(state, transactions);
        Ok(filtered)
    }

    async fn all_statically_valid(
        &self,
        transactions: &[TestSigned],
    ) -> Result<bool, ProcessorError> {
        let batch = ManagedDb::new_batch(&self.db).await;
        let state = load_state(&batch, transactions).await?;
        let precompiles = self.precompiles.clone();
        let processor = Processor::new(&Sequential, &precompiles);
        Ok(processor.all_statically_valid(state, transactions))
    }

    async fn write_state(&self, writes: impl IntoIterator<Item = (Slot, StateValue)>) {
        let mut db = self.db.write().await;
        let batch = writes
            .into_iter()
            .fold(db.new_batch(), |batch, (key, value)| {
                batch.write(key, Some(value))
            });
        let finalized = batch
            .merkleize(None, &db)
            .await
            .expect("merkleization should succeed")
            .finalize();
        db.apply_batch(finalized)
            .await
            .expect("batch apply should succeed");
    }
}

fn address(byte: u8) -> Address {
    Address::decode(&[byte; Address::SIZE][..]).expect("address bytes should decode")
}

fn slot(byte: u8) -> Slot {
    Slot::from([byte; Slot::SIZE])
}

fn private_key(seed: [u8; 32]) -> recoverable::PrivateKey {
    let mut rng = StdRng::from_seed(seed);
    recoverable::PrivateKey::random(&mut rng)
}

fn state_db_config(suffix: &str, context: &TestContext) -> FixedConfig<EightCap> {
    let page_cache = CacheRef::from_pooler(context, NZU16!(101), NZUsize!(11));
    FixedConfig {
        mmr_config: MmrConfig {
            journal_partition: format!("journal-{suffix}"),
            metadata_partition: format!("metadata-{suffix}"),
            items_per_blob: NZU64!(11),
            write_buffer: NZUsize!(1024),
            thread_pool: None,
            page_cache: page_cache.clone(),
        },
        journal_config: JournalConfig {
            partition: format!("log-journal-{suffix}"),
            items_per_blob: NZU64!(7),
            page_cache,
            write_buffer: NZUsize!(1024),
        },
        translator: EightCap,
    }
}

async fn open_state_db(
    context: TestContext,
    suffix: &str,
) -> StateDatabase<TestContext, TestHasher, EightCap> {
    let db = fixed::Db::init(context.clone(), state_db_config(suffix, &context))
        .await
        .expect("db init should succeed");
    Arc::new(AsyncRwLock::new(db))
}

fn run_test<F, Fut>(test: F)
where
    F: FnOnce(TestContext) -> Fut,
    Fut: Future<Output = ()> + 'static,
{
    let executor = deterministic::Runner::default();
    executor.start(test);
}

fn parallel_strategy() -> Rayon {
    Rayon::new(NonZeroUsize::new(4).expect("thread count must be non-zero"))
        .expect("rayon strategy should build")
}

fn assert_receipt(run: &ProcessorRun, index: usize, status: ReceiptStatus, return_data: Bytes) {
    assert_eq!(run.receipt(index).status, status);
    assert_eq!(run.receipt(index).return_data, return_data);
}

#[derive(Debug, Clone, Copy)]
enum BuilderCase {
    UpgradesReadToWrite,
    DeduplicatesRepeatedAccesses,
    RecordsCrossAccountReads,
}

#[test]
fn write_access_allows_reads() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "write-access-allows-reads").await;
        let sender = harness.signer([1; 32]);
        let precompile = address(0x31);
        let owner_slot = slot(0x41);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness
            .set_storage(precompile, owner_slot, slot(0x10))
            .await;
        harness.insert_precompile(
            precompile,
            vec![
                PrecompileStep::AssertReadStorage(owner_slot, slot(0x10)),
                PrecompileStep::WriteStorage(owner_slot, slot(0x20)),
                PrecompileStep::Return(Bytes::from_static(b"ok")),
            ],
        );

        let run = harness
            .execute_specs(&[
                TransactionSpec::call(sender, precompile, 0, 0, Bytes::new()).with_access_list(
                    vec![Access::Storage(precompile, owner_slot, AccessMode::Write)],
                ),
            ])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::from_static(b"ok"));
        assert_eq!(run.storage_change(precompile, owner_slot), Some(slot(0x20)));
    });
}

#[test]
fn undeclared_account_read_reverts() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "undeclared-account-read").await;
        let sender = harness.signer([2; 32]);
        let precompile = address(0x32);
        let other = address(0x42);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness
            .set_account(
                other,
                Account {
                    balance: 7,
                    nonce: 3,
                },
            )
            .await;
        harness.insert_precompile(
            precompile,
            vec![
                PrecompileStep::InspectAccount(other),
                PrecompileStep::Return(Bytes::from_static(b"ok")),
            ],
        );

        let run = harness
            .execute_specs(&[
                TransactionSpec::call(sender.clone(), precompile, 0, 0, Bytes::new())
                    .with_access_list(Vec::new()),
            ])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::new());
        assert_eq!(
            run.account_change(sender.address),
            Some(Account {
                balance: 10,
                nonce: 1,
            })
        );
        assert_eq!(run.account_change(other), None);
    });
}

#[test]
fn malformed_loaded_account_value_returns_error() {
    run_test(|context| async move {
        let harness = ProcessorHarness::new(context, "malformed-account-value").await;
        let sender = harness.signer([50; 32]);
        let recipient = address(0x90);

        harness
            .write_state([(
                super::state::account_key(sender.address),
                StateValue::Storage(slot(0x01)),
            )])
            .await;

        let result = harness
            .execute_specs(&[TransactionSpec::transfer(sender, recipient, 0, 0)])
            .await;

        assert!(result.is_err());
    });
}

#[test]
fn malformed_loaded_storage_value_returns_error() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "malformed-storage-value").await;
        let sender = harness.signer([55; 32]);
        let precompile = address(0x95);
        let slot_key = slot(0x96);
        let mut hasher = TestHasher::default();
        let storage_key = super::state::storage_key(&mut hasher, precompile, slot_key);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness
            .write_state([(storage_key, StateValue::Account(Account::default()))])
            .await;
        harness.insert_precompile(precompile, vec![PrecompileStep::ReadStorage(slot_key)]);

        let result = harness
            .execute_specs(&[TransactionSpec::call(
                sender,
                precompile,
                0,
                0,
                Bytes::new(),
            )])
            .await;

        assert!(result.is_err());
    });
}

#[test]
fn max_nonce_transaction_reverts_instead_of_panicking() {
    run_test(|context| async move {
        let harness = ProcessorHarness::new(context, "max-nonce-revert").await;
        let sender = harness.signer([51; 32]);
        let recipient = address(0x91);
        let sender_address = sender.address;

        harness
            .set_account(
                sender_address,
                Account {
                    balance: 10,
                    nonce: u64::MAX,
                },
            )
            .await;

        let run = harness
            .execute_specs(&[TransactionSpec::transfer(sender, recipient, 0, u64::MAX)])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::new());
        assert_eq!(run.account_change(sender_address), None);
        assert_eq!(run.account_change(recipient), None);
    });
}

#[test]
fn precompile_panic_reverts_instead_of_panicking() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "precompile-panic").await;
        let sender = harness.signer([52; 32]);
        let precompile = address(0x92);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.insert_precompile(precompile, vec![PrecompileStep::Panic]);

        let run = harness
            .execute_specs(&[TransactionSpec::call(
                sender,
                precompile,
                0,
                0,
                Bytes::new(),
            )])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::new());
    });
}

#[test]
fn declared_account_read_succeeds() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "declared-account-read").await;
        let sender = harness.signer([3; 32]);
        let precompile = address(0x33);
        let other = address(0x43);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness
            .set_account(
                other,
                Account {
                    balance: 7,
                    nonce: 3,
                },
            )
            .await;
        harness.insert_precompile(
            precompile,
            vec![
                PrecompileStep::AssertAccountBalance(other, 7),
                PrecompileStep::Return(Bytes::from_static(b"ok")),
            ],
        );

        let run = harness
            .execute_specs(&[
                TransactionSpec::call(sender, precompile, 0, 0, Bytes::new())
                    .with_access_list(vec![Access::Account(other, AccessMode::Read)]),
            ])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::from_static(b"ok"));
    });
}

#[test]
fn undeclared_storage_read_reverts() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "undeclared-storage-read").await;
        let sender = harness.signer([4; 32]);
        let precompile = address(0x34);
        let other = address(0x44);
        let other_slot = slot(0x54);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.set_storage(other, other_slot, slot(0x11)).await;
        harness.insert_precompile(
            precompile,
            vec![
                PrecompileStep::InspectStorage(other, other_slot),
                PrecompileStep::Return(Bytes::from_static(b"ok")),
            ],
        );

        let run = harness
            .execute_specs(&[
                TransactionSpec::call(sender.clone(), precompile, 0, 0, Bytes::new())
                    .with_access_list(Vec::new()),
            ])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::new());
        assert_eq!(
            run.account_change(sender.address),
            Some(Account {
                balance: 10,
                nonce: 1,
            })
        );
        assert_eq!(run.storage_change(other, other_slot), None);
    });
}

#[test]
fn read_only_storage_write_reverts() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "read-only-storage-write").await;
        let sender = harness.signer([5; 32]);
        let precompile = address(0x35);
        let owner_slot = slot(0x55);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness
            .set_storage(precompile, owner_slot, slot(0x01))
            .await;
        harness.insert_precompile(
            precompile,
            vec![
                PrecompileStep::WriteStorage(owner_slot, slot(0x02)),
                PrecompileStep::Return(Bytes::from_static(b"ok")),
            ],
        );

        let run = harness
            .execute_specs(&[
                TransactionSpec::call(sender.clone(), precompile, 0, 0, Bytes::new())
                    .with_access_list(vec![Access::Storage(
                        precompile,
                        owner_slot,
                        AccessMode::Read,
                    )]),
            ])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::new());
        assert_eq!(
            run.account_change(sender.address),
            Some(Account {
                balance: 10,
                nonce: 1,
            })
        );
        assert_eq!(run.storage_change(precompile, owner_slot), None);
    });
}

#[test]
fn precompile_can_read_any_declared_storage() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "declared-storage-read").await;
        let sender = harness.signer([6; 32]);
        let precompile = address(0x36);
        let other = address(0x46);
        let other_slot = slot(0x56);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.set_storage(other, other_slot, slot(0x12)).await;
        harness.insert_precompile(
            precompile,
            vec![
                PrecompileStep::AssertStorage(other, other_slot, slot(0x12)),
                PrecompileStep::Return(Bytes::from_static(b"ok")),
            ],
        );

        let run = harness
            .execute_specs(&[
                TransactionSpec::call(sender, precompile, 0, 0, Bytes::new())
                    .with_access_list(vec![Access::Storage(other, other_slot, AccessMode::Read)]),
            ])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::from_static(b"ok"));
    });
}

#[test]
fn precompile_cannot_write_other_account_storage() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "owner-scoped-storage-write").await;
        let sender = harness.signer([7; 32]);
        let precompile = address(0x37);
        let other = address(0x47);
        let shared_slot = slot(0x57);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness
            .set_storage(precompile, shared_slot, slot(0x01))
            .await;
        harness.set_storage(other, shared_slot, slot(0x02)).await;
        harness.insert_precompile(
            precompile,
            vec![
                PrecompileStep::AssertStorage(other, shared_slot, slot(0x02)),
                PrecompileStep::WriteStorage(shared_slot, slot(0x03)),
                PrecompileStep::Return(Bytes::from_static(b"ok")),
            ],
        );

        let run = harness
            .execute_specs(&[
                TransactionSpec::call(sender, precompile, 0, 0, Bytes::new()).with_access_list(
                    vec![
                        Access::Storage(precompile, shared_slot, AccessMode::Write),
                        Access::Storage(other, shared_slot, AccessMode::Read),
                    ],
                ),
            ])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::from_static(b"ok"));
        assert_eq!(
            run.storage_change(precompile, shared_slot),
            Some(slot(0x03))
        );
        assert_eq!(run.storage_change(other, shared_slot), None);
    });
}

#[test]
fn transfer_requires_declared_recipient_access() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "transfer-recipient-access").await;
        let sender = harness.signer([8; 32]);
        let precompile = address(0x38);
        let beneficiary = address(0x48);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.insert_precompile(
            precompile,
            vec![
                PrecompileStep::Transfer(beneficiary, 1),
                PrecompileStep::Return(Bytes::from_static(b"ok")),
            ],
        );

        let run = harness
            .execute_specs(&[
                TransactionSpec::call(sender.clone(), precompile, 1, 0, Bytes::new())
                    .with_access_list(Vec::new()),
            ])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::new());
        assert_eq!(
            run.account_change(sender.address),
            Some(Account {
                balance: 10,
                nonce: 1,
            })
        );
        assert_eq!(run.account_change(precompile), None);
        assert_eq!(run.account_change(beneficiary), None);
    });
}

#[test]
fn precompile_transfer_updates_balances() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "precompile-transfer-updates").await;
        let sender = harness.signer([9; 32]);
        let precompile = address(0x39);
        let beneficiary = address(0x49);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.insert_precompile(
            precompile,
            vec![
                PrecompileStep::Transfer(beneficiary, 3),
                PrecompileStep::Return(Bytes::from_static(b"ok")),
            ],
        );

        let run = harness
            .execute_specs(&[TransactionSpec::call(
                sender.clone(),
                precompile,
                4,
                0,
                Bytes::new(),
            )])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::from_static(b"ok"));
        assert_eq!(
            run.account_change(sender.address),
            Some(Account {
                balance: 6,
                nonce: 1,
            })
        );
        assert_eq!(
            run.account_change(precompile),
            Some(Account {
                balance: 1,
                nonce: 0,
            })
        );
        assert_eq!(
            run.account_change(beneficiary),
            Some(Account {
                balance: 3,
                nonce: 0,
            })
        );
    });
}

#[test]
fn precompile_transfer_underflow_reverts() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "precompile-transfer-underflow").await;
        let sender = harness.signer([10; 32]);
        let precompile = address(0x3A);
        let beneficiary = address(0x4A);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.insert_precompile(
            precompile,
            vec![
                PrecompileStep::Transfer(beneficiary, 1),
                PrecompileStep::Return(Bytes::from_static(b"ok")),
            ],
        );

        let run = harness
            .execute_specs(&[
                TransactionSpec::call(sender.clone(), precompile, 0, 0, Bytes::new())
                    .with_access_list(vec![Access::Account(beneficiary, AccessMode::Write)]),
            ])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::new());
        assert_eq!(
            run.account_change(sender.address),
            Some(Account {
                balance: 10,
                nonce: 1,
            })
        );
        assert_eq!(run.account_change(precompile), None);
        assert_eq!(run.account_change(beneficiary), None);
    });
}

#[test]
fn root_transfer_zero_value_is_noop() {
    run_test(|context| async move {
        let harness = ProcessorHarness::new(context, "root-zero-value-transfer").await;
        let sender = harness.signer([11; 32]);
        let recipient = address(0x4B);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;

        let run = harness
            .execute_specs(&[TransactionSpec::transfer(sender.clone(), recipient, 0, 0)])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::new());
        assert_eq!(
            run.account_change(sender.address),
            Some(Account {
                balance: 10,
                nonce: 1,
            })
        );
        assert_eq!(run.account_change(recipient), None);
    });
}

#[test]
fn root_self_transfer_keeps_balance() {
    run_test(|context| async move {
        let harness = ProcessorHarness::new(context, "root-self-transfer").await;
        let sender = harness.signer([12; 32]);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;

        let run = harness
            .execute_specs(&[TransactionSpec::transfer(
                sender.clone(),
                sender.address,
                10,
                0,
            )])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::new());
        assert_eq!(
            run.account_change(sender.address),
            Some(Account {
                balance: 10,
                nonce: 1,
            })
        );
    });
}

#[test]
fn precompile_zero_value_call_can_still_mutate_own_storage() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "zero-value-call-storage-write").await;
        let sender = harness.signer([12; 32]);
        let precompile = address(0x3C);
        let owner_slot = slot(0x5C);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.insert_precompile(
            precompile,
            vec![
                PrecompileStep::WriteStorage(owner_slot, slot(0x21)),
                PrecompileStep::Return(Bytes::from_static(b"ok")),
            ],
        );

        let run = harness
            .execute_specs(&[TransactionSpec::call(
                sender,
                precompile,
                0,
                0,
                Bytes::new(),
            )])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::from_static(b"ok"));
        assert_eq!(run.storage_change(precompile, owner_slot), Some(slot(0x21)));
    });
}

#[test]
fn child_success_merges_into_parent() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "child-success-merges").await;
        let sender = harness.signer([13; 32]);
        let precompile = address(0x3D);
        let owner_slot = slot(0x5D);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.insert_precompile(
            precompile,
            vec![
                PrecompileStep::WriteStorage(owner_slot, slot(0x30)),
                PrecompileStep::Return(Bytes::from_static(b"ok")),
            ],
        );

        let run = harness
            .execute_specs(&[TransactionSpec::call(
                sender.clone(),
                precompile,
                2,
                0,
                Bytes::new(),
            )])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::from_static(b"ok"));
        assert_eq!(
            run.account_change(sender.address),
            Some(Account {
                balance: 8,
                nonce: 1,
            })
        );
        assert_eq!(
            run.account_change(precompile),
            Some(Account {
                balance: 2,
                nonce: 0,
            })
        );
        assert_eq!(run.storage_change(precompile, owner_slot), Some(slot(0x30)));
    });
}

#[test]
fn child_revert_discards_child_diff() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "child-revert-discards").await;
        let sender = harness.signer([14; 32]);
        let precompile = address(0x3E);
        let owner_slot = slot(0x5E);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.insert_precompile(
            precompile,
            vec![
                PrecompileStep::WriteStorage(owner_slot, slot(0x31)),
                PrecompileStep::Revert(Bytes::from_static(b"stop")),
            ],
        );

        let run = harness
            .execute_specs(&[TransactionSpec::call(
                sender.clone(),
                precompile,
                2,
                0,
                Bytes::new(),
            )])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::from_static(b"stop"));
        assert_eq!(
            run.account_change(sender.address),
            Some(Account {
                balance: 10,
                nonce: 1,
            })
        );
        assert_eq!(run.account_change(precompile), None);
        assert_eq!(run.storage_change(precompile, owner_slot), None);
    });
}

#[test]
fn recursive_precompile_call_merges_nested_diff() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "recursive-call-merges").await;
        let sender = harness.signer([31; 32]);
        let parent = address(0x63);
        let child = address(0x64);
        let child_slot = slot(0x73);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.insert_precompile(
            child,
            vec![
                PrecompileStep::WriteStorage(child_slot, slot(0x33)),
                PrecompileStep::Return(Bytes::from_static(b"child")),
            ],
        );
        harness.insert_precompile(
            parent,
            vec![
                PrecompileStep::AssertCallReturns(
                    child,
                    3,
                    Bytes::from_static(b"nested"),
                    Bytes::from_static(b"child"),
                ),
                PrecompileStep::Return(Bytes::from_static(b"parent")),
            ],
        );

        let run = harness
            .execute_specs(&[TransactionSpec::call(
                sender.clone(),
                parent,
                5,
                0,
                Bytes::new(),
            )])
            .await
            .expect("processing should succeed");

        assert_receipt(
            &run,
            0,
            ReceiptStatus::Success,
            Bytes::from_static(b"parent"),
        );
        assert_eq!(
            run.account_change(sender.address),
            Some(Account {
                balance: 5,
                nonce: 1,
            })
        );
        assert_eq!(
            run.account_change(parent),
            Some(Account {
                balance: 2,
                nonce: 0,
            })
        );
        assert_eq!(
            run.account_change(child),
            Some(Account {
                balance: 3,
                nonce: 0,
            })
        );
        assert_eq!(run.storage_change(child, child_slot), Some(slot(0x33)));

        let access_list = run
            .built_access_list(0)
            .expect("successful transaction should return an access list");
        assert!(access_list.contains(&Access::Account(parent, AccessMode::Write)));
        assert!(access_list.contains(&Access::Account(child, AccessMode::Write)));
        assert!(access_list.contains(&Access::Storage(child, child_slot, AccessMode::Write)));
    });
}

#[test]
fn recursive_precompile_call_can_handle_child_revert() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "recursive-call-handled-revert").await;
        let sender = harness.signer([32; 32]);
        let parent = address(0x65);
        let child = address(0x66);
        let parent_slot = slot(0x74);
        let child_slot = slot(0x75);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.insert_precompile(
            child,
            vec![
                PrecompileStep::WriteStorage(child_slot, slot(0x44)),
                PrecompileStep::Revert(Bytes::from_static(b"child-revert")),
            ],
        );
        harness.insert_precompile(
            parent,
            vec![
                PrecompileStep::AssertCallReverts(
                    child,
                    0,
                    Bytes::new(),
                    Bytes::from_static(b"child-revert"),
                ),
                PrecompileStep::WriteStorage(parent_slot, slot(0x45)),
                PrecompileStep::Return(Bytes::from_static(b"handled")),
            ],
        );

        let run = harness
            .execute_specs(&[TransactionSpec::call(
                sender.clone(),
                parent,
                0,
                0,
                Bytes::new(),
            )])
            .await
            .expect("processing should succeed");

        assert_receipt(
            &run,
            0,
            ReceiptStatus::Success,
            Bytes::from_static(b"handled"),
        );
        assert_eq!(run.storage_change(parent, parent_slot), Some(slot(0x45)));
        assert_eq!(run.storage_change(child, child_slot), None);
        assert_eq!(run.account_change(child), None);
    });
}

#[test]
fn recursive_precompile_call_bubbles_child_revert() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "recursive-call-bubbles-revert").await;
        let sender = harness.signer([33; 32]);
        let parent = address(0x67);
        let child = address(0x68);
        let child_slot = slot(0x76);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.insert_precompile(
            child,
            vec![
                PrecompileStep::WriteStorage(child_slot, slot(0x46)),
                PrecompileStep::Revert(Bytes::from_static(b"bubble")),
            ],
        );
        harness.insert_precompile(
            parent,
            vec![
                PrecompileStep::Call(child, 0, Bytes::new()),
                PrecompileStep::Return(Bytes::from_static(b"unreachable")),
            ],
        );

        let run = harness
            .execute_specs(&[TransactionSpec::call(
                sender.clone(),
                parent,
                0,
                0,
                Bytes::new(),
            )])
            .await
            .expect("processing should succeed");

        assert_receipt(
            &run,
            0,
            ReceiptStatus::Revert,
            Bytes::from_static(b"bubble"),
        );
        assert_eq!(
            run.account_change(sender.address),
            Some(Account {
                balance: 10,
                nonce: 1,
            })
        );
        assert_eq!(run.account_change(parent), None);
        assert_eq!(run.account_change(child), None);
        assert_eq!(run.storage_change(child, child_slot), None);
    });
}

#[test]
fn recursive_precompile_call_halts_at_max_depth() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "recursive-call-depth-limit").await;
        let sender = harness.signer([34; 32]);
        let recursive = address(0x69);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.insert_precompile(
            recursive,
            vec![PrecompileStep::Call(recursive, 0, Bytes::new())],
        );

        let run = harness
            .execute_specs(&[TransactionSpec::call(
                sender.clone(),
                recursive,
                0,
                0,
                Bytes::new(),
            )])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::new());
        assert_eq!(
            run.account_change(sender.address),
            Some(Account {
                balance: 10,
                nonce: 1,
            })
        );
        assert_eq!(run.account_change(recursive), None);
        assert_eq!(
            run.output
                .access_lists
                .expect("access-list builder should be enabled"),
            vec![None],
        );
    });
}

#[rstest]
#[case("empty", [15; 32], 0x60, Bytes::new())]
#[case(
    "ascii",
    [16; 32],
    0x61,
    Bytes::from_static(b"revert")
)]
#[case("binary", [17; 32], 0x62, Bytes::from(vec![0, 1, 2, 3]))]
fn revert_payload_is_preserved(
    #[case] suffix: &'static str,
    #[case] seed: [u8; 32],
    #[case] precompile_byte: u8,
    #[case] payload: Bytes,
) {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, suffix).await;
        let sender = harness.signer(seed);
        let precompile = address(precompile_byte);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.insert_precompile(precompile, vec![PrecompileStep::Revert(payload.clone())]);

        let run = harness
            .execute_specs(&[TransactionSpec::call(
                sender,
                precompile,
                0,
                0,
                Bytes::new(),
            )])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Revert, payload);
    });
}

#[test]
fn restored_value_is_omitted_from_changeset() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "restored-storage-omitted").await;
        let sender = harness.signer([19; 32]);
        let precompile = address(0x3F);
        let owner_slot = slot(0x5F);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness
            .set_storage(precompile, owner_slot, slot(0x40))
            .await;
        harness.insert_precompile(
            precompile,
            vec![
                PrecompileStep::WriteStorage(owner_slot, slot(0x41)),
                PrecompileStep::WriteStorage(owner_slot, slot(0x40)),
                PrecompileStep::Return(Bytes::from_static(b"ok")),
            ],
        );

        let run = harness
            .execute_specs(&[
                TransactionSpec::call(sender.clone(), precompile, 0, 0, Bytes::new())
                    .with_access_list(vec![Access::Storage(
                        precompile,
                        owner_slot,
                        AccessMode::Write,
                    )]),
            ])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::from_static(b"ok"));
        assert_eq!(run.storage_change(precompile, owner_slot), None);
        assert_eq!(
            run.account_change(sender.address),
            Some(Account {
                balance: 10,
                nonce: 1,
            })
        );
    });
}

#[test]
fn restored_account_balance_is_omitted_from_changeset() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "restored-account-omitted").await;
        let sender = harness.signer([20; 32]);
        let first = address(0x40);
        let second = address(0x50);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.insert_precompile(
            first,
            vec![
                PrecompileStep::Transfer(second, 5),
                PrecompileStep::Return(Bytes::from_static(b"ok")),
            ],
        );
        harness.insert_precompile(
            second,
            vec![
                PrecompileStep::Transfer(sender.address, 5),
                PrecompileStep::Return(Bytes::from_static(b"ok")),
            ],
        );

        let run = harness
            .execute_specs(&[
                TransactionSpec::call(sender.clone(), first, 5, 0, Bytes::new()),
                TransactionSpec::call(sender.clone(), second, 0, 1, Bytes::new()),
            ])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::from_static(b"ok"));
        assert_receipt(&run, 1, ReceiptStatus::Success, Bytes::from_static(b"ok"));
        assert_eq!(
            run.account_change(sender.address),
            Some(Account {
                balance: 10,
                nonce: 2,
            })
        );
        assert_eq!(run.account_change(first), None);
        assert_eq!(run.account_change(second), None);
    });
}

#[test]
fn later_transaction_sees_prior_transaction_state() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "later-transaction-sees-prior").await;
        let sender = harness.signer([21; 32]);
        let precompile = address(0x41);
        let owner_slot = slot(0x61);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.insert_precompile(
            precompile,
            vec![
                PrecompileStep::WriteStorage(owner_slot, slot(0x42)),
                PrecompileStep::Return(Bytes::from_static(b"written")),
            ],
        );

        let reader = address(0x42);
        harness.insert_precompile(
            reader,
            vec![
                PrecompileStep::AssertStorage(precompile, owner_slot, slot(0x42)),
                PrecompileStep::Return(Bytes::from_static(b"read")),
            ],
        );

        let run = harness
            .execute_specs(&[
                TransactionSpec::call(sender.clone(), precompile, 0, 0, Bytes::new()),
                TransactionSpec::call(sender.clone(), reader, 0, 1, Bytes::new()),
            ])
            .await
            .expect("processing should succeed");

        assert_receipt(
            &run,
            0,
            ReceiptStatus::Success,
            Bytes::from_static(b"written"),
        );
        assert_receipt(&run, 1, ReceiptStatus::Success, Bytes::from_static(b"read"));
        assert_eq!(run.storage_change(precompile, owner_slot), Some(slot(0x42)));
    });
}

#[test]
fn reverted_transaction_does_not_affect_later_transactions() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "revert-does-not-affect-later").await;
        let sender = harness.signer([22; 32]);
        let writer = address(0x43);
        let reader = address(0x44);
        let owner_slot = slot(0x62);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.insert_precompile(
            writer,
            vec![
                PrecompileStep::WriteStorage(owner_slot, slot(0x51)),
                PrecompileStep::Revert(Bytes::from_static(b"nope")),
            ],
        );
        harness.insert_precompile(
            reader,
            vec![
                PrecompileStep::AssertStorage(writer, owner_slot, Slot::default()),
                PrecompileStep::Return(Bytes::from_static(b"clear")),
            ],
        );

        let run = harness
            .execute_specs(&[
                TransactionSpec::call(sender.clone(), writer, 0, 0, Bytes::new()),
                TransactionSpec::call(sender.clone(), reader, 0, 1, Bytes::new()),
            ])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::from_static(b"nope"));
        assert_receipt(
            &run,
            1,
            ReceiptStatus::Success,
            Bytes::from_static(b"clear"),
        );
        assert_eq!(run.storage_change(writer, owner_slot), None);
        assert_eq!(
            run.account_change(sender.address),
            Some(Account {
                balance: 10,
                nonce: 2,
            })
        );
    });
}

#[test]
fn nonce_advances_across_slice() {
    run_test(|context| async move {
        let harness = ProcessorHarness::new(context, "nonce-advances-across-slice").await;
        let sender = harness.signer([23; 32]);
        let first = address(0x45);
        let second = address(0x46);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;

        let run = harness
            .execute_specs(&[
                TransactionSpec::transfer(sender.clone(), first, 1, 0),
                TransactionSpec::transfer(sender.clone(), second, 2, 1),
            ])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::new());
        assert_receipt(&run, 1, ReceiptStatus::Success, Bytes::new());
        assert_eq!(
            run.account_change(sender.address),
            Some(Account {
                balance: 7,
                nonce: 2,
            })
        );
        assert_eq!(
            run.account_change(first),
            Some(Account {
                balance: 1,
                nonce: 0,
            })
        );
        assert_eq!(
            run.account_change(second),
            Some(Account {
                balance: 2,
                nonce: 0,
            })
        );
    });
}

#[test]
fn reverted_tx_still_consumes_nonce_for_next_tx() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "revert-consumes-next-nonce").await;
        let sender = harness.signer([24; 32]);
        let precompile = address(0x47);
        let recipient = address(0x57);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.insert_precompile(
            precompile,
            vec![PrecompileStep::Revert(Bytes::from_static(b"nope"))],
        );

        let run = harness
            .execute_specs(&[
                TransactionSpec::call(sender.clone(), precompile, 0, 0, Bytes::new()),
                TransactionSpec::transfer(sender.clone(), recipient, 1, 1),
            ])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::from_static(b"nope"));
        assert_receipt(&run, 1, ReceiptStatus::Success, Bytes::new());
        assert_eq!(
            run.account_change(sender.address),
            Some(Account {
                balance: 9,
                nonce: 2,
            })
        );
        assert_eq!(
            run.account_change(recipient),
            Some(Account {
                balance: 1,
                nonce: 0,
            })
        );
    });
}

#[test]
fn bad_nonce_returns_revert_receipt_and_continues() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "bad-nonce-continues").await;
        let sender = harness.signer([25; 32]);
        let panic_precompile = address(0x48);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.insert_precompile(panic_precompile, vec![PrecompileStep::Return(Bytes::new())]);

        let run = harness
            .execute_specs(&[
                TransactionSpec::transfer(sender.clone(), address(0x58), 1, 0),
                TransactionSpec::transfer(sender.clone(), address(0x59), 1, 0),
                TransactionSpec::call(sender, panic_precompile, 0, 1, Bytes::new()),
            ])
            .await
            .expect("processing should succeed");

        assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::new());
        assert_receipt(&run, 1, ReceiptStatus::Revert, Bytes::new());
        assert_receipt(&run, 2, ReceiptStatus::Success, Bytes::new());
    });
}

#[test]
fn filter_invalid_drops_static_invalid_transactions() {
    run_test(|context| async move {
        let harness = ProcessorHarness::new(context, "filter-invalid-transactions").await;
        let sender = harness.signer([53; 32]);
        let recipient = address(0x93);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;

        let transactions = harness
            .transactions(&[
                TransactionSpec::transfer(sender.clone(), recipient, 1, 1),
                TransactionSpec::transfer(sender.clone(), recipient, 1, 0),
            ])
            .await
            .expect("transaction building should succeed");

        let filtered = harness
            .filter_invalid(&transactions)
            .await
            .expect("filtering should succeed");

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].value().nonce, 0);
    });
}

#[test]
fn all_statically_valid_rejects_invalid_block_transaction() {
    run_test(|context| async move {
        let harness = ProcessorHarness::new(context, "all-statically-valid").await;
        let sender = harness.signer([54; 32]);
        let recipient = address(0x94);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;

        let transactions = harness
            .transactions(&[
                TransactionSpec::transfer(sender.clone(), recipient, 1, 0),
                TransactionSpec::transfer(sender.clone(), recipient, 1, 0),
            ])
            .await
            .expect("transaction building should succeed");

        let is_valid = harness
            .all_statically_valid(&transactions)
            .await
            .expect("validation should succeed");

        assert!(!is_valid);
    });
}

#[test]
fn successful_tx_returns_built_access_list() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "successful-built-access-list").await;
        let sender = harness.signer([26; 32]);
        let precompile = address(0x49);
        let other = address(0x5A);
        let other_slot = slot(0x6A);
        let owner_slot = slot(0x6B);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness
            .set_account(
                other,
                Account {
                    balance: 7,
                    nonce: 0,
                },
            )
            .await;
        harness.set_storage(other, other_slot, slot(0x22)).await;
        harness
            .set_storage(precompile, owner_slot, slot(0x23))
            .await;
        harness.insert_precompile(
            precompile,
            vec![
                PrecompileStep::AssertAccountBalance(other, 7),
                PrecompileStep::AssertStorage(other, other_slot, slot(0x22)),
                PrecompileStep::AssertReadStorage(owner_slot, slot(0x23)),
                PrecompileStep::WriteStorage(owner_slot, slot(0x24)),
                PrecompileStep::Return(Bytes::from_static(b"ok")),
            ],
        );

        let run = harness
            .execute_specs(&[TransactionSpec::call(
                sender.clone(),
                precompile,
                0,
                0,
                Bytes::new(),
            )])
            .await
            .expect("processing should succeed");

        let access_list = run
            .built_access_list(0)
            .expect("successful transaction should return an access list");
        assert_eq!(run.transaction_access_list(0), access_list);
        assert_eq!(access_list.len(), 5);
        assert!(access_list.contains(&Access::Account(sender.address, AccessMode::Write)));
        assert!(access_list.contains(&Access::Account(precompile, AccessMode::Read)));
        assert!(access_list.contains(&Access::Account(other, AccessMode::Read)));
        assert!(access_list.contains(&Access::Storage(other, other_slot, AccessMode::Read)));
        assert!(access_list.contains(&Access::Storage(precompile, owner_slot, AccessMode::Write)));
    });
}

#[test]
fn reverted_tx_returns_none_access_list() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "revert-none-access-list").await;
        let sender = harness.signer([27; 32]);
        let precompile = address(0x4A);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.insert_precompile(
            precompile,
            vec![PrecompileStep::Revert(Bytes::from_static(b"stop"))],
        );

        let run = harness
            .execute_specs(&[TransactionSpec::call(
                sender,
                precompile,
                0,
                0,
                Bytes::new(),
            )])
            .await
            .expect("processing should succeed");

        assert_eq!(
            run.output
                .access_lists
                .expect("access-list builder should be enabled"),
            vec![None],
        );
    });
}

#[rstest]
#[case(
    "builder-upgrades-read-write",
    [28; 32],
    0x4B,
    BuilderCase::UpgradesReadToWrite
)]
#[case(
    "builder-deduplicates",
    [29; 32],
    0x4C,
    BuilderCase::DeduplicatesRepeatedAccesses
)]
#[case(
    "builder-cross-account-reads",
    [30; 32],
    0x4D,
    BuilderCase::RecordsCrossAccountReads
)]
fn builder_access_patterns(
    #[case] suffix: &'static str,
    #[case] seed: [u8; 32],
    #[case] precompile_byte: u8,
    #[case] case: BuilderCase,
) {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, suffix).await;
        let sender = harness.signer(seed);
        let precompile = address(precompile_byte);
        let other = address(0x5C);
        let other_slot = slot(0x6D);
        let owner_slot = slot(0x6E);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;

        let (program, expected_accesses, expected_len) = match case {
            BuilderCase::UpgradesReadToWrite => (
                vec![
                    PrecompileStep::ReadStorage(owner_slot),
                    PrecompileStep::WriteStorage(owner_slot, slot(0x30)),
                    PrecompileStep::Return(Bytes::from_static(b"ok")),
                ],
                vec![
                    Access::Account(sender.address, AccessMode::Write),
                    Access::Account(precompile, AccessMode::Read),
                    Access::Storage(precompile, owner_slot, AccessMode::Write),
                ],
                3,
            ),
            BuilderCase::DeduplicatesRepeatedAccesses => (
                vec![
                    PrecompileStep::InspectAccount(other),
                    PrecompileStep::InspectAccount(other),
                    PrecompileStep::InspectStorage(other, other_slot),
                    PrecompileStep::InspectStorage(other, other_slot),
                    PrecompileStep::ReadStorage(owner_slot),
                    PrecompileStep::ReadStorage(owner_slot),
                    PrecompileStep::WriteStorage(owner_slot, slot(0x31)),
                    PrecompileStep::WriteStorage(owner_slot, slot(0x31)),
                    PrecompileStep::Return(Bytes::from_static(b"ok")),
                ],
                vec![
                    Access::Account(sender.address, AccessMode::Write),
                    Access::Account(precompile, AccessMode::Read),
                    Access::Account(other, AccessMode::Read),
                    Access::Storage(other, other_slot, AccessMode::Read),
                    Access::Storage(precompile, owner_slot, AccessMode::Write),
                ],
                5,
            ),
            BuilderCase::RecordsCrossAccountReads => (
                vec![
                    PrecompileStep::InspectAccount(other),
                    PrecompileStep::InspectStorage(other, other_slot),
                    PrecompileStep::Return(Bytes::from_static(b"ok")),
                ],
                vec![
                    Access::Account(sender.address, AccessMode::Write),
                    Access::Account(precompile, AccessMode::Read),
                    Access::Account(other, AccessMode::Read),
                    Access::Storage(other, other_slot, AccessMode::Read),
                ],
                4,
            ),
        };

        harness.insert_precompile(precompile, program);

        let run = harness
            .execute_specs(&[TransactionSpec::call(
                sender.clone(),
                precompile,
                0,
                0,
                Bytes::new(),
            )])
            .await
            .expect("processing should succeed");

        let access_list = run
            .built_access_list(0)
            .expect("successful transaction should return an access list");
        assert_eq!(access_list.len(), expected_len);
        for access in expected_accesses {
            assert!(access_list.contains(&access));
        }

        if matches!(case, BuilderCase::UpgradesReadToWrite) {
            assert!(!access_list.contains(&Access::Storage(
                precompile,
                owner_slot,
                AccessMode::Read,
            )));
        }
    });
}

#[test]
fn parallel_execution_matches_sequential_output() {
    run_test(|context| async move {
        let suffix = "parallel-matches-sequential";
        let mut sequential_harness = ProcessorHarness::new(context.clone(), suffix).await;
        let mut parallel_harness = sequential_harness.clone();

        let sender_a = sequential_harness.signer([31; 32]);
        let sender_b = sequential_harness.signer([32; 32]);
        let sender_c = sequential_harness.signer([33; 32]);
        let precompile_x = address(0x60);
        let precompile_y = address(0x61);
        let slot_x = slot(0x71);
        let slot_y = slot(0x72);

        for harness in [&sequential_harness, &parallel_harness] {
            harness
                .set_account(
                    sender_a.address,
                    Account {
                        balance: 10,
                        nonce: 0,
                    },
                )
                .await;
            harness
                .set_account(
                    sender_b.address,
                    Account {
                        balance: 10,
                        nonce: 0,
                    },
                )
                .await;
            harness
                .set_account(
                    sender_c.address,
                    Account {
                        balance: 10,
                        nonce: 0,
                    },
                )
                .await;
        }

        let program_x = vec![
            PrecompileStep::ReadStorage(slot_x),
            PrecompileStep::WriteStorage(slot_x, slot(0x81)),
            PrecompileStep::Return(Bytes::from_static(b"x")),
        ];
        let program_y = vec![
            PrecompileStep::ReadStorage(slot_y),
            PrecompileStep::WriteStorage(slot_y, slot(0x82)),
            PrecompileStep::Return(Bytes::from_static(b"y")),
        ];

        sequential_harness.insert_precompile(precompile_x, program_x.clone());
        sequential_harness.insert_precompile(precompile_y, program_y.clone());
        parallel_harness.insert_precompile(precompile_x, program_x);
        parallel_harness.insert_precompile(precompile_y, program_y);

        let specs = vec![
            TransactionSpec::call(sender_a, precompile_x, 0, 0, Bytes::new()),
            TransactionSpec::call(sender_b, precompile_x, 0, 0, Bytes::new()),
            TransactionSpec::call(sender_c, precompile_y, 0, 0, Bytes::new()),
        ];

        let sequential = sequential_harness
            .execute_specs(&specs)
            .await
            .expect("sequential processing should succeed");
        let parallel = parallel_harness
            .execute_specs_with_strategy(&specs, &parallel_strategy())
            .await
            .expect("parallel processing should succeed");

        assert_eq!(parallel.output, sequential.output);
    });
}

#[test]
fn parallel_execution_reports_receipts_in_transaction_order() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "parallel-receipt-order").await;
        let sender_a = harness.signer([34; 32]);
        let sender_b = harness.signer([35; 32]);
        let sender_c = harness.signer([36; 32]);
        let precompile_x = address(0x62);
        let precompile_y = address(0x63);
        let slot_x = slot(0x73);
        let slot_y = slot(0x74);

        harness
            .set_account(
                sender_a.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness
            .set_account(
                sender_b.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness
            .set_account(
                sender_c.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.insert_precompile(
            precompile_x,
            vec![
                PrecompileStep::WriteStorage(slot_x, slot(0x91)),
                PrecompileStep::Return(Bytes::from_static(b"first")),
            ],
        );
        harness.insert_precompile(
            precompile_y,
            vec![
                PrecompileStep::WriteStorage(slot_y, slot(0x92)),
                PrecompileStep::Return(Bytes::from_static(b"second")),
            ],
        );

        let run = harness
            .execute_specs_with_strategy(
                &[
                    TransactionSpec::call(sender_a, precompile_x, 0, 0, Bytes::new()),
                    TransactionSpec::call(sender_b, precompile_x, 0, 0, Bytes::new()),
                    TransactionSpec::call(sender_c, precompile_y, 0, 0, Bytes::new()),
                ],
                &parallel_strategy(),
            )
            .await
            .expect("parallel processing should succeed");

        for (index, transaction) in run.transactions.iter().enumerate() {
            assert_eq!(
                run.output.receipts[index].transaction_hash,
                *transaction.message_digest(),
            );
        }

        assert_eq!(
            run.output.receipts[0].return_data,
            Bytes::from_static(b"first"),
        );
        assert_eq!(
            run.output.receipts[1].return_data,
            Bytes::from_static(b"first"),
        );
        assert_eq!(
            run.output.receipts[2].return_data,
            Bytes::from_static(b"second"),
        );
    });
}

#[test]
fn nested_call_to_undeclared_account_reverts() {
    run_test(|context| async move {
        let mut harness = ProcessorHarness::new(context, "undeclared-nested-account").await;
        let sender = harness.signer([80; 32]);
        let parent = address(0xA0);
        let child = address(0xA1);
        let child_slot = slot(0xB0);

        harness
            .set_account(
                sender.address,
                Account {
                    balance: 10,
                    nonce: 0,
                },
            )
            .await;
        harness.insert_precompile(
            child,
            vec![
                PrecompileStep::WriteStorage(child_slot, slot(0x01)),
                PrecompileStep::Return(Bytes::new()),
            ],
        );
        harness.insert_precompile(parent, vec![PrecompileStep::Call(child, 0, Bytes::new())]);

        // Deliberately omit child's account from the access list. Only declare
        // the child's storage so the call body would succeed *if* the account
        // check were missing.
        let run = harness
            .execute_specs(&[
                TransactionSpec::call(sender.clone(), parent, 0, 0, Bytes::new())
                    .with_access_list(vec![Access::Storage(child, child_slot, AccessMode::Write)]),
            ])
            .await
            .expect("processing should succeed");

        // The nested call targets an undeclared account, so the transaction
        // must revert.
        assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::new());
    });
}
