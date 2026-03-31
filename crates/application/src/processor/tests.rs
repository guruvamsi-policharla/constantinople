//! Focused processor tests for BAL proposal and verification.

use super::{
    Precompiles,
    executor::{Processor, ProposalOutput, VerificationError},
    frame::{Frame, FrameError},
    keys::{account_key, storage_key},
    state::{DiscoveryState, State},
};
use bytes::Bytes;
use commonware_codec::{DecodeExt, FixedSize};
use commonware_cryptography::{Signer, blake3, ed25519};
use commonware_parallel::Sequential;
use constantinople_primitives::{
    Access, AccessMode, Account, Address, ReceiptStatus, Slot, StateValue, Transaction,
};
use std::{
    collections::HashMap,
    marker::PhantomData,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

const NAMESPACE: &[u8] = b"processor-test";

type TestHasher = blake3::Blake3;
type TestTransaction =
    constantinople_primitives::VerifiedTransaction<ed25519::PublicKey, TestHasher>;

#[derive(Debug, Clone)]
enum Program {
    WriteStorage {
        slot: Slot,
        value: Slot,
        return_data: Bytes,
    },
    CountAndReturn {
        counter: Arc<AtomicUsize>,
        return_data: Bytes,
    },
    RevertAfterRead {
        slot: Slot,
        payload: Bytes,
    },
}

#[derive(Debug, Clone, Default)]
struct TestPrecompiles {
    programs: HashMap<Address, Program>,
}

impl TestPrecompiles {
    fn insert(&mut self, address: Address, program: Program) {
        self.programs.insert(address, program);
    }
}

impl Precompiles for TestPrecompiles {
    fn is_precompile(&self, address: Address) -> bool {
        self.programs.contains_key(&address)
    }

    fn execute<S, R>(
        &self,
        address: Address,
        frame: &mut Frame<'_, R>,
        _processor: &Processor<'_, S, Self>,
    ) -> Result<Bytes, FrameError>
    where
        S: commonware_parallel::Strategy,
        R: super::state::StateReader,
    {
        match self.programs.get(&address).expect("precompile must exist") {
            Program::WriteStorage {
                slot,
                value,
                return_data,
            } => {
                let _ = frame.read_storage(*slot)?;
                frame.write_storage(*slot, *value)?;
                Ok(return_data.clone())
            }
            Program::CountAndReturn {
                counter,
                return_data,
            } => {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(return_data.clone())
            }
            Program::RevertAfterRead { slot, payload } => {
                let _ = frame.read_storage(*slot)?;
                Err(FrameError::Revert(payload.clone()))
            }
        }
    }
}

fn address(byte: u8) -> Address {
    Address::decode(&[byte; Address::SIZE][..]).expect("address bytes should decode")
}

fn slot(byte: u8) -> Slot {
    Slot::from([byte; Slot::SIZE])
}

fn signer(seed: u64) -> ed25519::PrivateKey {
    ed25519::PrivateKey::from_seed(seed)
}

fn sign_transaction(key: &ed25519::PrivateKey, to: Address, nonce: u64) -> TestTransaction {
    Transaction {
        sender: key.public_key(),
        to,
        input: Bytes::new(),
        value: 0,
        nonce,
        _digest: PhantomData,
    }
    .seal_and_sign_verified(key, NAMESPACE, &mut TestHasher::default())
}

fn base_state(
    sender: Address,
    precompile: Address,
    storage_slot: Slot,
    storage_value: Slot,
) -> State {
    let mut accounts = HashMap::new();
    accounts.insert(
        sender,
        Account {
            balance: 1,
            nonce: 0,
        },
    );
    accounts.insert(precompile, Account::default());

    let mut storage = HashMap::new();
    storage.insert((precompile, storage_slot), storage_value);

    State::new(accounts, storage)
}

fn propose_block_access_list(
    precompiles: &TestPrecompiles,
    initial_state: &State,
    transactions: Vec<TestTransaction>,
) -> (ProposalOutput<blake3::Digest>, Vec<TestTransaction>) {
    let processor = Processor::new(&Sequential, precompiles);
    let mut discovery_state = DiscoveryState::new(initial_state.clone());
    let validation = processor.validate(&discovery_state, transactions);
    assert!(validation.invalid.is_empty(), "transaction should validate");
    let valid = validation.valid;
    let output = processor.propose(&mut discovery_state, &valid);
    (output, valid)
}

#[test]
fn propose_builds_block_access_list_and_final_writes() {
    let key = signer(7);
    let sender = Address::from_public_key(&mut TestHasher::default(), &key.public_key());
    let precompile = address(0x44);
    let storage_slot = slot(0x11);
    let new_value = slot(0x99);

    let mut precompiles = TestPrecompiles::default();
    precompiles.insert(
        precompile,
        Program::WriteStorage {
            slot: storage_slot,
            value: new_value,
            return_data: Bytes::from_static(b"ok"),
        },
    );

    let initial_state = base_state(sender, precompile, storage_slot, slot(0x01));
    let transaction = sign_transaction(&key, precompile, 0);
    let (output, _) = propose_block_access_list(&precompiles, &initial_state, vec![transaction]);

    assert_eq!(output.receipts.len(), 1);
    assert_eq!(output.receipts[0].status, ReceiptStatus::Success);
    assert_eq!(output.access_list.tx_offsets, vec![0, 3]);
    assert!(
        output
            .access_list
            .tx_accesses
            .contains(&Access::Account(sender, AccessMode::Write))
    );
    assert!(
        output
            .access_list
            .tx_accesses
            .contains(&Access::Account(precompile, AccessMode::Read))
    );
    assert!(output.access_list.tx_accesses.contains(&Access::Storage(
        precompile,
        storage_slot,
        AccessMode::Write
    )));
    assert_eq!(output.access_list.account_writes.len(), 1);
    assert_eq!(output.access_list.account_writes[0].address, sender);
    assert_eq!(output.access_list.account_writes[0].account.nonce, 1);
    assert_eq!(output.access_list.storage_writes.len(), 1);
    assert_eq!(output.access_list.storage_writes[0].address, precompile);
    assert_eq!(output.access_list.storage_writes[0].slot, storage_slot);
    assert_eq!(output.access_list.storage_writes[0].value, new_value);

    let mut hasher = TestHasher::default();
    let storage_key = storage_key(&mut hasher, precompile, storage_slot);
    assert_eq!(
        output.changeset.get(&account_key(sender)),
        Some(&StateValue::Account(Account {
            balance: 1,
            nonce: 1,
        }))
    );
    assert_eq!(
        output.changeset.get(&storage_key),
        Some(&StateValue::Storage(new_value))
    );
}

#[test]
fn verify_accepts_proposed_block_access_list() {
    let key = signer(8);
    let sender = Address::from_public_key(&mut TestHasher::default(), &key.public_key());
    let precompile = address(0x45);
    let storage_slot = slot(0x12);
    let new_value = slot(0xaa);

    let mut precompiles = TestPrecompiles::default();
    precompiles.insert(
        precompile,
        Program::WriteStorage {
            slot: storage_slot,
            value: new_value,
            return_data: Bytes::from_static(b"ok"),
        },
    );

    let initial_state = base_state(sender, precompile, storage_slot, slot(0x02));
    let transaction = sign_transaction(&key, precompile, 0);
    let (discovered, valid) =
        propose_block_access_list(&precompiles, &initial_state, vec![transaction]);

    let processor = Processor::new(&Sequential, &precompiles);
    let output = processor
        .verify(initial_state, &valid, &discovered.access_list)
        .expect("BAL should verify");

    assert_eq!(output.receipts, discovered.receipts);
    assert_eq!(output.changeset, discovered.changeset);
}

#[test]
fn verify_rejects_missing_declared_access() {
    let key = signer(9);
    let sender = Address::from_public_key(&mut TestHasher::default(), &key.public_key());
    let precompile = address(0x46);
    let storage_slot = slot(0x13);

    let mut precompiles = TestPrecompiles::default();
    precompiles.insert(
        precompile,
        Program::WriteStorage {
            slot: storage_slot,
            value: slot(0xbb),
            return_data: Bytes::from_static(b"ok"),
        },
    );

    let initial_state = base_state(sender, precompile, storage_slot, slot(0x03));
    let transaction = sign_transaction(&key, precompile, 0);
    let (mut discovered, valid) =
        propose_block_access_list(&precompiles, &initial_state, vec![transaction]);
    discovered
        .access_list
        .tx_accesses
        .retain(|access| !matches!(access, Access::Storage(_, _, _)));
    discovered.access_list.tx_offsets = vec![0, 2];

    let processor = Processor::new(&Sequential, &precompiles);
    let err = processor
        .verify(initial_state, &valid, &discovered.access_list)
        .expect_err("underdeclared BAL must be rejected");
    assert_eq!(
        err,
        VerificationError::AccessListMismatch {
            transaction_index: 0
        }
    );
}

#[test]
fn verify_rejects_unused_declared_access() {
    let key = signer(10);
    let sender = Address::from_public_key(&mut TestHasher::default(), &key.public_key());
    let precompile = address(0x47);
    let storage_slot = slot(0x14);
    let extra_account = address(0x99);

    let mut precompiles = TestPrecompiles::default();
    precompiles.insert(
        precompile,
        Program::WriteStorage {
            slot: storage_slot,
            value: slot(0xcc),
            return_data: Bytes::from_static(b"ok"),
        },
    );

    let initial_state = base_state(sender, precompile, storage_slot, slot(0x04));
    let transaction = sign_transaction(&key, precompile, 0);
    let (mut discovered, valid) =
        propose_block_access_list(&precompiles, &initial_state, vec![transaction]);
    discovered
        .access_list
        .tx_accesses
        .push(Access::Account(extra_account, AccessMode::Read));
    discovered.access_list.tx_offsets = vec![0, 4];

    let processor = Processor::new(&Sequential, &precompiles);
    let err = processor
        .verify(initial_state, &valid, &discovered.access_list)
        .expect_err("overdeclared BAL must be rejected");
    assert_eq!(
        err,
        VerificationError::AccessListMismatch {
            transaction_index: 0
        }
    );
}

#[test]
fn verify_rejects_redundant_declared_access() {
    let key = signer(20);
    let sender = Address::from_public_key(&mut TestHasher::default(), &key.public_key());
    let precompile = address(0x4a);
    let storage_slot = slot(0x17);

    let mut precompiles = TestPrecompiles::default();
    precompiles.insert(
        precompile,
        Program::WriteStorage {
            slot: storage_slot,
            value: slot(0xde),
            return_data: Bytes::from_static(b"ok"),
        },
    );

    let initial_state = base_state(sender, precompile, storage_slot, slot(0x07));
    let transaction = sign_transaction(&key, precompile, 0);
    let (mut discovered, valid) =
        propose_block_access_list(&precompiles, &initial_state, vec![transaction]);
    discovered
        .access_list
        .tx_accesses
        .push(Access::Account(sender, AccessMode::Write));
    discovered.access_list.tx_offsets = vec![0, 4];

    let processor = Processor::new(&Sequential, &precompiles);
    let err = processor
        .verify(initial_state, &valid, &discovered.access_list)
        .expect_err("duplicate declared access must be rejected");
    assert_eq!(
        err,
        VerificationError::AccessListMismatch {
            transaction_index: 0
        }
    );
}

#[test]
fn verify_stops_after_first_access_mismatch() {
    let key_a = signer(30);
    let sender_a = Address::from_public_key(&mut TestHasher::default(), &key_a.public_key());
    let key_b = signer(31);
    let sender_b = Address::from_public_key(&mut TestHasher::default(), &key_b.public_key());
    let invalid_precompile = address(0x4b);
    let counting_precompile = address(0x4c);
    let storage_slot = slot(0x18);
    let counter = Arc::new(AtomicUsize::new(0));

    let mut precompiles = TestPrecompiles::default();
    precompiles.insert(
        invalid_precompile,
        Program::WriteStorage {
            slot: storage_slot,
            value: slot(0xef),
            return_data: Bytes::from_static(b"bad"),
        },
    );
    precompiles.insert(
        counting_precompile,
        Program::CountAndReturn {
            counter: counter.clone(),
            return_data: Bytes::from_static(b"ok"),
        },
    );

    let mut accounts = HashMap::new();
    accounts.insert(
        sender_a,
        Account {
            balance: 1,
            nonce: 0,
        },
    );
    accounts.insert(
        sender_b,
        Account {
            balance: 1,
            nonce: 0,
        },
    );
    accounts.insert(invalid_precompile, Account::default());
    accounts.insert(counting_precompile, Account::default());

    let mut storage = HashMap::new();
    storage.insert((invalid_precompile, storage_slot), slot(0x08));
    let initial_state = State::new(accounts, storage);

    let tx_a = sign_transaction(&key_a, invalid_precompile, 0);
    let tx_b = sign_transaction(&key_b, counting_precompile, 0);
    let transactions = vec![tx_a, tx_b];
    let (mut discovered, valid) =
        propose_block_access_list(&precompiles, &initial_state, transactions);
    let first_transaction_accesses = discovered
        .access_list
        .accesses_for_transaction(0)
        .iter()
        .copied()
        .filter(|access| !matches!(access, Access::Storage(_, _, _)))
        .collect::<Vec<_>>();
    let second_transaction_accesses = discovered.access_list.accesses_for_transaction(1).to_vec();
    let first_transaction_end =
        u32::try_from(first_transaction_accesses.len()).expect("test BAL must fit in u32");
    let block_end =
        u32::try_from(first_transaction_accesses.len() + second_transaction_accesses.len())
            .expect("test BAL must fit in u32");

    discovered.access_list.tx_accesses = first_transaction_accesses;
    discovered
        .access_list
        .tx_accesses
        .extend(second_transaction_accesses);
    discovered.access_list.tx_offsets = vec![0, first_transaction_end, block_end];

    // Discovery runs both transactions. Reset the counter so this test only
    // measures verifier-side execution.
    counter.store(0, Ordering::SeqCst);

    let processor = Processor::new(&Sequential, &precompiles);
    let err = processor
        .verify(initial_state, &valid, &discovered.access_list)
        .expect_err("first transaction should fail access validation");

    assert_eq!(
        err,
        VerificationError::AccessListMismatch {
            transaction_index: 0
        }
    );
    assert_eq!(counter.load(Ordering::SeqCst), 0);
}

#[test]
fn verify_rejects_wrong_final_state() {
    let key = signer(11);
    let sender = Address::from_public_key(&mut TestHasher::default(), &key.public_key());
    let precompile = address(0x48);
    let storage_slot = slot(0x15);

    let mut precompiles = TestPrecompiles::default();
    precompiles.insert(
        precompile,
        Program::WriteStorage {
            slot: storage_slot,
            value: slot(0xdd),
            return_data: Bytes::from_static(b"ok"),
        },
    );

    let initial_state = base_state(sender, precompile, storage_slot, slot(0x05));
    let transaction = sign_transaction(&key, precompile, 0);
    let (mut discovered, valid) =
        propose_block_access_list(&precompiles, &initial_state, vec![transaction]);
    discovered.access_list.storage_writes[0].value = slot(0xee);

    let processor = Processor::new(&Sequential, &precompiles);
    let err = processor
        .verify(initial_state, &valid, &discovered.access_list)
        .expect_err("wrong final writes must be rejected");
    assert_eq!(err, VerificationError::FinalStateMismatch);
}

#[test]
fn reverted_transaction_still_requires_exact_declared_accesses() {
    let key = signer(12);
    let sender = Address::from_public_key(&mut TestHasher::default(), &key.public_key());
    let precompile = address(0x49);
    let storage_slot = slot(0x16);

    let mut precompiles = TestPrecompiles::default();
    precompiles.insert(
        precompile,
        Program::RevertAfterRead {
            slot: storage_slot,
            payload: Bytes::from_static(b"nope"),
        },
    );

    let initial_state = base_state(sender, precompile, storage_slot, slot(0x06));
    let transaction = sign_transaction(&key, precompile, 0);
    let (discovered, valid) =
        propose_block_access_list(&precompiles, &initial_state, vec![transaction]);

    let processor = Processor::new(&Sequential, &precompiles);
    let output = processor
        .verify(initial_state, &valid, &discovered.access_list)
        .expect("reverted tx should still verify with matching BAL");

    assert_eq!(output.receipts.len(), 1);
    assert_eq!(output.receipts[0].status, ReceiptStatus::Revert);
    assert!(
        discovered
            .access_list
            .tx_accesses
            .contains(&Access::Storage(precompile, storage_slot, AccessMode::Read))
    );
}
