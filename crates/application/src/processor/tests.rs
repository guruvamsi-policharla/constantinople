//! End-to-end processor tests for transfer-only execution.

use super::{
    executor::{Processor, ValidationResult},
    state::{DiscoveryState, State},
};
use commonware_cryptography::{Signer, blake3, ed25519};
use commonware_math::algebra::Random;
use commonware_parallel::{Rayon, Sequential};
use constantinople_primitives::{Account, Address, Transaction, VerifiedTransaction};
use core::{marker::PhantomData, num::NonZeroU64};
use rand::rngs::OsRng;
use std::{collections::HashMap, num::NonZeroUsize};

const NAMESPACE: &[u8] = b"processor-test";

type TestHasher = blake3::Blake3;
type TestTransaction = VerifiedTransaction<ed25519::PublicKey, TestHasher>;
type TestValidation = ValidationResult<ed25519::PublicKey, TestHasher>;

#[derive(Debug, Clone)]
struct TestSigner {
    key: ed25519::PrivateKey,
    address: Address,
}

impl TestSigner {
    fn new() -> Self {
        let key = ed25519::PrivateKey::random(&mut OsRng);
        let address = Address::from_public_key(&mut TestHasher::default(), &key.public_key());
        Self { key, address }
    }

    fn sign(&self, to: Address, value: u64, nonce: u64) -> TestTransaction {
        Transaction {
            sender: self.key.public_key(),
            to,
            value: NonZeroU64::new(value).expect("test values must be non-zero"),
            nonce,
            _digest: PhantomData,
        }
        .seal_and_sign_verified(&self.key, NAMESPACE, &mut TestHasher::default())
    }
}

fn processor() -> Processor<'static, Sequential> {
    Processor::new(&Sequential)
}

fn account(balance: u64, nonce: u64) -> Account {
    Account { balance, nonce }
}

#[test]
fn validate_tracks_pending_nonce_and_balance() {
    let signer = TestSigner::new();
    let recipient = TestSigner::new();
    let mut accounts = HashMap::new();
    accounts.insert(signer.address, account(10, 0));

    let validation: TestValidation = processor().validate(
        &State::new(accounts),
        vec![
            signer.sign(recipient.address, 4, 0),
            signer.sign(recipient.address, 7, 1),
            signer.sign(recipient.address, 6, 1),
        ],
    );

    assert_eq!(validation.valid.len(), 2);
    assert_eq!(validation.invalid.len(), 1);
    assert_eq!(validation.valid[0].value().nonce, 0);
    assert_eq!(validation.valid[1].value().nonce, 1);
    assert_eq!(validation.invalid[0].value().value.get(), 7);
}

#[test]
fn propose_and_verify_match_for_transfer_batch() {
    let sender_a = TestSigner::new();
    let sender_b = TestSigner::new();
    let recipient = TestSigner::new();

    let mut accounts = HashMap::new();
    accounts.insert(sender_a.address, account(11, 0));
    accounts.insert(sender_b.address, account(13, 0));
    accounts.insert(recipient.address, account(5, 0));

    let transactions = vec![
        sender_a.sign(recipient.address, 4, 0),
        sender_b.sign(recipient.address, 6, 0),
    ];

    let sequential = Sequential;
    let processor = Processor::new(&sequential);
    let validation = processor.validate(&State::new(accounts.clone()), transactions.clone());
    let mut discovery = DiscoveryState::new(State::new(accounts.clone()));
    let proposal = processor.propose(&mut discovery, &validation.valid);
    let verification = processor.verify(State::new(accounts), &validation.valid);

    assert_eq!(proposal.changeset, verification.changeset);
    assert_eq!(
        verification.changeset.get(&sender_a.address),
        Some(&account(7, 1))
    );
    assert_eq!(
        verification.changeset.get(&sender_b.address),
        Some(&account(7, 1))
    );
    assert_eq!(
        verification.changeset.get(&recipient.address),
        Some(&account(15, 0))
    );
}

#[test]
fn self_transfer_only_bumps_nonce() {
    let signer = TestSigner::new();
    let mut accounts = HashMap::new();
    accounts.insert(signer.address, account(9, 3));

    let processor = processor();
    let validation = processor.validate(
        &State::new(accounts.clone()),
        vec![signer.sign(signer.address, 4, 3)],
    );
    let output = processor.verify(State::new(accounts), &validation.valid);

    assert_eq!(output.changeset.get(&signer.address), Some(&account(9, 4)));
}

#[test]
fn parallel_verify_matches_sequential_verify() {
    let sender_a = TestSigner::new();
    let sender_b = TestSigner::new();
    let recipient_a = TestSigner::new();
    let recipient_b = TestSigner::new();

    let mut accounts = HashMap::new();
    accounts.insert(sender_a.address, account(8, 0));
    accounts.insert(sender_b.address, account(9, 0));

    let transactions = vec![
        sender_a.sign(recipient_a.address, 3, 0),
        sender_b.sign(recipient_b.address, 5, 0),
    ];

    let sequential = Sequential;
    let parallel = Rayon::new(NonZeroUsize::new(2).expect("parallelism must be non-zero"))
        .expect("rayon should build");

    let sequential_processor = Processor::new(&sequential);
    let parallel_processor = Processor::new(&parallel);
    let validation = sequential_processor.validate(&State::new(accounts.clone()), transactions);

    let sequential_output =
        sequential_processor.verify(State::new(accounts.clone()), &validation.valid);
    let parallel_output = parallel_processor.verify(State::new(accounts), &validation.valid);

    assert_eq!(parallel_output.changeset, sequential_output.changeset);
}
