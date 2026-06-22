use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{Signer, ed25519, sha256};
use commonware_math::algebra::Random;
use commonware_parallel::{Rayon, Sequential};
use commonware_privacy::payments::{Backend, Commitment};
use constantinople_application::executor::{self, State};
use constantinople_primitives::{
    Account, AccountKey, ChainPrivatePaymentBackend, LazySignedTransaction, Nonce, Payload,
    PrivateAccount, PrivatePaymentBackend, TRANSACTION_NAMESPACE, Transaction,
    TransactionPublicKey, VerifiedTransaction, preload_transaction_chunks, to_state_account,
    verify_transaction_batch,
};
use core::num::NonZeroUsize;
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::{SeedableRng, rngs::StdRng};
use std::{env, hint::black_box};

type TestHasher = sha256::Sha256;
type PrivateBackend = ChainPrivatePaymentBackend;
type TestTransaction = VerifiedTransaction<TestHasher, PrivateBackend>;
type TestLazyTransaction = LazySignedTransaction<TestHasher, PrivateBackend>;

const DEFAULT_TRANSACTION_COUNTS: &[usize] = &[1 << 14];
const DEFAULT_PROOF_VERIFY_THREADS: &[usize] = &[1, 2, 4, 8, 16];
const INITIAL_PRIVATE_BALANCE: u64 = 100000;
const TRANSFER_VALUE: u64 = 1;

fn application_verify(c: &mut Criterion) {
    let transaction_counts =
        usize_list_from_env("APPLICATION_VERIFY_TXS", DEFAULT_TRANSACTION_COUNTS);
    let proof_verify_threads =
        usize_list_from_env("APPLICATION_VERIFY_THREADS", DEFAULT_PROOF_VERIFY_THREADS);
    let mut group = c.benchmark_group(format!(
        "application_verify/private_transfer/{}",
        PrivateBackend::NAME
    ));

    for &transaction_count in &transaction_counts {
        let fixture = build_private_transfer_fixture(transaction_count);
        let operations = prepare_operations(&fixture.transactions);

        group.throughput(Throughput::Elements(transaction_count as u64));
        group.bench_with_input(
            BenchmarkId::new("signatures_decode_and_verify", transaction_count),
            &fixture,
            |bencher, fixture| {
                bencher.iter_batched(
                    || deferred_body(&fixture.transactions),
                    |body| {
                        let body = preload_transaction_chunks(&Sequential, body)
                            .expect("bench transactions should decode");
                        let mut rng = StdRng::seed_from_u64(0);
                        black_box(verify_transaction_batch::<TestHasher, PrivateBackend, _>(
                            &Sequential,
                            TRANSACTION_NAMESPACE,
                            &mut rng,
                            black_box(&body),
                        ))
                    },
                    BatchSize::SmallInput,
                );
            },
        );
        group.bench_with_input(
            BenchmarkId::new("prepare_operations", transaction_count),
            &fixture.transactions,
            |bencher, transactions| {
                bencher.iter(|| {
                    black_box(prepare_operations(black_box(transactions)).len());
                });
            },
        );
        for &threads in &proof_verify_threads {
            if threads == 1 {
                group.bench_with_input(
                    BenchmarkId::new(
                        "execute_operations_threads",
                        format!("txs={transaction_count}/threads=1"),
                    ),
                    &(&fixture.state, &operations),
                    |bencher, (state, operations)| {
                        bencher.iter(|| {
                            black_box(
                                executor::execute_with_strategy(
                                    black_box(state),
                                    black_box(operations),
                                    &Sequential,
                                )
                                .expect("bench transfers should execute")
                                .len(),
                            );
                        });
                    },
                );
                group.bench_with_input(
                    BenchmarkId::new(
                        "prepare_and_execute_threads",
                        format!("txs={transaction_count}/threads=1"),
                    ),
                    &fixture,
                    |bencher, fixture| {
                        bencher.iter(|| {
                            let operations = prepare_operations(black_box(&fixture.transactions));
                            black_box(
                                executor::execute_with_strategy(
                                    black_box(&fixture.state),
                                    black_box(&operations),
                                    &Sequential,
                                )
                                .expect("bench transfers should execute")
                                .len(),
                            );
                        });
                    },
                );
                continue;
            }

            let strategy =
                Rayon::new(NonZeroUsize::new(threads).expect("thread count must be non-zero"))
                    .expect("rayon strategy should initialize");
            group.bench_with_input(
                BenchmarkId::new(
                    "execute_operations_threads",
                    format!("txs={transaction_count}/threads={threads}"),
                ),
                &(&fixture.state, &operations),
                |bencher, (state, operations)| {
                    bencher.iter(|| {
                        black_box(
                            executor::execute_with_strategy(
                                black_box(state),
                                black_box(operations),
                                &strategy,
                            )
                            .expect("bench transfers should execute")
                            .len(),
                        );
                    });
                },
            );
            group.bench_with_input(
                BenchmarkId::new(
                    "prepare_and_execute_threads",
                    format!("txs={transaction_count}/threads={threads}"),
                ),
                &fixture,
                |bencher, fixture| {
                    bencher.iter(|| {
                        let operations = prepare_operations(black_box(&fixture.transactions));
                        black_box(
                            executor::execute_with_strategy(
                                black_box(&fixture.state),
                                black_box(&operations),
                                &strategy,
                            )
                            .expect("bench transfers should execute")
                            .len(),
                        );
                    });
                },
            );
        }
    }

    group.finish();
}

fn usize_list_from_env(name: &str, default: &[usize]) -> Vec<usize> {
    let Some(values) = env::var(name).ok().map(|value| {
        value
            .split(',')
            .filter_map(|entry| entry.trim().parse::<usize>().ok())
            .filter(|value| *value > 0)
            .collect::<Vec<_>>()
    }) else {
        return default.to_vec();
    };

    if values.is_empty() {
        default.to_vec()
    } else {
        values
    }
}

struct VerifyFixture {
    state: State,
    transactions: Vec<TestTransaction>,
}

fn build_private_transfer_fixture(transaction_count: usize) -> VerifyFixture {
    let mut state = State::with_capacity(transaction_count * 2);
    let mut transactions = Vec::with_capacity(transaction_count);
    let mut rng = StdRng::seed_from_u64(7);

    for index in 0..transaction_count {
        let sender = TestSigner::new(index as u64);
        let recipient = TestSigner::new(index as u64 + transaction_count as u64);
        let sender_key = TransactionPublicKey::ed25519(sender.public_key.clone());
        let recipient_key = TransactionPublicKey::ed25519(recipient.public_key.clone());
        let sender_account_key = AccountKey::from_public_key(&sender_key);
        let recipient_account_key = AccountKey::from_public_key(&recipient_key);

        let (current_commitment, current_opening) =
            PrivateBackend::commit_public(PrivateBackend::params(), INITIAL_PRIVATE_BALANCE);
        let (amount, _amount_opening, proof) = PrivateBackend::transfer(
            PrivateBackend::params(),
            &current_commitment,
            &current_opening,
            TRANSFER_VALUE,
            &mut rng,
        );

        state.insert(
            sender_account_key,
            to_state_account(Account {
                balance: 0,
                nonce: Nonce::default(),
                private: PrivateAccount {
                    current: current_commitment,
                    pending: <PrivateBackend as Backend>::Commitment::zero(),
                },
            }),
        );
        state.insert(
            recipient_account_key.clone(),
            to_state_account(Account::default()),
        );

        transactions.push(sender.sign_payload(
            Payload::PrivateTransfer {
                to: recipient_account_key,
                amount,
                proof,
            },
            0,
        ));
    }

    VerifyFixture {
        state,
        transactions,
    }
}

fn prepare_operations(
    transactions: &[TestTransaction],
) -> Vec<
    constantinople_application::executor::PreparedOperation<
        TestHasher,
        <PrivateBackend as constantinople_primitives::PrivatePaymentExecutionBackend>::ExecutionBackend,
    >,
>{
    transactions
        .iter()
        .map(executor::prepare_operation)
        .collect::<Option<Vec<_>>>()
        .expect("bench transactions should prepare")
}

fn deferred_body(transactions: &[TestTransaction]) -> Vec<TestLazyTransaction> {
    transactions
        .iter()
        .cloned()
        .map(TestLazyTransaction::new)
        .map(|transaction| {
            TestLazyTransaction::decode(transaction.encode())
                .expect("encoded lazy transaction should decode")
        })
        .collect()
}

struct TestSigner {
    key: ed25519::PrivateKey,
    public_key: ed25519::PublicKey,
}

impl TestSigner {
    fn new(index: u64) -> Self {
        let key = ed25519::PrivateKey::random(&mut StdRng::seed_from_u64(index));
        let public_key = key.public_key();
        Self { key, public_key }
    }

    fn sign_payload(&self, payload: Payload<PrivateBackend>, nonce: u64) -> TestTransaction {
        Transaction::from_payload(
            TransactionPublicKey::ed25519(self.key.public_key()),
            payload,
            nonce,
        )
        .seal_and_sign(&self.key, TRANSACTION_NAMESPACE, &mut TestHasher::default())
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = application_verify
}
criterion_main!(benches);
