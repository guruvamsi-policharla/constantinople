//! Does concurrent ingress decompression on the shared strategy pool starve
//! the leader's block-build verify? Times `verify_with_strategy` over an
//! 8000-transfer round on an idle pool vs. while background workers
//! continuously frame + preload compressed ingress batches (the real
//! competing workload a leader sees from the relayer firehose during its
//! build slot).
//!
//! Run: cargo bench -p constantinople-application --bench leader_contention \
//!   --features constantinople-primitives/privacy-backend-zkpari,constantinople-primitives/privacy-backend-simulator

use commonware_codec::Encode as _;
use commonware_cryptography::{Hasher as _, Sha256, Signer as _, ed25519};
use commonware_math::algebra::Random as _;
use commonware_parallel::Rayon;
use commonware_privacy::payments::Backend as _;
use constantinople_application::executor::{
    PreparedOperation, PreparedPayload, SelectiveExecutor, State,
};
use constantinople_primitives::{
    AccountKey, ChainPrivatePaymentBackend as Chain, Nonce, Payload, PrivateAccount,
    PrivatePaymentBackend, PrivatePaymentSimulatorBackend, SignedTransaction, StateAccount,
    TRANSACTION_NAMESPACE, Transaction, TransactionPublicKey, frame_signed_batch,
    preload_transaction_chunks, to_state_commitment, to_state_transfer_proof,
};
use core::num::NonZeroUsize;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn key(index: u64) -> AccountKey {
    AccountKey::try_from(Sha256::hash(&index.to_le_bytes()).as_ref()).expect("32-byte key")
}

/// One 64-tx compressed ingress batch body, as the relayer forwards.
fn ingress_body(seed: u64) -> bytes::Bytes {
    let params = <Chain as PrivatePaymentBackend>::params();
    let trapdoor = <Chain as PrivatePaymentSimulatorBackend>::simulator_trapdoor();
    let mut rng = commonware_utils::test_rng();
    let _ = seed;
    let signer = ed25519::PrivateKey::random(&mut rng);
    let sender = TransactionPublicKey::ed25519(signer.public_key());
    let mut txs: Vec<SignedTransaction<Sha256>> = Vec::with_capacity(64);
    for nonce in 0..64u64 {
        let (input_c, _o, _f) = Chain::fund(params, 1_000, &mut rng);
        let (amount, _o2, _f2) = Chain::fund(params, 250, &mut rng);
        let proof = Chain::simulated_transfer_proof(params, trapdoor, &input_c, &amount, &mut rng);
        let payload = Payload::PrivateTransfer {
            to: AccountKey::from_public_key(&sender),
            amount,
            proof,
        };
        txs.push(
            Transaction::from_payload(sender.clone(), payload, nonce).seal_and_sign(
                &signer,
                TRANSACTION_NAMESPACE,
                &mut Sha256::default(),
            ),
        );
    }
    txs.encode()
}

fn main() {
    let n = 8_000usize;
    let params = <Chain as PrivatePaymentBackend>::params();
    let trapdoor = <Chain as PrivatePaymentSimulatorBackend>::simulator_trapdoor();
    let mut rng = commonware_utils::test_rng();

    // Build an 8000-transfer round the way the leader's select sees it.
    let mut state = State::default();
    let mut ops = Vec::with_capacity(n);
    for i in 0..n as u64 {
        let (input_c, _o, _fp) = Chain::fund(params, 1_000, &mut rng);
        let (amount, _o2, _fp2) = Chain::fund(params, 250, &mut rng);
        let proof = Chain::simulated_transfer_proof(params, trapdoor, &input_c, &amount, &mut rng);
        let sender = key(i);
        state.insert(
            sender,
            StateAccount {
                balance: 1_000_000,
                nonce: Nonce::default(),
                private: {
                    let mut p = PrivateAccount::zero();
                    p.deposit(&to_state_commitment(input_c));
                    p.rollover();
                    p
                },
            },
        );
        ops.push(PreparedOperation {
            sender,
            sender_prefix: sender.prefix(),
            nonce: 0,
            payload: PreparedPayload::PrivateTransfer {
                recipient: key(u64::MAX - i),
                recipient_prefix: key(u64::MAX - i).prefix(),
                amount: to_state_commitment(amount),
                proof: to_state_transfer_proof(proof),
            },
        });
    }

    let pool = Rayon::new(NonZeroUsize::new(28).unwrap()).expect("pool");
    let mut selector = SelectiveExecutor::new();
    let keys = selector.begin_round(&ops);
    let values: Vec<_> = keys.iter().map(|k| state.get(k).cloned()).collect();
    selector.register(&values);
    let (_applied, verifications) = selector.apply(&ops);
    assert!(!verifications.is_empty());
    println!(
        "round: {} proofs to verify (28-thread pool)",
        verifications.len()
    );

    // (A) verify on an idle pool.
    let mut idle = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        assert!(verifications.verify_with_strategy(&pool));
        idle.push(t.elapsed().as_secs_f64() * 1e3);
    }
    idle.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "verify, idle pool:            {:.1} ms (median of 5)",
        idle[2]
    );

    // (B) verify while background workers hammer the SAME pool with real
    // ingress decompression (frame + preload of compressed 64-tx batches).
    let bodies: Vec<bytes::Bytes> = (0..8).map(ingress_body).collect();
    let stop = Arc::new(AtomicBool::new(false));
    let batches_done = Arc::new(AtomicU64::new(0));
    let mut loaders = Vec::new();
    for w in 0..16 {
        let pool = pool.clone();
        let stop = stop.clone();
        let done = batches_done.clone();
        let body = bodies[w % bodies.len()].clone();
        loaders.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let framed = frame_signed_batch::<Sha256, Chain>(&body, 64).expect("frame");
                let _ = preload_transaction_chunks(framed, &pool);
                done.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    // Let the firehose saturate the pool.
    while batches_done.load(Ordering::Relaxed) < 4 {
        std::hint::spin_loop();
    }
    let mut loaded = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        assert!(verifications.verify_with_strategy(&pool));
        loaded.push(t.elapsed().as_secs_f64() * 1e3);
    }
    stop.store(true, Ordering::Relaxed);
    for h in loaders {
        h.join().ok();
    }
    loaded.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "verify, ingress firehose on pool: {:.1} ms (median of 5)  [{:.1}x]",
        loaded[2],
        loaded[2] / idle[2].max(1e-9)
    );
}
