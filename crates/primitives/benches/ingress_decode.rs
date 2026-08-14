//! Ingress decode strategies, head to head: eager `Vec<SignedTransaction>`
//! decode (decompresses every point serially on the accepting thread) vs
//! `frame_signed_batch` + parallel preload (frames cheaply, decompresses
//! across the pool). This is the fix for compressed-point ingress stalling
//! the leader; the numbers below are the evidence.
//!
//! Run with the real backend:
//!   cargo bench -p constantinople-primitives --bench ingress_decode \
//!     --features privacy-backend-zkpari,privacy-backend-simulator

use commonware_codec::{Decode as _, Encode as _, RangeCfg};
use commonware_cryptography::{Sha256, Signer as _, ed25519};
use commonware_math::algebra::Random as _;
use commonware_parallel::Rayon;
use commonware_privacy::payments::Backend as _;
use constantinople_primitives::{
    ChainPrivatePaymentBackend as Chain, LazySignedTransaction, Payload, PrivatePaymentBackend,
    PrivatePaymentSimulatorBackend, SignedTransaction, TRANSACTION_NAMESPACE, Transaction,
    TransactionPublicKey, frame_signed_batch, preload_transaction_chunks,
};
use core::num::NonZeroUsize;
use rand::{SeedableRng as _, rngs::StdRng};
use std::time::Instant;

const BATCH: usize = 64; // one relayer submission
const REPEAT: usize = 200; // submissions per trial (a block's worth of ingress)

fn build_batch_body() -> bytes::Bytes {
    let params = <Chain as PrivatePaymentBackend>::params();
    let trapdoor = <Chain as PrivatePaymentSimulatorBackend>::simulator_trapdoor();
    let mut rng = StdRng::from_seed([7u8; 32]);
    let signer = ed25519::PrivateKey::random(&mut rng);
    let sender = TransactionPublicKey::ed25519(signer.public_key());

    let mut txs: Vec<SignedTransaction<Sha256>> = Vec::with_capacity(BATCH);
    for nonce in 0..BATCH as u64 {
        let (input_c, _o, _f) = Chain::fund(params, 1_000, &mut rng);
        let (amount, _o2, _f2) = Chain::fund(params, 250, &mut rng);
        let proof = Chain::simulated_transfer_proof(params, trapdoor, &input_c, &amount, &mut rng);
        let payload = Payload::PrivateTransfer {
            to: constantinople_primitives::AccountKey::from_public_key(&sender),
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
    let body = build_batch_body();
    let max = BATCH;
    let pool = Rayon::new(NonZeroUsize::new(8).unwrap()).expect("pool");

    // (1) EAGER: decode the batch on the calling thread. This is the current
    // hot-path cost — a full serial decompression that occupies one pool
    // worker per submission.
    let t = Instant::now();
    for _ in 0..REPEAT {
        let decoded = Vec::<SignedTransaction<Sha256>>::decode_cfg(
            body.as_ref(),
            &(RangeCfg::new(1..=max), ()),
        )
        .expect("eager decode");
        std::hint::black_box(decoded);
    }
    let eager_serial = t.elapsed() / REPEAT as u32;

    // (2) FRAMED: frame the batch on the calling thread — no point touched.
    let t = Instant::now();
    for _ in 0..REPEAT {
        let framed = frame_signed_batch::<Sha256, Chain>(&body, max).expect("frame");
        std::hint::black_box(framed);
    }
    let framed_serial = t.elapsed() / REPEAT as u32;

    // (3) FRAMED + parallel preload: the deferred decompression done across
    // the pool (what verify_transaction_chunks runs).
    let t = Instant::now();
    for _ in 0..REPEAT {
        let framed = frame_signed_batch::<Sha256, Chain>(&body, max).expect("frame");
        let preloaded = preload_transaction_chunks(framed, &pool).expect("preload");
        std::hint::black_box(preloaded);
    }
    let framed_total = t.elapsed() / REPEAT as u32;

    // (4) Reference: eager decode then materialize as already-decoded lazy
    // (the pre-fix ingress shape), for total-time comparison.
    let t = Instant::now();
    for _ in 0..REPEAT {
        let decoded = Vec::<SignedTransaction<Sha256>>::decode_cfg(
            body.as_ref(),
            &(RangeCfg::new(1..=max), ()),
        )
        .expect("eager decode");
        let lazy: Vec<_> = decoded
            .into_iter()
            .map(LazySignedTransaction::new)
            .collect();
        std::hint::black_box(lazy);
    }
    let eager_total = t.elapsed() / REPEAT as u32;

    println!("per {BATCH}-tx submission (mean of {REPEAT}):");
    println!("  eager decode, calling thread (serial decompress):  {eager_serial:>10.2?}");
    println!("  framed,       calling thread (no decompress):       {framed_serial:>10.2?}");
    println!("  framed + parallel preload (pool decompress):        {framed_total:>10.2?}");
    println!("  eager total (pre-fix ingress shape):                {eager_total:>10.2?}");
    println!();
    println!(
        "  calling-thread cost removed from the pool: {:.1}x ({eager_serial:.2?} -> {framed_serial:.2?})",
        eager_serial.as_secs_f64() / framed_serial.as_secs_f64().max(1e-9)
    );
}
