//! Diagnostic: times the leader's private selection path — optimistic apply +
//! batched verify (top-level vs nested-in-pool-job, mirroring
//! `execution.rs`'s `strategy.spawn` structure) vs the per-proof fallback.
//!
//! Run: cargo bench -p constantinople-application --bench selective_private \
//!   --features constantinople-primitives/privacy-backend-zkpari,constantinople-primitives/privacy-backend-simulator

use commonware_cryptography::{Hasher as _, Sha256};
use commonware_math::algebra::Random as _;
use commonware_parallel::Strategy;
use commonware_privacy::payments::Backend;
use constantinople_application::executor::{
    PreparedOperation, PreparedPayload, SelectiveExecutor, State,
};
use constantinople_primitives::{
    AccountKey, ChainPrivatePaymentBackend, Nonce, PrivateAccount, PrivatePaymentBackend,
    PrivatePaymentSimulatorBackend, StateAccount, to_state_commitment, to_state_transfer_proof,
};
use std::time::Instant;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

type Chain = ChainPrivatePaymentBackend;

fn key(index: u64) -> AccountKey {
    AccountKey::try_from(Sha256::hash(&index.to_le_bytes()).as_ref()).expect("32-byte key")
}

fn main() {
    let n: usize = 8_000;
    let params = <Chain as PrivatePaymentBackend>::params();
    let trapdoor = <Chain as PrivatePaymentSimulatorBackend>::simulator_trapdoor();
    let mut rng = rand::rng();

    let mut state = State::default();
    let mut ops = Vec::with_capacity(n);
    for i in 0..n as u64 {
        let sender = key(i);
        let recipient = key(u64::MAX - i);
        let (input_c, _o, _fp) = <Chain as Backend>::fund(params, 1_000, &mut rng);
        let (amount, _o2, _fp2) = <Chain as Backend>::fund(params, 250, &mut rng);
        let proof = <Chain as Backend>::simulated_transfer_proof(
            params, trapdoor, &input_c, &amount, &mut rng,
        );
        state.insert(
            sender,
            StateAccount {
                balance: 1_000_000,
                nonce: Nonce::default(),
                private: {
                    let mut private = PrivateAccount::zero();
                    private.deposit(&to_state_commitment(input_c));
                    private.rollover();
                    private
                },
            },
        );
        ops.push(PreparedOperation {
            sender,
            sender_prefix: sender.prefix(),
            nonce: 0,
            payload: PreparedPayload::PrivateTransfer {
                recipient,
                recipient_prefix: recipient.prefix(),
                amount: to_state_commitment(amount),
                proof: to_state_transfer_proof(proof),
            },
        });
    }
    println!("built {n} simulated private transfers");

    let strategy =
        commonware_parallel::Rayon::new(core::num::NonZeroUsize::new(8).unwrap()).expect("pool");

    // (a) optimistic apply alone
    let mut selector = SelectiveExecutor::new();
    let keys = selector.begin_round(&ops);
    let values: Vec<_> = keys.iter().map(|k| state.get(k).cloned()).collect();
    selector.register(&values);
    let cp = selector.checkpoint();
    let t = Instant::now();
    let (applied, verifications) = selector.apply(&ops);
    let apply_d = t.elapsed();
    let applied_count = applied.iter().filter(|a| **a).count();

    // (b) batched verify, top-level strategy
    let t = Instant::now();
    let ok_top = verifications.verify_with_strategy(&strategy);
    let verify_top = t.elapsed();

    // (c) batched verify, nested inside a strategy.spawn job (leader shape)
    let verifications2 = verifications;
    let t = Instant::now();
    let ok_nested = futures::executor::block_on(
        strategy
            .spawn(move |s: commonware_parallel::Rayon| verifications2.verify_with_strategy(&s)),
    );
    let verify_nested = t.elapsed();

    // (d) per-proof fallback
    selector.restore(cp);
    let t = Instant::now();
    let applied_v = selector.apply_verifying(&ops);
    let fallback_d = t.elapsed();
    let applied_v_count = applied_v.iter().filter(|a| **a).count();

    // (e) the leader's reality: the same batched verify while the pool is
    // saturated with unrelated work (certify, prior-view verify, ingress).
    let mut selector2 = SelectiveExecutor::new();
    let keys2 = selector2.begin_round(&ops);
    let values2: Vec<_> = keys2.iter().map(|k| state.get(k).cloned()).collect();
    selector2.register(&values2);
    let (_, verifications3) = selector2.apply(&ops);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut background = Vec::new();
    // 6 of 8 threads busy: the verify job contends for the remainder plus
    // work-stealing, mirroring a leader whose pool also runs certify,
    // prior-view verification, and ingress.
    for _ in 0..6 {
        let stop = stop.clone();
        background.push(strategy.spawn(move |_: commonware_parallel::Rayon| {
            let mut x = 1u64;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                for _ in 0..1_000_000 {
                    x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
                }
                std::hint::black_box(x);
            }
        }));
    }
    std::thread::sleep(std::time::Duration::from_millis(50));
    let t = Instant::now();
    let ok_contended = futures::executor::block_on(
        strategy
            .spawn(move |s: commonware_parallel::Rayon| verifications3.verify_with_strategy(&s)),
    );
    let verify_contended = t.elapsed();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for job in background {
        futures::executor::block_on(job);
    }

    // (f) ingress unit cost: serial decode of one 64-tx submission batch.
    use commonware_codec::{Decode as _, Encode as _, RangeCfg};
    use constantinople_primitives::SignedTransaction;
    let sample = {
        let mut txs: Vec<SignedTransaction<commonware_cryptography::Sha256>> = Vec::new();
        let mut key_rng = rand::rng();
        let signer = commonware_cryptography::ed25519::PrivateKey::random(&mut key_rng);
        for i in 0..64u64 {
            let (amount, _o, _f) = <Chain as Backend>::fund(params, 1 + i, &mut rng);
            let (input_c, _o2, _f2) = <Chain as Backend>::fund(params, 1_000, &mut rng);
            let proof = <Chain as Backend>::simulated_transfer_proof(
                params, trapdoor, &input_c, &amount, &mut rng,
            );
            let payload = constantinople_primitives::Payload::PrivateTransfer {
                to: key(i),
                amount,
                proof,
            };
            let tx = constantinople_primitives::Transaction::from_payload(
                constantinople_primitives::TransactionPublicKey::ed25519(
                    commonware_cryptography::Signer::public_key(&signer),
                ),
                payload,
                i,
            );
            txs.push(tx.seal_and_sign(
                &signer,
                constantinople_primitives::TRANSACTION_NAMESPACE,
                &mut commonware_cryptography::Sha256::default(),
            ));
        }
        txs.encode().to_vec()
    };
    let t = Instant::now();
    let cfg = (RangeCfg::new(1..=64usize), ());
    let decoded = Vec::<SignedTransaction<commonware_cryptography::Sha256>>::decode_cfg(
        sample.as_slice(),
        &cfg,
    )
    .expect("batch decodes");
    let ingress_d = t.elapsed();
    std::hint::black_box(decoded);

    println!("apply (optimistic):        {apply_d:?}  applied={applied_count}/{n}");
    println!("batched verify (top):      {verify_top:?}  ok={ok_top}");
    println!("batched verify (nested):   {verify_nested:?}  ok={ok_nested}");
    println!("apply_verifying fallback:  {fallback_d:?}  applied={applied_v_count}/{n}");
    println!("batched verify (contended pool): {verify_contended:?}  ok={ok_contended}");
    println!("ingress decode 64-tx batch (serial): {ingress_d:?}");
}
