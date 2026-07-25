//! Diagnostic: times the leader's private selection path — optimistic apply +
//! batched verify (top-level vs nested-in-pool-job, mirroring
//! `execution.rs`'s `strategy.spawn` structure) vs the per-proof fallback.
//!
//! Run: cargo bench -p constantinople-application --bench selective_private \
//!   --features constantinople-primitives/privacy-backend-zkpari,constantinople-primitives/privacy-backend-simulator

use commonware_cryptography::{Hasher as _, Sha256};
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

    println!("apply (optimistic):        {apply_d:?}  applied={applied_count}/{n}");
    println!("batched verify (top):      {verify_top:?}  ok={ok_top}");
    println!("batched verify (nested):   {verify_nested:?}  ok={ok_nested}");
    println!("apply_verifying fallback:  {fallback_d:?}  applied={applied_v_count}/{n}");
}
