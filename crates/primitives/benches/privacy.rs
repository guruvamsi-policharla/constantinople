//! Microbenchmarks for the private-transfer cryptography.
//!
//! Block processing splits into (a) one batched pairing check over every ZK
//! claim in the block (`verify_proofs_batch`, the `prepare` phase of
//! `execute_body`) and (b) per-transaction commitment arithmetic during
//! execution. These benches isolate both, plus the client-side proving costs,
//! so the per-block crypto budget can be read directly:
//!
//!   block crypto time ~= verify_batch(n) + n * (commitment add/sub)

use constantinople_primitives::{
    BalanceCommitment, PrivateBalance, ProofClaim, verify_proofs_batch,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::{SeedableRng, rngs::StdRng};

const BATCH_SIZES: &[usize] = &[1, 16, 64, 256, 1024, 4096];

/// One self-consistent transfer claim: a funded balance sending `amount`.
fn transfer_claim(seed: u64, simulate: bool) -> ProofClaim {
    let mut rng = StdRng::seed_from_u64(seed);
    let amount = 1 + (seed % 7);
    let mut balance = PrivateBalance::empty();
    balance.fund(amount * 8);
    let input = balance.commitment();
    let plan = balance
        .plan_transfer(amount, &mut rng)
        .expect("funded balance covers the transfer");
    let amount_commitment = plan.amount_commitment();
    let proof = if simulate {
        plan.simulate(&mut rng)
    } else {
        plan.prove(&mut rng)
    };
    ProofClaim::Transfer {
        input,
        amount: amount_commitment,
        proof,
    }
}

fn proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("privacy/verify");
    for &batch in BATCH_SIZES {
        let claims: Vec<ProofClaim> = (0..batch).map(|i| transfer_claim(i as u64, true)).collect();
        group.throughput(Throughput::Elements(batch as u64));
        group.bench_with_input(BenchmarkId::new("batch", batch), &claims, |b, claims| {
            b.iter(|| {
                assert!(verify_proofs_batch(std::hint::black_box(claims)));
            });
        });
    }
    group.finish();
}

fn proving(c: &mut Criterion) {
    let mut group = c.benchmark_group("privacy/prove");
    group.sample_size(10);

    group.bench_function("simulate", |b| {
        let mut seed = 0u64;
        b.iter(|| {
            seed += 1;
            std::hint::black_box(transfer_claim(seed, true))
        });
    });
    group.bench_function("prove", |b| {
        let mut seed = 0u64;
        b.iter(|| {
            seed += 1;
            std::hint::black_box(transfer_claim(seed, false))
        });
    });

    group.finish();
}

fn commitments(c: &mut Criterion) {
    let mut group = c.benchmark_group("privacy/commitment");

    let a = BalanceCommitment::commit(123_456);
    let b_ = BalanceCommitment::commit(789);
    group.bench_function("commit", |b| {
        let mut value = 0u64;
        b.iter(|| {
            value += 1;
            std::hint::black_box(BalanceCommitment::commit(std::hint::black_box(value)))
        });
    });
    group.bench_function("add", |b| {
        b.iter(|| std::hint::black_box(a.add(std::hint::black_box(&b_))));
    });
    group.bench_function("sub", |b| {
        b.iter(|| std::hint::black_box(a.sub(std::hint::black_box(&b_))));
    });
    // Same 2-base MSM shape (one small scalar, one full-width scalar) as the
    // verifier's per-claim `com_theta = com_amount + theta * com_remaining`
    // reconstruction, so this is a direct proxy for that hot-path cost.
    group.bench_function("commit_blinded", |b| {
        use zkpari::CommittedInputOpening;
        let mut rng = StdRng::seed_from_u64(7);
        let opening = CommittedInputOpening::<ark_bn254::Fr>::rand(&mut rng);
        let mut value = 0u64;
        b.iter(|| {
            value += 1;
            std::hint::black_box(BalanceCommitment::commit_with(
                std::hint::black_box(value),
                std::hint::black_box(&opening),
            ))
        });
    });

    group.finish();
}

/// Splits the cost of one validated point deserialization — the dominant
/// per-claim verification cost (5 such decodes per private transfer) — into
/// its parts: sqrt-based decompression vs the subgroup check.
fn point_decoding(c: &mut Criterion) {
    use ark_bn254::G1Affine;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    let mut group = c.benchmark_group("privacy/decode");

    let point = BalanceCommitment::commit(123_456_789);
    let mut bytes = Vec::new();
    G1Affine::deserialize_compressed(point.as_bytes().as_slice())
        .expect("commitment bytes are canonical")
        .serialize_compressed(&mut bytes)
        .expect("serialization cannot fail");

    group.bench_function("validated", |b| {
        b.iter(|| {
            G1Affine::deserialize_compressed(std::hint::black_box(bytes.as_slice()))
                .expect("valid point")
        });
    });
    group.bench_function("unchecked", |b| {
        b.iter(|| {
            G1Affine::deserialize_compressed_unchecked(std::hint::black_box(bytes.as_slice()))
                .expect("valid point")
        });
    });
    let affine = G1Affine::deserialize_compressed(bytes.as_slice()).expect("valid point");
    group.bench_function("subgroup_check", |b| {
        b.iter(|| {
            assert!(std::hint::black_box(&affine).is_in_correct_subgroup_assuming_on_curve());
        });
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = proof_verification, proving, commitments, point_decoding
}
criterion_main!(benches);
