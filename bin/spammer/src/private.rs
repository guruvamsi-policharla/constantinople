//! Private-payment workload.
//!
//! Each *source* account cycles fund -> rollover -> transfer:
//! 1. **fund** moves its public balance into the private `pending` commitment,
//! 2. **rollover** folds `pending` into the spendable `current` commitment,
//! 3. **transfer** sends `value` from `current` to a *sink* account.
//!
//! Sinks are never senders and their balances are not tracked, which keeps
//! reconciliation per-source and order-independent (and sidesteps the
//! private self-transfer case in the executor).
//!
//! The client keeps the commitment *openings* locally so it can build the next
//! proof. Because [`RelayerSubmitter::submit_private`] blocks until the relayer
//! reports a definitive outcome, the client advances a source's state only for
//! transactions that finalized and retries the rest with fresh proofs.

use crate::{
    accounts::{SpamAccount, generate_accounts},
    cli::PrivateProofMode,
    signer::{Tx, account_key, sign_payload},
    submitter::{RelayerSubmitter, Stats},
};
use commonware_privacy::payments::{Backend, Commitment, Opening};
use constantinople_primitives::{
    AccountKey, ChainPrivatePaymentBackend, DEFAULT_ACCOUNT_BALANCE, Payload, PrivatePaymentBackend,
};
use core::num::NonZeroU64;
use futures::future::join_all;
use rand::{CryptoRng, SeedableRng, rngs::StdRng};
use std::sync::Arc;
use tracing::info;

type Privacy = ChainPrivatePaymentBackend;
type PrivateCommitment = <Privacy as Backend>::Commitment;
type PrivateOpening = <Privacy as Backend>::Opening;

/// A commitment paired with its opening, mirroring one side of the chain's
/// `PrivateAccount`.
#[derive(Clone)]
struct PrivateBalance {
    commitment: PrivateCommitment,
    opening: PrivateOpening,
}

impl PrivateBalance {
    fn zero() -> Self {
        Self {
            commitment: PrivateCommitment::zero(),
            opening: PrivateOpening::zero(),
        }
    }

    fn value(&self) -> u64 {
        self.opening.value()
    }

    fn deposit(&mut self, commitment: &PrivateCommitment, opening: &PrivateOpening) {
        self.commitment = self.commitment.clone() + commitment;
        self.opening = self.opening.clone() + opening;
    }

    fn withdraw(&mut self, commitment: &PrivateCommitment, opening: &PrivateOpening) {
        self.commitment = self.commitment.clone() - commitment;
        self.opening = self.opening.clone() - opening;
    }
}

/// Client-side private state for one source account.
struct PrivateSpamState {
    public_balance: u64,
    current: PrivateBalance,
    pending: PrivateBalance,
    nonce: u64,
}

#[derive(Clone, Copy)]
enum PrivatePhase {
    Fund,
    Rollover,
    Transfer,
}

impl PrivateSpamState {
    fn new() -> Self {
        Self {
            public_balance: DEFAULT_ACCOUNT_BALANCE,
            current: PrivateBalance::zero(),
            pending: PrivateBalance::zero(),
            nonce: 0,
        }
    }

    /// The next phase given the account's balances, or `None` when the account
    /// can make no further progress (public balance and private balances are
    /// all exhausted).
    fn phase(&self, value: u64) -> Option<PrivatePhase> {
        if self.current.value() >= value {
            Some(PrivatePhase::Transfer)
        } else if self.pending.value() > 0 {
            Some(PrivatePhase::Rollover)
        } else if self.public_balance > 0 {
            Some(PrivatePhase::Fund)
        } else {
            None
        }
    }
}

/// The local state change to apply once a transaction is observed finalized.
enum PrivateEffect {
    Fund {
        value: u64,
        commitment: PrivateCommitment,
        opening: PrivateOpening,
    },
    Rollover,
    Transfer {
        commitment: PrivateCommitment,
        opening: PrivateOpening,
    },
}

fn apply_effect(state: &mut PrivateSpamState, effect: &PrivateEffect) {
    match effect {
        PrivateEffect::Fund {
            value,
            commitment,
            opening,
        } => {
            state.public_balance = state.public_balance.saturating_sub(*value);
            state.pending.deposit(commitment, opening);
        }
        PrivateEffect::Rollover => {
            let pending = state.pending.clone();
            state.current.deposit(&pending.commitment, &pending.opening);
            state.pending = PrivateBalance::zero();
        }
        PrivateEffect::Transfer {
            commitment,
            opening,
        } => {
            state.current.withdraw(commitment, opening);
        }
    }
    state.nonce += 1;
}

/// Builds and signs the next operation for one source, or `None` if the source
/// is exhausted. Returns the signed transaction and the effect to apply on
/// finalization.
fn plan_and_sign(
    sender: &SpamAccount,
    sink: &AccountKey,
    state: &PrivateSpamState,
    value: u64,
    proof_mode: PrivateProofMode,
    rng: &mut impl CryptoRng,
) -> Option<(Tx, PrivateEffect)> {
    let params = Privacy::params();
    let (payload, effect) = match state.phase(value)? {
        PrivatePhase::Fund => {
            let fund_value = state.public_balance;
            let (commitment, opening, proof) = Privacy::fund(params, fund_value, rng);
            (
                Payload::PrivateFund {
                    value: NonZeroU64::new(fund_value).expect("public balance is non-zero"),
                    commitment: commitment.clone(),
                    proof,
                },
                PrivateEffect::Fund {
                    value: fund_value,
                    commitment,
                    opening,
                },
            )
        }
        PrivatePhase::Rollover => (Payload::PrivateRollover, PrivateEffect::Rollover),
        PrivatePhase::Transfer => {
            let (amount, opening, proof) = transfer_payload(
                &state.current.commitment,
                &state.current.opening,
                value,
                proof_mode,
                rng,
            );
            (
                Payload::PrivateTransfer {
                    to: sink.clone(),
                    amount: amount.clone(),
                    proof,
                },
                PrivateEffect::Transfer {
                    commitment: amount,
                    opening,
                },
            )
        }
    };
    Some((sign_payload(sender, payload, state.nonce), effect))
}

fn transfer_payload(
    input_commitment: &PrivateCommitment,
    input_opening: &PrivateOpening,
    value: u64,
    proof_mode: PrivateProofMode,
    rng: &mut impl CryptoRng,
) -> (
    PrivateCommitment,
    PrivateOpening,
    <Privacy as Backend>::TransferProof,
) {
    match proof_mode {
        PrivateProofMode::Real => Privacy::transfer(
            Privacy::params(),
            input_commitment,
            input_opening,
            value,
            rng,
        ),
        PrivateProofMode::Simulated => simulated_transfer_payload(input_commitment, value, rng),
    }
}

#[cfg(feature = "privacy-backend-simulator")]
fn simulated_transfer_payload(
    input_commitment: &PrivateCommitment,
    value: u64,
    rng: &mut impl CryptoRng,
) -> (
    PrivateCommitment,
    PrivateOpening,
    <Privacy as Backend>::TransferProof,
) {
    use constantinople_primitives::PrivatePaymentSimulatorBackend as _;

    let (amount, opening, _proof) = Privacy::fund(Privacy::params(), value, rng);
    let proof = Privacy::simulated_transfer_proof(
        Privacy::params(),
        Privacy::simulator_trapdoor(),
        input_commitment,
        &amount,
        rng,
    );
    (amount, opening, proof)
}

#[cfg(not(feature = "privacy-backend-simulator"))]
fn simulated_transfer_payload(
    _input_commitment: &PrivateCommitment,
    _value: u64,
    _rng: &mut impl CryptoRng,
) -> (
    PrivateCommitment,
    PrivateOpening,
    <Privacy as Backend>::TransferProof,
) {
    panic!(
        "private proof mode 'simulated' requires building constantinople-spammer with \
         --features constantinople-spammer/privacy-backend-simulator"
    )
}

/// Drives the private workload across `lanes` concurrent lanes.
///
/// Each lane owns a disjoint slice of source (and sink) accounts and runs its
/// own blocking submit loop, so several batches are in flight at once. A single
/// lane only lands one batch per finalization round-trip (leaving the blocks in
/// between empty); running enough lanes keeps every block populated.
#[allow(clippy::too_many_arguments)]
pub async fn run_private(
    relayer_url: String,
    accounts_count: u32,
    value: NonZeroU64,
    seed_offset: u64,
    proof_mode: PrivateProofMode,
    batch_size: usize,
    lanes: usize,
    relayer_targets: Vec<String>,
    stats: Arc<Stats>,
) {
    assert!(batch_size > 0, "--private-batch must be > 0");
    let total = accounts_count as usize;
    let lanes = lanes.clamp(1, total.max(1));
    // Sinks live in a disjoint seed range so a lane's transfers never touch
    // another lane's (or its own) source accounts.
    let sink_base = seed_offset + u64::from(accounts_count);

    info!(
        accounts = total,
        lanes,
        batch = batch_size,
        ?proof_mode,
        "starting private workload"
    );

    let base = total / lanes;
    let extra = total % lanes;
    let mut start = 0usize;
    let mut lane_futures = Vec::with_capacity(lanes);
    for lane in 0..lanes {
        let count = base + usize::from(lane < extra);
        if count == 0 {
            continue;
        }
        // Spread lanes across the provided leader targets (mirrors the public
        // path); fall back to the relayer's default routing when none are given.
        let target = (!relayer_targets.is_empty())
            .then(|| relayer_targets[lane % relayer_targets.len()].clone());
        let submitter = RelayerSubmitter::new(relayer_url.clone(), stats.clone(), lane, target);
        lane_futures.push(run_lane(
            submitter,
            count as u32,
            seed_offset + start as u64,
            sink_base + start as u64,
            value.get(),
            proof_mode,
            batch_size,
            seed_offset.wrapping_add(lane as u64 + 1),
        ));
        start += count;
    }

    join_all(lane_futures).await;
    info!(
        finalized = stats.totals().finalized,
        "all private lanes complete"
    );
}

/// One independent blocking submit loop over a disjoint slice of accounts.
#[allow(clippy::too_many_arguments)]
async fn run_lane(
    submitter: RelayerSubmitter,
    accounts_count: u32,
    source_seed: u64,
    sink_seed: u64,
    value: u64,
    proof_mode: PrivateProofMode,
    batch_size: usize,
    rng_seed: u64,
) {
    let sources = generate_accounts(accounts_count, source_seed);
    let sinks = generate_accounts(accounts_count, sink_seed);
    let sink_keys: Vec<AccountKey> = sinks.iter().map(|s| account_key(&s.public_key)).collect();
    let mut states: Vec<PrivateSpamState> = (0..sources.len())
        .map(|_| PrivateSpamState::new())
        .collect();

    let mut rng = StdRng::seed_from_u64(rng_seed);
    let n = sources.len();
    let mut cursor = 0usize;

    loop {
        // Fill a batch from distinct sources, skipping exhausted ones.
        let mut batch: Vec<Tx> = Vec::with_capacity(batch_size);
        let mut planned: Vec<(usize, PrivateEffect)> = Vec::with_capacity(batch_size);
        let mut scanned = 0;
        while batch.len() < batch_size && scanned < n {
            let i = cursor;
            cursor = (cursor + 1) % n;
            scanned += 1;
            if let Some((tx, effect)) = plan_and_sign(
                &sources[i],
                &sink_keys[i],
                &states[i],
                value,
                proof_mode,
                &mut rng,
            ) {
                planned.push((i, effect));
                batch.push(tx);
            }
        }

        if batch.is_empty() {
            return;
        }

        let outcome = submitter.submit_private(&batch).await;
        // Apply finalized effects in batch order; leave the rest to retry with
        // a fresh proof and the same (still-free) nonce next time around.
        for (batch_index, (index, effect)) in planned.iter().enumerate() {
            if outcome.finalized(batch_index as u64) {
                apply_effect(&mut states[*index], effect);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use constantinople_primitives::Payload;

    fn sink_key(seed: u64) -> AccountKey {
        account_key(&generate_accounts(1, seed)[0].public_key)
    }

    #[test]
    fn source_cycles_fund_rollover_then_drains_current() {
        let source = &generate_accounts(1, 7)[0];
        let sink = sink_key(999);
        let mut state = PrivateSpamState::new();
        let mut rng = StdRng::seed_from_u64(7);
        let value = 1;

        // 1. Fund the whole public balance into pending.
        let (tx, effect) = plan_and_sign(
            source,
            &sink,
            &state,
            value,
            PrivateProofMode::Real,
            &mut rng,
        )
        .expect("fund");
        assert!(matches!(tx.value().payload, Payload::PrivateFund { .. }));
        assert_eq!(tx.value().nonce, 0);
        apply_effect(&mut state, &effect);
        assert_eq!(state.public_balance, 0);
        assert_eq!(state.pending.value(), DEFAULT_ACCOUNT_BALANCE);
        assert_eq!(state.current.value(), 0);
        assert_eq!(state.nonce, 1);

        // 2. Roll pending into current.
        let (tx, effect) = plan_and_sign(
            source,
            &sink,
            &state,
            value,
            PrivateProofMode::Real,
            &mut rng,
        )
        .expect("rollover");
        assert!(matches!(tx.value().payload, Payload::PrivateRollover));
        apply_effect(&mut state, &effect);
        assert_eq!(state.current.value(), DEFAULT_ACCOUNT_BALANCE);
        assert_eq!(state.pending.value(), 0);

        // 3. Transfer `value` until current is drained, then the source is exhausted.
        let mut transfers = 0;
        while let Some((tx, effect)) = plan_and_sign(
            source,
            &sink,
            &state,
            value,
            PrivateProofMode::Real,
            &mut rng,
        ) {
            assert!(matches!(
                tx.value().payload,
                Payload::PrivateTransfer { .. }
            ));
            apply_effect(&mut state, &effect);
            transfers += 1;
        }
        assert_eq!(transfers, DEFAULT_ACCOUNT_BALANCE);
        assert_eq!(state.current.value(), 0);
        assert!(
            state.phase(value).is_none(),
            "exhausted source has no phase"
        );
    }

    #[test]
    fn unfinalized_op_keeps_nonce_for_fresh_retry() {
        // Not applying the effect models a dropped/filtered transaction: the
        // nonce stays free, so the next plan re-signs at the same nonce.
        let source = &generate_accounts(1, 3)[0];
        let sink = sink_key(555);
        let state = PrivateSpamState::new();
        let mut rng = StdRng::seed_from_u64(3);

        let (first, _) =
            plan_and_sign(source, &sink, &state, 1, PrivateProofMode::Real, &mut rng).expect("op");
        let (retry, _) = plan_and_sign(source, &sink, &state, 1, PrivateProofMode::Real, &mut rng)
            .expect("retry");
        assert_eq!(first.value().nonce, 0);
        assert_eq!(retry.value().nonce, 0);
    }
}
