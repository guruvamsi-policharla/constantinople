//! Ring-pattern transaction signing and batch sizing.

use crate::{accounts::SpamAccount, config::PrivateProofMode};
use commonware_cryptography::{Sha256, ed25519};
use commonware_parallel::Strategy;
use commonware_privacy::payments::{Backend, Commitment, Opening};
use constantinople_primitives::{
    AccountKey, ChainPrivatePaymentBackend, DEFAULT_ACCOUNT_BALANCE, Payload,
    PrivatePaymentBackend, SignedTransaction, TRANSACTION_NAMESPACE, Transaction,
    TransactionPublicKey,
};
use core::num::NonZeroU64;
use rand::{RngCore, SeedableRng as _, rngs::StdRng};
use std::collections::HashSet;

/// Concrete signed transaction type.
pub type Tx = SignedTransaction<Sha256>;

/// Signs one transaction for a single sender in the ring.
fn sign_one(
    sender: &SpamAccount,
    recipient: &ed25519::PublicKey,
    value: NonZeroU64,
    nonce: u64,
) -> Tx {
    let tx = Transaction::new(
        TransactionPublicKey::ed25519(sender.public_key.clone()),
        TransactionPublicKey::ed25519(recipient.clone()),
        value,
        nonce,
    );
    tx.seal_and_sign(
        &sender.private_key,
        TRANSACTION_NAMESPACE,
        &mut Sha256::default(),
    )
}

fn sign_payload(sender: &SpamAccount, payload: Payload, nonce: u64) -> Tx {
    let tx = Transaction::from_payload(
        TransactionPublicKey::ed25519(sender.public_key.clone()),
        payload,
        nonce,
    );
    tx.seal_and_sign(
        &sender.private_key,
        TRANSACTION_NAMESPACE,
        &mut Sha256::default(),
    )
}

/// Signs a variable-size batch while preserving per-account nonce order.
///
/// Senders are selected by walking the account ring from `cursor`. Each
/// selected account uses and increments its own nonce, so callers can vary
/// `count` per submission without creating nonce gaps.
pub fn sign_batch<St: Strategy>(
    strategy: &St,
    accounts: &[SpamAccount],
    value: NonZeroU64,
    nonces: &mut [u64],
    cursor: &mut usize,
    count: usize,
) -> Vec<Tx> {
    assert_eq!(accounts.len(), nonces.len(), "nonces must match accounts");
    assert!(!accounts.is_empty(), "need at least one account");
    assert!(count > 0, "need at least one transaction");

    let n = accounts.len();
    let mut work = Vec::with_capacity(count);
    for _ in 0..count {
        let sender_index = *cursor;
        let nonce = nonces[sender_index];
        nonces[sender_index] = nonce + 1;
        *cursor = (*cursor + 1) % n;
        work.push((sender_index, nonce));
    }

    strategy.map_collect_vec(work, |(i, nonce)| {
        let sender = &accounts[i];
        let recipient = &accounts[(i + 1) % n].public_key;
        sign_one(sender, recipient, value, nonce)
    })
}

type PrivateBackend = ChainPrivatePaymentBackend;
type PrivateCommitment = <PrivateBackend as Backend>::Commitment;
type PrivateOpening = <PrivateBackend as Backend>::Opening;
const PRIVATE_INITIAL_FUND_VALUE: u64 = DEFAULT_ACCOUNT_BALANCE * 4 / 5;

/// Client-side private state tracked by the spammer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateSpamState {
    public_balance: u64,
    current: PrivateClientBalance,
    pending: PrivateClientBalance,
    phase: PrivatePhase,
}

impl Default for PrivateSpamState {
    fn default() -> Self {
        Self {
            public_balance: DEFAULT_ACCOUNT_BALANCE,
            current: PrivateClientBalance::zero(),
            pending: PrivateClientBalance::zero(),
            phase: PrivatePhase::Fund,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrivateClientBalance {
    commitment: PrivateCommitment,
    opening: PrivateOpening,
}

impl PrivateClientBalance {
    fn zero() -> Self {
        Self {
            commitment: PrivateCommitment::zero(),
            opening: PrivateOpening::zero(),
        }
    }

    const fn value(&self) -> u64 {
        self.opening.value()
    }

    fn deposit(&mut self, commitment: &PrivateCommitment, opening: &PrivateOpening) {
        self.commitment = self.commitment + commitment;
        self.opening = self.opening + opening;
    }

    fn withdraw(&mut self, commitment: &PrivateCommitment, opening: &PrivateOpening) {
        self.commitment = self.commitment - commitment;
        self.opening = self.opening - opening;
    }

    fn reset(&mut self) {
        *self = Self::zero();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrivatePhase {
    Fund,
    Rollover,
    Transfer,
}

/// Private transactions paired with local effects needed for outcome replay.
#[derive(Debug, Clone)]
pub struct PrivateBatch {
    pub txs: Vec<Tx>,
    effects: Vec<PrivateEffect>,
}

pub struct PrivateBatchState<'a> {
    pub nonces: &'a mut [u64],
    pub states: &'a mut [PrivateSpamState],
    pub cursor: &'a mut usize,
}

#[derive(Debug, Clone, Copy)]
pub struct PrivateBatchSpec {
    pub count: usize,
    pub proof_mode: PrivateProofMode,
}

#[derive(Debug, Clone)]
struct PrivateEffect {
    digest: String,
    sender_index: usize,
    nonce: u64,
    payload: PrivateEffectPayload,
}

#[derive(Debug, Clone)]
struct PlannedPrivateTx {
    sender_index: usize,
    recipient_index: usize,
    nonce: u64,
    seed: u64,
    payload: PlannedPrivatePayload,
}

#[derive(Debug, Clone)]
enum PlannedPrivatePayload {
    Fund {
        value: u64,
    },
    Rollover,
    Transfer {
        input_commitment: PrivateCommitment,
        input_opening: PrivateOpening,
    },
}

#[derive(Debug)]
struct RealizedPrivateTx {
    tx: Tx,
    effect: PrivateEffect,
}

#[derive(Debug, Clone)]
enum PrivateEffectPayload {
    Fund {
        value: u64,
        commitment: PrivateCommitment,
        opening: PrivateOpening,
    },
    Rollover,
    Transfer {
        recipient_index: usize,
        amount: PrivateCommitment,
        opening: PrivateOpening,
    },
}

/// Signs a batch of private transactions while preserving per-account nonce
/// order and private state validity.
pub fn sign_private_batch<St: Strategy>(
    strategy: &St,
    accounts: &[SpamAccount],
    value: NonZeroU64,
    state: PrivateBatchState<'_>,
    spec: PrivateBatchSpec,
    rng: &mut impl RngCore,
) -> PrivateBatch {
    let count = spec.count;
    assert_eq!(
        accounts.len(),
        state.nonces.len(),
        "nonces must match accounts"
    );
    assert_eq!(
        accounts.len(),
        state.states.len(),
        "states must match accounts"
    );
    assert!(accounts.len() >= 2, "need at least two accounts");
    assert!(count > 0, "need at least one transaction");

    let mut txs = Vec::with_capacity(count);
    let mut effects = Vec::with_capacity(count);
    let mut attempts = 0;
    let max_attempts = count
        .checked_add(accounts.len())
        .expect("private spammer batch attempt count overflow");

    while txs.len() < count && attempts < max_attempts {
        let round_len = (count - txs.len())
            .min(accounts.len())
            .min(max_attempts - attempts);
        let mut plans = Vec::with_capacity(round_len);

        for _ in 0..round_len {
            attempts += 1;
            let sender_index = *state.cursor;
            let recipient_index = (sender_index + 1) % accounts.len();
            *state.cursor = (*state.cursor + 1) % accounts.len();

            let Some(payload) = plan_private_payload(state.states, sender_index, value.get())
            else {
                continue;
            };
            let nonce = state.nonces[sender_index];
            state.nonces[sender_index] = nonce + 1;
            plans.push(PlannedPrivateTx {
                sender_index,
                recipient_index,
                nonce,
                seed: rng.next_u64(),
                payload,
            });
        }

        if plans.is_empty() {
            continue;
        }

        let realized = strategy.map_collect_vec(plans, |plan| {
            realize_private_tx(accounts, value.get(), spec.proof_mode, plan)
        });
        for realized in realized {
            apply_private_effect(
                value,
                state.states,
                realized.effect.sender_index,
                &realized.effect.payload,
            );
            effects.push(realized.effect);
            txs.push(realized.tx);
        }
    }

    PrivateBatch { txs, effects }
}

/// Applies finalized private transactions to the spammer's local state.
///
/// This replays the local effects for transactions that actually finalized
/// instead of committing the speculative state used while signing the candidate
/// batch.
pub fn apply_private_finalized_batch(
    value: NonZeroU64,
    nonces: &mut [u64],
    states: &mut [PrivateSpamState],
    batch: &PrivateBatch,
    included: &HashSet<String>,
) -> usize {
    assert_eq!(nonces.len(), states.len(), "states must match nonces");

    let mut applied = 0;
    for effect in &batch.effects {
        if !included.contains(&effect.digest) {
            continue;
        }

        let sender_index = effect.sender_index;
        nonces[sender_index] = nonces[sender_index].max(effect.nonce.saturating_add(1));
        apply_private_effect(value, states, sender_index, &effect.payload);
        applied += 1;
    }

    applied
}

fn plan_private_payload(
    states: &[PrivateSpamState],
    sender_index: usize,
    value: u64,
) -> Option<PlannedPrivatePayload> {
    let state = &states[sender_index];
    match private_phase_for(
        state.current.value(),
        state.pending.value(),
        state.public_balance,
        value,
    ) {
        PrivatePhase::Fund => next_fund_value(state, value)
            .map(|fund_value| PlannedPrivatePayload::Fund { value: fund_value }),
        PrivatePhase::Rollover => {
            (state.pending.value() > 0).then_some(PlannedPrivatePayload::Rollover)
        }
        PrivatePhase::Transfer => {
            assert!(
                state.current.value() >= value,
                "private spammer current balance too low"
            );
            Some(PlannedPrivatePayload::Transfer {
                input_commitment: state.current.commitment,
                input_opening: state.current.opening,
            })
        }
    }
}

fn realize_private_tx(
    accounts: &[SpamAccount],
    value: u64,
    proof_mode: PrivateProofMode,
    plan: PlannedPrivateTx,
) -> RealizedPrivateTx {
    let mut rng = StdRng::seed_from_u64(plan.seed);
    let (payload, effect_payload) = match plan.payload {
        PlannedPrivatePayload::Fund { value: fund_value } => {
            let (commitment, opening, proof) =
                PrivateBackend::fund(PrivateBackend::params(), fund_value, &mut rng);
            (
                Payload::PrivateFund {
                    value: NonZeroU64::new(fund_value).expect("fund value is non-zero"),
                    commitment,
                    proof,
                },
                PrivateEffectPayload::Fund {
                    value: fund_value,
                    commitment,
                    opening,
                },
            )
        }
        PlannedPrivatePayload::Rollover => {
            (Payload::PrivateRollover, PrivateEffectPayload::Rollover)
        }
        PlannedPrivatePayload::Transfer {
            input_commitment,
            input_opening,
        } => {
            let _ = proof_mode;
            let (amount, opening, proof) = PrivateBackend::transfer(
                PrivateBackend::params(),
                &input_commitment,
                &input_opening,
                value,
                &mut rng,
            );
            (
                Payload::PrivateTransfer {
                    to: account_key(&accounts[plan.recipient_index].public_key),
                    amount,
                    proof,
                },
                PrivateEffectPayload::Transfer {
                    recipient_index: plan.recipient_index,
                    amount,
                    opening,
                },
            )
        }
    };
    let tx = sign_payload(&accounts[plan.sender_index], payload, plan.nonce);
    RealizedPrivateTx {
        effect: PrivateEffect {
            digest: tx.message_digest().to_string(),
            sender_index: plan.sender_index,
            nonce: plan.nonce,
            payload: effect_payload,
        },
        tx,
    }
}

fn apply_private_effect(
    value: NonZeroU64,
    states: &mut [PrivateSpamState],
    sender_index: usize,
    effect: &PrivateEffectPayload,
) {
    match effect {
        PrivateEffectPayload::Fund {
            value,
            commitment,
            opening,
        } => {
            states[sender_index].public_balance =
                states[sender_index].public_balance.saturating_sub(*value);
            states[sender_index].pending.deposit(commitment, opening);
            states[sender_index].phase = PrivatePhase::Rollover;
        }
        PrivateEffectPayload::Rollover => {
            let pending = states[sender_index].pending.clone();
            states[sender_index]
                .current
                .deposit(&pending.commitment, &pending.opening);
            states[sender_index].pending.reset();
            states[sender_index].phase = if states[sender_index].current.value() >= value.get() {
                PrivatePhase::Transfer
            } else if states[sender_index].pending.value() > 0 {
                PrivatePhase::Rollover
            } else if states[sender_index].public_balance > 0 {
                PrivatePhase::Fund
            } else {
                PrivatePhase::Rollover
            };
        }
        PrivateEffectPayload::Transfer {
            recipient_index,
            amount,
            opening,
        } => {
            states[sender_index].current.withdraw(amount, opening);
            states[*recipient_index].pending.deposit(amount, opening);
            states[sender_index].phase = next_transfer_phase(
                states[sender_index].current.value(),
                states[sender_index].pending.value(),
                states[sender_index].public_balance,
                value.get(),
            );
        }
    };
}

fn next_fund_value(state: &PrivateSpamState, value: u64) -> Option<u64> {
    let public_balance = state.public_balance;
    if public_balance == 0 {
        return None;
    }

    if state.current.value() == 0
        && state.pending.value() == 0
        && public_balance == DEFAULT_ACCOUNT_BALANCE
    {
        return Some(PRIVATE_INITIAL_FUND_VALUE.max(value).min(public_balance));
    }

    let needed = value.saturating_sub(state.current.value());
    if needed == 0 {
        return Some(public_balance.min(value));
    }
    (public_balance >= needed).then_some(needed)
}

const fn next_transfer_phase(
    current: u64,
    pending: u64,
    public_balance: u64,
    value: u64,
) -> PrivatePhase {
    private_phase_for(current, pending, public_balance, value)
}

const fn private_phase_for(
    current: u64,
    pending: u64,
    public_balance: u64,
    value: u64,
) -> PrivatePhase {
    if current >= value {
        PrivatePhase::Transfer
    } else if pending > 0 {
        PrivatePhase::Rollover
    } else if public_balance > 0 {
        PrivatePhase::Fund
    } else {
        PrivatePhase::Rollover
    }
}

fn account_key(public_key: &ed25519::PublicKey) -> AccountKey {
    AccountKey::from_public_key(&TransactionPublicKey::ed25519(public_key.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::generate_accounts;
    use commonware_parallel::Sequential;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn sign_produces_correct_count() {
        let accounts = generate_accounts(5, 1000);
        let value = NonZeroU64::new(1).unwrap();
        let mut nonces = vec![0; accounts.len()];
        let mut cursor = 0;
        let txs = sign_batch(&Sequential, &accounts, value, &mut nonces, &mut cursor, 15);
        assert_eq!(txs.len(), 5 * 3);
    }

    #[test]
    fn single_round_produces_one_tx_per_account() {
        let accounts = generate_accounts(10, 1000);
        let value = NonZeroU64::new(1).unwrap();
        let mut nonces = vec![0; accounts.len()];
        let mut cursor = 0;
        let txs = sign_batch(&Sequential, &accounts, value, &mut nonces, &mut cursor, 10);
        assert_eq!(txs.len(), 10);
        for tx in &txs {
            assert_eq!(tx.value().nonce, 0);
        }
    }

    #[test]
    fn nonces_are_correct() {
        let accounts = generate_accounts(3, 1000);
        let value = NonZeroU64::new(1).unwrap();
        let mut nonces = vec![0; accounts.len()];
        let mut cursor = 0;
        let txs = sign_batch(&Sequential, &accounts, value, &mut nonces, &mut cursor, 12);
        for (idx, tx) in txs.iter().enumerate() {
            let round = (idx / 3) as u64;
            assert_eq!(tx.value().nonce, round);
        }
    }

    #[test]
    fn signed_transactions_survive_encode_decode_roundtrip() {
        use commonware_codec::{Decode, Encode, RangeCfg};
        use commonware_cryptography::Sha256;
        use constantinople_primitives::{TRANSACTION_NAMESPACE, verify_transaction_batch};

        let accounts = generate_accounts(5, 1000);
        let value = NonZeroU64::new(1).unwrap();
        let mut nonces = vec![0; accounts.len()];
        let mut cursor = 0;
        let txs = sign_batch(&Sequential, &accounts, value, &mut nonces, &mut cursor, 10);

        // Encode as the client would.
        let body = txs.as_slice().encode();

        // Decode as the server would.
        let max_transactions = body.len() / 119; // conservative min tx size
        let cfg = (RangeCfg::new(1..=max_transactions), ());
        let decoded = Vec::<Tx>::decode_cfg(&mut &body[..], &cfg).expect("decode should succeed");
        assert_eq!(decoded.len(), txs.len());

        // Verify signatures as the server would (using Sha256, same as the validator).
        let mut rng = commonware_utils::test_rng();
        let lazy_decoded: Vec<_> = decoded
            .into_iter()
            .map(constantinople_primitives::LazySignedTransaction::new)
            .collect();
        assert!(
            verify_transaction_batch::<Sha256, _, _>(
                &Sequential,
                TRANSACTION_NAMESPACE,
                &mut rng,
                &lazy_decoded,
            ),
            "batch signature verification should pass"
        );
    }

    #[test]
    fn variable_batch_preserves_per_account_nonces() {
        let accounts = generate_accounts(4, 1000);
        let value = NonZeroU64::new(1).unwrap();
        let mut nonces = vec![0; accounts.len()];
        let mut cursor = 0;

        let first = sign_batch(&Sequential, &accounts, value, &mut nonces, &mut cursor, 6);
        let second = sign_batch(&Sequential, &accounts, value, &mut nonces, &mut cursor, 3);

        assert_eq!(first.len(), 6);
        assert_eq!(second.len(), 3);
        assert_eq!(cursor, 1);
        assert_eq!(nonces, vec![3, 2, 2, 2]);

        let observed: Vec<_> = first
            .iter()
            .chain(second.iter())
            .map(|tx| tx.value().nonce)
            .collect();
        assert_eq!(observed, vec![0, 0, 0, 0, 1, 1, 1, 1, 2]);
    }

    #[test]
    fn private_batch_funds_once_then_transfers_until_exhausted() {
        let accounts = generate_accounts(3, 1000);
        let value = NonZeroU64::new(1).unwrap();
        let mut nonces = vec![0; accounts.len()];
        let mut states = vec![PrivateSpamState::default(); accounts.len()];
        let mut cursor = 0;
        let mut rng = StdRng::seed_from_u64(7);

        let batch = sign_private_batch(
            &Sequential,
            &accounts,
            value,
            PrivateBatchState {
                nonces: &mut nonces,
                states: &mut states,
                cursor: &mut cursor,
            },
            PrivateBatchSpec {
                count: 12,
                proof_mode: PrivateProofMode::Real,
            },
            &mut rng,
        );

        assert_eq!(batch.txs.len(), 12);
        assert_eq!(nonces, vec![4, 4, 4]);
        let payload_kinds: Vec<_> = batch
            .txs
            .iter()
            .map(|tx| match tx.value().payload {
                Payload::PrivateFund { .. } => "fund",
                Payload::PrivateRollover => "rollover",
                Payload::PrivateTransfer { .. } => "transfer",
                Payload::PrivateBurn { .. } => "burn",
                Payload::PublicTransfer { .. } => "public",
            })
            .collect();
        assert_eq!(
            payload_kinds,
            vec![
                "fund", "fund", "fund", "rollover", "rollover", "rollover", "transfer", "transfer",
                "transfer", "transfer", "transfer", "transfer"
            ]
        );
        assert_eq!(states[0].public_balance, 20);
        assert_eq!(states[1].public_balance, 20);
        assert_eq!(states[2].public_balance, 20);
        assert_eq!(states[0].current.value(), 78);
        assert_eq!(states[1].current.value(), 78);
        assert_eq!(states[2].current.value(), 78);
        assert_eq!(states[0].pending.value(), 2);
        assert_eq!(states[1].pending.value(), 2);
        assert_eq!(states[2].pending.value(), 2);
    }

    #[test]
    fn private_batch_can_use_simulated_transfer_proofs() {
        let accounts = generate_accounts(3, 1000);
        let value = NonZeroU64::new(1).unwrap();
        let mut nonces = vec![0; accounts.len()];
        let mut states = vec![PrivateSpamState::default(); accounts.len()];
        let mut cursor = 0;
        let mut rng = StdRng::seed_from_u64(23);

        let batch = sign_private_batch(
            &Sequential,
            &accounts,
            value,
            PrivateBatchState {
                nonces: &mut nonces,
                states: &mut states,
                cursor: &mut cursor,
            },
            PrivateBatchSpec {
                count: 9,
                proof_mode: PrivateProofMode::Simulated,
            },
            &mut rng,
        );

        assert!(
            batch
                .txs
                .iter()
                .any(|tx| matches!(tx.value().payload, Payload::PrivateTransfer { .. }))
        );
    }

    #[test]
    fn private_outcome_replay_advances_only_included_transactions() {
        let accounts = generate_accounts(3, 1000);
        let value = NonZeroU64::new(1).unwrap();
        let mut candidate_nonces = vec![0; accounts.len()];
        let mut candidate_states = vec![PrivateSpamState::default(); accounts.len()];
        let mut candidate_cursor = 0;
        let mut rng = StdRng::seed_from_u64(11);
        let batch = sign_private_batch(
            &Sequential,
            &accounts,
            value,
            PrivateBatchState {
                nonces: &mut candidate_nonces,
                states: &mut candidate_states,
                cursor: &mut candidate_cursor,
            },
            PrivateBatchSpec {
                count: accounts.len(),
                proof_mode: PrivateProofMode::Real,
            },
            &mut rng,
        );
        let included = HashSet::from([batch.txs[0].message_digest().to_string()]);

        let mut committed_nonces = vec![0; accounts.len()];
        let mut committed_states = vec![PrivateSpamState::default(); accounts.len()];
        let applied = apply_private_finalized_batch(
            value,
            &mut committed_nonces,
            &mut committed_states,
            &batch,
            &included,
        );

        assert_eq!(applied, 1);
        assert_eq!(committed_nonces, vec![1, 0, 0]);
        assert_eq!(committed_states[0].public_balance, 20);
        assert_eq!(committed_states[0].phase, PrivatePhase::Rollover);
        assert_eq!(
            committed_states[0].pending.value(),
            PRIVATE_INITIAL_FUND_VALUE
        );
        assert_eq!(committed_states[1], PrivateSpamState::default());
        assert_eq!(committed_states[2], PrivateSpamState::default());
    }

    #[test]
    fn private_batch_rolls_over_after_exhausting_current_balance() {
        let accounts = generate_accounts(3, 1000);
        let value = NonZeroU64::new(50).unwrap();
        let mut nonces = vec![0; accounts.len()];
        let mut states = vec![PrivateSpamState::default(); accounts.len()];
        let mut cursor = 0;
        let mut rng = StdRng::seed_from_u64(17);

        let batch = sign_private_batch(
            &Sequential,
            &accounts,
            value,
            PrivateBatchState {
                nonces: &mut nonces,
                states: &mut states,
                cursor: &mut cursor,
            },
            PrivateBatchSpec {
                count: 12,
                proof_mode: PrivateProofMode::Real,
            },
            &mut rng,
        );

        assert_eq!(batch.txs.len(), 12);
        let payload_kinds: Vec<_> = batch
            .txs
            .iter()
            .map(|tx| match tx.value().payload {
                Payload::PrivateFund { .. } => "fund",
                Payload::PrivateRollover => "rollover",
                Payload::PrivateTransfer { .. } => "transfer",
                Payload::PrivateBurn { .. } => "burn",
                Payload::PublicTransfer { .. } => "public",
            })
            .collect();
        assert_eq!(
            payload_kinds,
            vec![
                "fund", "fund", "fund", "rollover", "rollover", "rollover", "transfer", "transfer",
                "transfer", "rollover", "rollover", "rollover"
            ]
        );
        assert_eq!(states[0].current.value(), 80);
        assert_eq!(states[1].current.value(), 80);
        assert_eq!(states[2].current.value(), 80);
        assert_eq!(states[0].pending.value(), 0);
        assert_eq!(states[1].pending.value(), 0);
        assert_eq!(states[2].pending.value(), 0);
        assert_eq!(states[0].phase, PrivatePhase::Transfer);
        assert_eq!(states[1].phase, PrivatePhase::Transfer);
        assert_eq!(states[2].phase, PrivatePhase::Transfer);
    }

    #[test]
    fn private_batch_refuels_from_public_reserve_when_stranded() {
        let accounts = generate_accounts(3, 1000);
        let value = NonZeroU64::new(1).unwrap();
        let mut nonces = vec![0; accounts.len()];
        let mut states = vec![PrivateSpamState::default(); accounts.len()];
        states[0].public_balance = 20;
        states[0].phase = PrivatePhase::Fund;
        let mut cursor = 0;
        let mut rng = StdRng::seed_from_u64(19);

        let batch = sign_private_batch(
            &Sequential,
            &accounts,
            value,
            PrivateBatchState {
                nonces: &mut nonces,
                states: &mut states,
                cursor: &mut cursor,
            },
            PrivateBatchSpec {
                count: 1,
                proof_mode: PrivateProofMode::Real,
            },
            &mut rng,
        );

        assert_eq!(batch.txs.len(), 1);
        assert!(matches!(
            batch.txs[0].value().payload,
            Payload::PrivateFund { .. }
        ));
        assert_eq!(states[0].public_balance, 19);
        assert_eq!(states[0].pending.value(), 1);
        assert_eq!(states[0].phase, PrivatePhase::Rollover);
    }

    #[test]
    fn private_transactions_survive_server_decode_and_signature_verification() {
        use commonware_codec::{Decode, Encode, FixedSize, RangeCfg};
        use commonware_cryptography::Sha256;
        use constantinople_primitives::{
            TRANSACTION_NAMESPACE, TransactionPublicKey, TransactionSignature,
            verify_transaction_batch,
        };

        let accounts = generate_accounts(10, 1000);
        let value = NonZeroU64::new(1).unwrap();
        let mut nonces = vec![0; accounts.len()];
        let mut states = vec![PrivateSpamState::default(); accounts.len()];
        let mut cursor = 0;
        let mut rng = StdRng::seed_from_u64(13);

        let batch = sign_private_batch(
            &Sequential,
            &accounts,
            value,
            PrivateBatchState {
                nonces: &mut nonces,
                states: &mut states,
                cursor: &mut cursor,
            },
            PrivateBatchSpec {
                count: accounts.len(),
                proof_mode: PrivateProofMode::Real,
            },
            &mut rng,
        );
        let body = batch.txs.as_slice().encode();

        let min_signed_transaction_bytes =
            TransactionPublicKey::SIZE + 1 + u64::SIZE + TransactionSignature::MIN_SIZE;
        let max_transactions = body.len().saturating_sub(1) / min_signed_transaction_bytes;
        assert!(max_transactions >= batch.txs.len());

        let cfg = (RangeCfg::new(1..=max_transactions), ());
        let decoded = Vec::<Tx>::decode_cfg(&mut &body[..], &cfg).expect("decode should succeed");
        let mut rng = commonware_utils::test_rng();
        let lazy_decoded: Vec<_> = decoded
            .into_iter()
            .map(constantinople_primitives::LazySignedTransaction::new)
            .collect();

        assert!(
            verify_transaction_batch::<Sha256, _, _>(
                &Sequential,
                TRANSACTION_NAMESPACE,
                &mut rng,
                &lazy_decoded,
            ),
            "private batch signature verification should pass"
        );
    }
}
