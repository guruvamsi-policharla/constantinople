//! Ring-pattern transaction signing and batch sizing.

use crate::accounts::SpamAccount;
use commonware_cryptography::{Sha256, ed25519};
use commonware_parallel::Strategy;
use constantinople_primitives::{
    AccountKey, BalanceCommitment, PrivateBalance, SignedTransaction, TRANSACTION_NAMESPACE,
    Transaction, TransactionPublicKey, TransferPlan,
};
use core::num::NonZeroU64;
use rand::{SeedableRng, rngs::StdRng};

/// Concrete signed transaction type.
pub type Tx = SignedTransaction<Sha256>;

/// How much an account funds into its private balance at a time, as a multiple
/// of the transfer value. Larger chunks mean longer transfer chains between
/// funds, which is what stresses the proposer's commitment-chain packing.
const FUND_MULTIPLE: u64 = 8;

/// Per-account private state for the spammer, mirroring the on-chain
/// commitment chain.
///
/// Each account funds its private balance from its public balance, then sends
/// commitment-chained private transfers to its ring neighbor. Funds permanently
/// move public tokens into the private side (and transfers land in recipients'
/// unspendable `pending` slots), so accounts gradually drain — the spammer
/// keeps producing until an account can neither transfer nor fund.
pub struct PrivateChains {
    balances: Vec<PrivateBalance>,
    public_remaining: Vec<u64>,
}

impl PrivateChains {
    /// Creates chains for `accounts` accounts, each starting with
    /// `starting_public_balance` spendable public tokens.
    pub fn new(accounts: usize, starting_public_balance: u64) -> Self {
        Self {
            balances: (0..accounts).map(|_| PrivateBalance::empty()).collect(),
            public_remaining: vec![starting_public_balance; accounts],
        }
    }
}

/// One planned private-mode transaction, with the sender's commitment chain
/// already advanced. Proving (simulated) happens later, in parallel.
// Transient per-transaction planning data; the transfer variant carries the
// secret openings and is consumed immediately, so boxing it to equalize the
// enum size would only add churn in the signing loop.
#[allow(clippy::large_enum_variant)]
enum PrivatePlan {
    Fund {
        account: usize,
        nonce: u64,
        input: BalanceCommitment,
        value: NonZeroU64,
    },
    Transfer {
        account: usize,
        nonce: u64,
        recipient: AccountKey,
        input: BalanceCommitment,
        plan: TransferPlan,
    },
}

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

/// Signs a private-mode batch, preserving each account's commitment chain.
///
/// Planning walks the account ring and, per slot, either funds an account (when
/// its private balance can't cover a transfer) or sends a commitment-chained
/// private transfer to its ring neighbor. Planning is sequential because each
/// link binds the previous commitment; the expensive part — proving — is
/// **simulated** from the setup trapdoor and fans out across the strategy.
///
/// May return fewer than `count` transactions if accounts have drained their
/// public and private balances.
pub fn sign_batch_private<St: Strategy>(
    strategy: &St,
    accounts: &[SpamAccount],
    value: NonZeroU64,
    nonces: &mut [u64],
    chains: &mut PrivateChains,
    cursor: &mut usize,
    count: usize,
) -> Vec<Tx> {
    assert_eq!(accounts.len(), nonces.len(), "nonces must match accounts");
    assert_eq!(
        accounts.len(),
        chains.balances.len(),
        "chains must match accounts"
    );
    assert!(!accounts.is_empty(), "need at least one account");
    assert!(count > 0, "need at least one transaction");

    let n = accounts.len();
    let mut plans = Vec::with_capacity(count);
    let mut planning_rng = StdRng::seed_from_u64(0x5341_4D50 ^ (*cursor as u64));

    // Each produced transaction may need to scan past drained accounts, so cap
    // the walk at one full ring per slot.
    let mut budget = count.saturating_mul(n).max(count);
    while plans.len() < count && budget > 0 {
        budget -= 1;
        let account = *cursor;
        *cursor = (*cursor + 1) % n;

        let Some(plan) = plan_account(
            account,
            n,
            accounts,
            value,
            nonces,
            chains,
            &mut planning_rng,
        ) else {
            continue;
        };
        plans.push(plan);
    }

    strategy.map_collect_vec(plans, |plan| prove_and_sign(accounts, plan))
}

/// Plans the next action for `account`: a transfer when its private balance
/// covers `value`, otherwise a fund when it still has public balance, else
/// `None` (drained — caller skips it).
fn plan_account(
    account: usize,
    n: usize,
    accounts: &[SpamAccount],
    value: NonZeroU64,
    nonces: &mut [u64],
    chains: &mut PrivateChains,
    rng: &mut StdRng,
) -> Option<PrivatePlan> {
    let input = chains.balances[account].commitment();

    if chains.balances[account].value() >= value.get() {
        let recipient =
            TransactionPublicKey::ed25519(accounts[(account + 1) % n].public_key.clone());
        let plan = chains.balances[account]
            .plan_transfer(value.get(), rng)
            .expect("private balance covers the transfer");
        let nonce = take_nonce(nonces, account);
        return Some(PrivatePlan::Transfer {
            account,
            nonce,
            recipient: AccountKey::from_public_key(&recipient),
            input,
            plan,
        });
    }

    if chains.public_remaining[account] >= value.get() {
        let fund = chains.public_remaining[account].min(value.get().saturating_mul(FUND_MULTIPLE));
        let fund = NonZeroU64::new(fund).expect("fund is at least `value`");
        chains.public_remaining[account] -= fund.get();
        chains.balances[account].fund(fund.get());
        let nonce = take_nonce(nonces, account);
        return Some(PrivatePlan::Fund {
            account,
            nonce,
            input,
            value: fund,
        });
    }

    None
}

fn take_nonce(nonces: &mut [u64], account: usize) -> u64 {
    let nonce = nonces[account];
    nonces[account] = nonce + 1;
    nonce
}

/// Simulates the proof (if any) and signs the planned transaction.
fn prove_and_sign(accounts: &[SpamAccount], plan: PrivatePlan) -> Tx {
    let account = match &plan {
        PrivatePlan::Fund { account, .. } | PrivatePlan::Transfer { account, .. } => *account,
    };
    let sender = &accounts[account];
    let sender_key = TransactionPublicKey::ed25519(sender.public_key.clone());

    let tx = match plan {
        PrivatePlan::Fund {
            nonce,
            input,
            value,
            ..
        } => Transaction::fund(sender_key, value, input, nonce),
        PrivatePlan::Transfer {
            nonce,
            recipient,
            input,
            plan,
            ..
        } => {
            // Per-item deterministic RNG: the simulator only samples blinding
            // for zero-knowledge, so any seed yields a verifying proof.
            let mut rng = StdRng::seed_from_u64(((account as u64) << 32) ^ nonce);
            let amount = plan.amount_commitment();
            let proof = plan.simulate(&mut rng);
            Transaction::private_transfer(sender_key, recipient, input, amount, proof, nonce)
        }
    };
    tx.seal_and_sign(
        &sender.private_key,
        TRANSACTION_NAMESPACE,
        &mut Sha256::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::generate_accounts;
    use commonware_parallel::Sequential;

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
        let min_tx_bytes = Transaction::<commonware_cryptography::sha256::Digest>::MIN_SIZE
            + constantinople_primitives::TransactionSignature::MIN_SIZE;
        let max_transactions = body.len() / min_tx_bytes;
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
            verify_transaction_batch::<Sha256, _>(
                &Sequential,
                TRANSACTION_NAMESPACE,
                &mut rng,
                &lazy_decoded,
            ),
            "batch signature verification should pass"
        );
    }

    /// Replays one account's transactions in order, asserting the commitment
    /// chain is consistent (each declared input equals the prior output) and
    /// every simulated proof verifies — exactly what the on-chain executor
    /// checks.
    fn assert_account_chain_valid(txs: &[&Tx]) {
        use constantinople_primitives::Payload;

        let mut expected = BalanceCommitment::zero();
        let mut saw_fund_first = false;
        for (index, tx) in txs.iter().enumerate() {
            match &tx.value().payload {
                Payload::Fund {
                    value,
                    sender_commitment,
                } => {
                    if index == 0 {
                        saw_fund_first = true;
                    }
                    assert_eq!(*sender_commitment, expected, "fund must chain");
                    expected = expected.add(&BalanceCommitment::commit(value.get()));
                }
                Payload::PrivateTransfer {
                    sender_commitment,
                    amount,
                    proof,
                    ..
                } => {
                    assert_eq!(*sender_commitment, expected, "transfer must chain");
                    assert!(
                        proof.verify_transfer(sender_commitment, amount),
                        "simulated proof must verify on-chain"
                    );
                    expected = expected.sub(amount);
                }
                _ => panic!("private mode emits only fund and private transfer"),
            }
        }
        assert!(saw_fund_first, "an account's first action funds it");
    }

    #[test]
    fn private_batches_chain_and_verify() {
        let accounts = generate_accounts(3, 1000);
        let value = NonZeroU64::new(2).unwrap();
        let mut nonces = vec![0; accounts.len()];
        let mut chains = PrivateChains::new(accounts.len(), 100);
        let mut cursor = 0;

        let txs = sign_batch_private(
            &Sequential,
            &accounts,
            value,
            &mut nonces,
            &mut chains,
            &mut cursor,
            9,
        );
        assert_eq!(txs.len(), 9);

        // The ring walks accounts round-robin, so account k owns txs k, k+3, ...
        for account in 0..accounts.len() {
            let account_txs: Vec<&Tx> = txs.iter().skip(account).step_by(3).collect();
            assert_account_chain_valid(&account_txs);
        }
    }

    #[test]
    fn private_chain_state_survives_batch_boundaries() {
        use constantinople_primitives::Payload;

        let accounts = generate_accounts(2, 1000);
        let value = NonZeroU64::new(1).unwrap();
        let mut nonces = vec![0; accounts.len()];
        let mut chains = PrivateChains::new(accounts.len(), 100);
        let mut cursor = 0;

        let first = sign_batch_private(
            &Sequential,
            &accounts,
            value,
            &mut nonces,
            &mut chains,
            &mut cursor,
            2,
        );
        let second = sign_batch_private(
            &Sequential,
            &accounts,
            value,
            &mut nonces,
            &mut chains,
            &mut cursor,
            2,
        );

        // Each account's first batch funds, the second transfers from the
        // funded commitment, and the chain stays consistent across batches.
        for account in 0..accounts.len() {
            let chained = [first[account].clone(), second[account].clone()];
            assert_account_chain_valid(&chained.iter().collect::<Vec<_>>());
            assert!(matches!(
                first[account].value().payload,
                Payload::Fund { .. }
            ));
            assert_eq!(second[account].value().nonce, 1);
        }
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
}
