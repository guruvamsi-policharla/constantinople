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

/// Fund-chunk multiple for a given salt, in `[1, FUND_MULTIPLE]`.
///
/// Fund transactions carry no randomness, so this is what makes a re-signed
/// fund differ in bytes from the failed one: the mempool caches batch status
/// by body hash and would answer a byte-identical resubmission from the cache
/// of its dropped predecessor without ever re-pooling it. Consecutive salts
/// yield distinct multiples (the cycle is `FUND_MULTIPLE` long, far past the
/// consecutive-failure halt threshold), so every resign produces fresh bytes
/// for any batch composition.
const fn fund_multiple(salt: u64) -> u64 {
    FUND_MULTIPLE - (salt % FUND_MULTIPLE)
}

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

/// Sender-side state delta captured for one private transaction.
///
/// The presigner runs ahead of on-chain confirmation, so when a batch's fate
/// diverges from the happy path (dropped, partially finalized, or lost to a
/// transport error) it must rewind its local nonce and commitment-chain state
/// to what is actually committed. Each meta records the sender's state on both
/// sides of its transaction so a batch can be unwound and confirmed
/// transactions selectively re-applied.
#[derive(Clone)]
pub struct TxMeta {
    pub account: usize,
    pub nonce: u64,
    /// Transaction digest string, matching the relayer's included/filtered
    /// status lists.
    pub digest: String,
    pub pre_balance: PrivateBalance,
    pub pre_public_remaining: u64,
    pub post_balance: PrivateBalance,
    pub post_public_remaining: u64,
}

/// Rollback metadata for one signed private batch: the ring cursor before
/// planning plus one [`TxMeta`] per transaction, in batch order.
#[derive(Clone)]
pub struct BatchMeta {
    pub pre_cursor: usize,
    pub txs: Vec<TxMeta>,
}

/// Unwinds every transaction in `meta`, newest first, restoring nonces and
/// private-side state to the instant before the batch was planned.
pub fn unwind_batch(meta: &BatchMeta, nonces: &mut [u64], chains: &mut PrivateChains) {
    for tx in meta.txs.iter().rev() {
        nonces[tx.account] = tx.nonce;
        chains.balances[tx.account] = tx.pre_balance.clone();
        chains.public_remaining[tx.account] = tx.pre_public_remaining;
    }
}

/// Re-applies the post-state of the transactions at `landed` (ascending
/// indices into `meta.txs`) after [`unwind_batch`], used when a subset of a
/// failed batch was confirmed on-chain.
pub fn replay_landed(
    meta: &BatchMeta,
    landed: &[usize],
    nonces: &mut [u64],
    chains: &mut PrivateChains,
) {
    for &index in landed {
        let tx = &meta.txs[index];
        nonces[tx.account] = tx.nonce + 1;
        chains.balances[tx.account] = tx.post_balance.clone();
        chains.public_remaining[tx.account] = tx.post_public_remaining;
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
/// `salt` perturbs the planning and proving randomness (transfer blinding)
/// and the fund chunk size ([`fund_multiple`]); rolling back and re-signing
/// with a new salt therefore yields different transaction bytes for every
/// batch composition, which matters because the mempool caches batch status
/// by body hash and would otherwise answer a byte-identical resubmission
/// from the cache.
///
/// May return fewer than `count` transactions if accounts have drained their
/// public and private balances. The returned [`BatchMeta`] carries the state
/// deltas needed to unwind the batch if it fails.
#[allow(clippy::too_many_arguments)]
pub fn sign_batch_private<St: Strategy>(
    strategy: &St,
    accounts: &[SpamAccount],
    value: NonZeroU64,
    nonces: &mut [u64],
    chains: &mut PrivateChains,
    cursor: &mut usize,
    count: usize,
    salt: u64,
) -> (Vec<Tx>, BatchMeta) {
    assert_eq!(accounts.len(), nonces.len(), "nonces must match accounts");
    assert_eq!(
        accounts.len(),
        chains.balances.len(),
        "chains must match accounts"
    );
    assert!(!accounts.is_empty(), "need at least one account");
    assert!(count > 0, "need at least one transaction");

    let n = accounts.len();
    let pre_cursor = *cursor;
    let mut plans = Vec::with_capacity(count);
    let mut deltas = Vec::with_capacity(count);
    let mut planning_rng =
        StdRng::seed_from_u64(0x5341_4D50 ^ (*cursor as u64) ^ salt.rotate_left(17));

    // Each produced transaction may need to scan past drained accounts, so cap
    // the walk at one full ring per slot.
    let mut budget = count.saturating_mul(n).max(count);
    while plans.len() < count && budget > 0 {
        budget -= 1;
        let account = *cursor;
        *cursor = (*cursor + 1) % n;

        let pre_balance = chains.balances[account].clone();
        let pre_public_remaining = chains.public_remaining[account];
        let Some(plan) = plan_account(
            account,
            n,
            accounts,
            value,
            nonces,
            chains,
            &mut planning_rng,
            salt,
        ) else {
            continue;
        };
        let nonce = match &plan {
            PrivatePlan::Fund { nonce, .. } | PrivatePlan::Transfer { nonce, .. } => *nonce,
        };
        deltas.push(TxMeta {
            account,
            nonce,
            digest: String::new(),
            pre_balance,
            pre_public_remaining,
            post_balance: chains.balances[account].clone(),
            post_public_remaining: chains.public_remaining[account],
        });
        plans.push(plan);
    }

    let txs = strategy.map_collect_vec(plans, |plan| prove_and_sign(accounts, plan, salt));
    for (delta, tx) in deltas.iter_mut().zip(txs.iter()) {
        delta.digest = tx.message_digest().to_string();
    }
    (
        txs,
        BatchMeta {
            pre_cursor,
            txs: deltas,
        },
    )
}

/// Plans the next action for `account`: a transfer when its private balance
/// covers `value`, otherwise a fund when it still has public balance, else
/// `None` (drained — caller skips it).
#[allow(clippy::too_many_arguments)]
fn plan_account(
    account: usize,
    n: usize,
    accounts: &[SpamAccount],
    value: NonZeroU64,
    nonces: &mut [u64],
    chains: &mut PrivateChains,
    rng: &mut StdRng,
    salt: u64,
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
        let fund =
            chains.public_remaining[account].min(value.get().saturating_mul(fund_multiple(salt)));
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
fn prove_and_sign(accounts: &[SpamAccount], plan: PrivatePlan, salt: u64) -> Tx {
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
            let mut rng =
                StdRng::seed_from_u64((((account as u64) << 32) ^ nonce) ^ salt.rotate_right(7));
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

        let (txs, _) = sign_batch_private(
            &Sequential,
            &accounts,
            value,
            &mut nonces,
            &mut chains,
            &mut cursor,
            9,
            0,
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

        let (first, _) = sign_batch_private(
            &Sequential,
            &accounts,
            value,
            &mut nonces,
            &mut chains,
            &mut cursor,
            2,
            0,
        );
        let (second, _) = sign_batch_private(
            &Sequential,
            &accounts,
            value,
            &mut nonces,
            &mut chains,
            &mut cursor,
            2,
            0,
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

    /// Snapshot of presigner state for equality comparison in rollback tests.
    fn state_fingerprint(
        nonces: &[u64],
        chains: &PrivateChains,
    ) -> Vec<(u64, PrivateBalance, u64)> {
        nonces
            .iter()
            .zip(chains.balances.iter())
            .zip(chains.public_remaining.iter())
            .map(|((nonce, balance), remaining)| (*nonce, balance.clone(), *remaining))
            .collect()
    }

    /// Unwinding signed batches newest-first restores the exact pre-signing
    /// state, and re-signing from it with the same salt is byte-identical.
    #[test]
    fn unwind_restores_state_and_resign_is_deterministic() {
        use commonware_codec::Encode;

        let accounts = generate_accounts(3, 1000);
        let value = NonZeroU64::new(2).unwrap();
        let mut nonces = vec![0; accounts.len()];
        let mut chains = PrivateChains::new(accounts.len(), 100);
        let mut cursor = 0;

        // Advance past the all-fund phase so batches contain transfers too.
        let (_, first_meta) = sign_batch_private(
            &Sequential,
            &accounts,
            value,
            &mut nonces,
            &mut chains,
            &mut cursor,
            3,
            0,
        );
        let checkpoint = state_fingerprint(&nonces, &chains);
        let checkpoint_cursor = cursor;

        let (second, second_meta) = sign_batch_private(
            &Sequential,
            &accounts,
            value,
            &mut nonces,
            &mut chains,
            &mut cursor,
            3,
            0,
        );
        let (_, third_meta) = sign_batch_private(
            &Sequential,
            &accounts,
            value,
            &mut nonces,
            &mut chains,
            &mut cursor,
            3,
            0,
        );

        // Unwind third then second, as the presigner does after a failure of
        // the second batch.
        unwind_batch(&third_meta, &mut nonces, &mut chains);
        unwind_batch(&second_meta, &mut nonces, &mut chains);
        cursor = second_meta.pre_cursor;
        assert_eq!(state_fingerprint(&nonces, &chains), checkpoint);
        assert_eq!(cursor, checkpoint_cursor);
        assert_eq!(first_meta.txs.len(), 3);

        // Same salt, same state: the resigned batch is byte-identical.
        let (resigned, _) = sign_batch_private(
            &Sequential,
            &accounts,
            value,
            &mut nonces,
            &mut chains,
            &mut cursor,
            3,
            0,
        );
        assert_eq!(second.encode(), resigned.encode());
    }

    /// After an unwind, replaying the landed subset advances exactly those
    /// senders, and the next batch chains correctly on the mixed state.
    #[test]
    fn replay_landed_advances_only_confirmed_transactions() {
        let accounts = generate_accounts(3, 1000);
        let value = NonZeroU64::new(2).unwrap();
        let mut nonces = vec![0; accounts.len()];
        let mut chains = PrivateChains::new(accounts.len(), 100);
        let mut cursor = 0;

        let (txs, meta) = sign_batch_private(
            &Sequential,
            &accounts,
            value,
            &mut nonces,
            &mut chains,
            &mut cursor,
            3,
            0,
        );
        assert_eq!(txs.len(), 3);

        // Suppose only the first two transactions landed.
        unwind_batch(&meta, &mut nonces, &mut chains);
        cursor = meta.pre_cursor;
        replay_landed(&meta, &[0, 1], &mut nonces, &mut chains);

        assert_eq!(nonces, vec![1, 1, 0]);
        assert_eq!(
            chains.balances[0].commitment().as_bytes(),
            meta.txs[0].post_balance.commitment().as_bytes()
        );
        assert_eq!(
            chains.balances[2].commitment().as_bytes(),
            meta.txs[2].pre_balance.commitment().as_bytes()
        );

        // The next batch must chain on the mixed state and stay valid from the
        // chain's perspective for each account.
        let (next, _) = sign_batch_private(
            &Sequential,
            &accounts,
            value,
            &mut nonces,
            &mut chains,
            &mut cursor,
            3,
            1,
        );
        assert_eq!(next.len(), 3);
        for account in 0..accounts.len() {
            let mut history: Vec<&Tx> = Vec::new();
            if account < 2 {
                history.push(&txs[account]);
            }
            history.push(&next[account]);
            assert_account_chain_valid(&history);
        }
    }

    /// A new salt changes the bytes of every batch composition: transfers
    /// via blinding, funds via the chunk size. Re-signed batches must never
    /// be byte-identical to a failed predecessor, because the mempool caches
    /// batch status by body hash and would answer the resubmission from the
    /// cache without re-pooling it.
    #[test]
    fn salt_changes_both_fund_and_transfer_bytes() {
        use commonware_codec::Encode;

        let accounts = generate_accounts(2, 1000);
        let value = NonZeroU64::new(2).unwrap();

        let sign_two_rounds = |salt: u64| {
            let mut nonces = vec![0; accounts.len()];
            let mut chains = PrivateChains::new(accounts.len(), 100);
            let mut cursor = 0;
            let (funds, _) = sign_batch_private(
                &Sequential,
                &accounts,
                value,
                &mut nonces,
                &mut chains,
                &mut cursor,
                2,
                salt,
            );
            let (transfers, _) = sign_batch_private(
                &Sequential,
                &accounts,
                value,
                &mut nonces,
                &mut chains,
                &mut cursor,
                2,
                salt,
            );
            (funds.encode(), transfers.encode())
        };

        let (funds_a, transfers_a) = sign_two_rounds(0);
        let (funds_b, transfers_b) = sign_two_rounds(1);
        assert_ne!(funds_a, funds_b, "fund chunk size must vary with salt");
        assert_ne!(
            transfers_a, transfers_b,
            "transfer blinding must vary with salt"
        );

        // Consecutive salts stay distinct across the whole halt window.
        let multiples: Vec<u64> = (0..super::FUND_MULTIPLE)
            .map(super::fund_multiple)
            .collect();
        let mut deduped = multiples.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(deduped.len(), multiples.len());
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
