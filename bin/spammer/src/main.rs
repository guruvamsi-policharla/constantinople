//! Constantinople spam bot binary.
//!
//! Generates deterministic accounts and submits ring-transfer transactions to
//! the relayer in a continuous loop.
//!
//! Each target gets its own independent account set. A local signer keeps one
//! batch ready while the submitter has one batch in flight, hiding signing
//! latency without queueing multiple batches at a proposer.
//!
//! The spammer presigns from nonce zero with empty commitment chains, so it
//! requires a fresh chain: before submitting anything it waits for the
//! relayer's health endpoint and verifies that a sample of its accounts has
//! no committed on-chain state, refusing to start otherwise. In private mode
//! a failed batch is rolled back and re-signed from the last confirmed state
//! (see [`submitter`]) instead of silently desynchronizing the commitment
//! chains.

mod accounts;
mod chain_api;
mod cli;
mod config;
mod signer;
mod submitter;

use accounts::{SpamAccount, generate_accounts};
use chain_api::{ChainApi, is_pristine};
use clap::Parser;
use cli::Cli;
use commonware_cryptography::ed25519;
use commonware_runtime::{Runner as _, Supervisor as _, ThreadPooler as _, tokio::telemetry};
use commonware_utils::NZUsize;
use constantinople_primitives::DEFAULT_ACCOUNT_BALANCE;
use core::num::NonZeroU64;
use signer::{
    BatchMeta, PrivateChains, replay_landed, sign_batch, sign_batch_private, unwind_batch,
};
use std::{
    collections::VecDeque,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use submitter::{Envelope, Feedback, RelayerSubmitter, Stats};
use tokio::sync::mpsc;
use tracing::{error, info};

/// How long to wait for the relayer's `/health` endpoint at startup. The
/// deploy-generated mprocs setup launches the spammer alongside the
/// validators, so the relayer may need a while to come up.
const HEALTH_TIMEOUT: Duration = Duration::from_secs(120);

/// How long to wait for the relayer to attach state and answer account
/// lookups during the startup freshness check.
const STATE_READY_TIMEOUT: Duration = Duration::from_secs(120);

fn main() {
    let cli = Cli::parse();

    // Load config file if provided (deployer mode); CLI defaults are used otherwise.
    let (
        accounts_count,
        value,
        seed_offset,
        relayer_url,
        relayer_submitters,
        presigned_batches,
        primary_validators,
        rayon_threads,
        accounts_jitter,
        private,
    ) = if let Some(config_path) = &cli.config {
        let cfg = config::load_config(config_path);
        let relayer_submitters = if cfg.relayer_submitters == 0 {
            cfg.primary_validators.len().max(1)
        } else {
            cfg.relayer_submitters
        };
        (
            cfg.accounts,
            cfg.value,
            cfg.seed_offset,
            config::resolve_named_http_url(&cfg.relayer_url, cli.hosts.as_deref()),
            relayer_submitters,
            cfg.presigned_batches,
            if cfg.primary_validators.is_empty() {
                cli.relayer_targets.clone()
            } else {
                cfg.primary_validators
            },
            cfg.rayon_threads,
            cfg.accounts_jitter,
            cfg.private,
        )
    } else {
        (
            cli.accounts,
            cli.value,
            cli.seed_offset,
            cli.relayer_url
                .clone()
                .expect("provide --relayer-url or --config"),
            cli.relayer_submitters.max(1),
            cli.presigned_batches,
            cli.relayer_targets.clone(),
            cli.rayon_threads,
            cli.accounts_jitter,
            cli.private,
        )
    };
    assert!(
        (0.0..=1.0).contains(&accounts_jitter),
        "--accounts-jitter must be between 0 and 1"
    );
    assert!(presigned_batches > 0, "--presigned-batches must be > 0");

    // Validate parameters.
    assert!(accounts_count >= 2, "need at least 2 accounts for a ring");
    assert!(value > 0, "transfer value must be > 0");
    // The relayer's fanout path (no pinned target) returns best-effort
    // statuses while transactions may still sit in multiple leaders' pools;
    // commitment-chain rollback is only sound against the pinned
    // single-leader path, where the blocking response is authoritative.
    assert!(
        !private || !primary_validators.is_empty(),
        "--private requires --relayer-targets (pinned leader submission)"
    );
    assert!(
        value <= DEFAULT_ACCOUNT_BALANCE,
        "transfer value ({value}) must be <= DEFAULT_ACCOUNT_BALANCE ({DEFAULT_ACCOUNT_BALANCE})"
    );
    let value = NonZeroU64::new(value).expect("checked above");

    let runtime_cfg = commonware_runtime::tokio::Config::default();
    let runner = commonware_runtime::tokio::Runner::new(runtime_cfg);

    runner.start(|context| async move {
        // In deployer mode (--hosts), use JSON logs so Loki/Promtail can scrape them.
        let json_logs = cli.hosts.is_some();
        telemetry::init(
            context.child("telemetry"),
            telemetry::Logging {
                level: tracing::Level::INFO,
                json: json_logs,
            },
            None,
            None,
        );

        let strategy = context
            .create_strategy(NZUsize!(rayon_threads))
            .expect("failed to create parallel strategy");

        let config = RelayerModeConfig {
            relayer_url,
            accounts_count,
            value,
            seed_offset,
            accounts_jitter,
            relayer_submitters,
            presigned_batches,
            relayer_targets: primary_validators,
            private,
        };
        run_relayer_mode(config, strategy).await;
    });
}

struct RelayerModeConfig {
    relayer_url: String,
    accounts_count: u32,
    value: NonZeroU64,
    seed_offset: u64,
    accounts_jitter: f64,
    relayer_submitters: usize,
    presigned_batches: usize,
    relayer_targets: Vec<String>,
    private: bool,
}

async fn run_relayer_mode(
    config: RelayerModeConfig,
    strategy: impl commonware_parallel::Strategy + 'static,
) {
    let RelayerModeConfig {
        relayer_url,
        accounts_count,
        value,
        seed_offset,
        accounts_jitter,
        relayer_submitters,
        presigned_batches,
        relayer_targets,
        private,
    } = config;

    info!(
        submitters = relayer_submitters,
        accounts = accounts_count,
        value = value.get(),
        seed_offset,
        accounts_jitter,
        %relayer_url,
        presigned_batches,
        private,
        "starting spammer relayer mode"
    );

    // The deploy-generated mprocs setup launches everything at once, so the
    // relayer may not be listening yet. Submitting into the void would burn
    // presigned nonces and commitment chains, so gate on health first.
    let chain = ChainApi::new(&relayer_url);
    info!(%relayer_url, "waiting for relayer to become healthy");
    if let Err(reason) = chain.wait_for_health(HEALTH_TIMEOUT).await {
        error!(%reason, "relayer never became healthy, exiting");
        std::process::exit(1);
    }

    // Generate all account sets up front so chain freshness can be verified
    // before anything is signed or submitted.
    let submitters: Vec<(usize, Vec<SpamAccount>)> = (0..relayer_submitters)
        .map(|index| {
            let offset = seed_offset + (index as u64) * u64::from(accounts_count);
            (index, generate_accounts(accounts_count, offset))
        })
        .collect();
    let all_keys: Vec<ed25519::PublicKey> = submitters
        .iter()
        .flat_map(|(_, accounts)| accounts.iter().map(|account| account.public_key.clone()))
        .collect();
    if let Err(reason) = ensure_fresh_chain(&chain, all_keys).await {
        error!(%reason, "refusing to start");
        std::process::exit(1);
    }

    let stats = Arc::new(Stats::new());
    let start = Instant::now();

    // Submitters report completion (drained presigner or halt) so the
    // process can exit with a meaningful status instead of flat-lining.
    let (done_tx, mut done_rx) = mpsc::channel::<()>(relayer_submitters);
    for (index, accounts) in submitters {
        let account_offset = seed_offset + (index as u64) * u64::from(accounts_count);
        let keys: Arc<Vec<ed25519::PublicKey>> = Arc::new(
            accounts
                .iter()
                .map(|account| account.public_key.clone())
                .collect(),
        );
        let target = relayer_target_for(&relayer_targets, index);
        let submitter = RelayerSubmitter::new(
            relayer_url.clone(),
            stats.clone(),
            index,
            target,
            chain.clone(),
        );
        let (batches, feedback) = spawn_presigner(
            strategy.clone(),
            accounts,
            value,
            accounts_jitter,
            account_offset,
            presigned_batches,
            private,
            DEFAULT_ACCOUNT_BALANCE,
        );
        let done = done_tx.clone();
        tokio::spawn(async move {
            submitter.run(batches, feedback, keys).await;
            let _ = done.send(()).await;
        });
    }
    drop(done_tx);

    let mut remaining = relayer_submitters;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let finalized = stats.finalized.load(Ordering::Relaxed);
                let filtered = stats.filtered.load(Ordering::Relaxed);
                let dropped = stats.dropped.load(Ordering::Relaxed);
                let errors = stats.errors.load(Ordering::Relaxed);
                let halted = stats.halted.load(Ordering::Relaxed);
                let elapsed = start.elapsed().as_secs_f64();
                let tps = if elapsed > 0.0 {
                    finalized as f64 / elapsed
                } else {
                    0.0
                };
                info!(
                    finalized,
                    filtered,
                    dropped,
                    errors,
                    halted,
                    tps = format!("{tps:.0}"),
                    elapsed_s = format!("{elapsed:.1}"),
                    "progress"
                );
            }
            done = done_rx.recv() => {
                if done.is_some() {
                    remaining = remaining.saturating_sub(1);
                }
                // None means every submitter task ended (a panicked task
                // drops its sender without reporting).
                if done.is_none() || remaining == 0 {
                    let halted = stats.halted.load(Ordering::Relaxed);
                    info!(
                        finalized = stats.finalized.load(Ordering::Relaxed),
                        filtered = stats.filtered.load(Ordering::Relaxed),
                        dropped = stats.dropped.load(Ordering::Relaxed),
                        errors = stats.errors.load(Ordering::Relaxed),
                        halted,
                        elapsed_s = format!("{:.1}", start.elapsed().as_secs_f64()),
                        "all submitters finished"
                    );
                    std::process::exit(if halted > 0 { 1 } else { 0 });
                }
            }
        }
    }
}

/// Concurrent account-state lookups during the startup freshness check.
const FRESHNESS_CONCURRENCY: usize = 32;

/// Verifies that none of the spam accounts has committed on-chain state.
///
/// The spammer presigns from nonce zero with empty commitment chains, so a
/// chain that has already executed transactions for any of these accounts can
/// only reject what it signs — and committed private state is unrecoverable
/// anyway (the commitment openings lived in the previous process). Every
/// account is checked, not a sample: a previous run with an overlapping seed
/// range may have touched accounts anywhere in the ring, and one poisoned
/// account makes every batch containing it fail. Failing fast with a remedy
/// beats submitting garbage forever.
async fn ensure_fresh_chain(chain: &ChainApi, keys: Vec<ed25519::PublicKey>) -> Result<(), String> {
    // Wait for the relayer to attach its state database (503 until then).
    let deadline = tokio::time::Instant::now() + STATE_READY_TIMEOUT;
    let probe = keys.first().ok_or("no accounts to check")?;
    loop {
        match chain.account(probe).await {
            Ok(_) => break,
            Err(reason) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(format!(
                        "could not read account state from the relayer: {reason}"
                    ));
                }
                tokio::time::sleep(chain_api::POLL_INTERVAL).await;
            }
        }
    }

    let total = keys.len();
    let mut pending = keys.into_iter().enumerate();
    let mut join_set = tokio::task::JoinSet::new();
    loop {
        while join_set.len() < FRESHNESS_CONCURRENCY {
            let Some((index, key)) = pending.next() else {
                break;
            };
            let chain = chain.clone();
            join_set.spawn(async move {
                // Tolerate transient lookup failures within a small budget.
                let mut last_error = None;
                for _ in 0..5 {
                    match chain.account(&key).await {
                        Err(reason) => {
                            last_error = Some(reason);
                            tokio::time::sleep(chain_api::POLL_INTERVAL).await;
                        }
                        result => return (index, result),
                    }
                }
                (index, Err(last_error.expect("at least one attempt failed")))
            });
        }
        let Some(joined) = join_set.join_next().await else {
            break;
        };
        let (index, account) =
            joined.map_err(|reason| format!("account check failed: {reason}"))?;
        match account {
            Ok(None) => {}
            Ok(Some(info)) if is_pristine(&info) => {}
            Ok(Some(info)) => {
                return Err(format!(
                    "spam account {index} already has on-chain state (nonce base {}, balance {}): \
                     the spammer requires a fresh chain — wipe the validators' state directories \
                     (the deploy output dir) or use a seed range no prior run has touched",
                    info.nonce.base, info.balance,
                ));
            }
            Err(reason) => {
                return Err(format!("could not read account state: {reason}"));
            }
        }
    }
    info!(
        accounts = total,
        "verified spam accounts have no prior on-chain state"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn spawn_presigner<St>(
    strategy: St,
    accounts: Vec<SpamAccount>,
    value: NonZeroU64,
    accounts_jitter: f64,
    account_offset: u64,
    presigned_batches: usize,
    private: bool,
    starting_balance: u64,
) -> (mpsc::Receiver<Envelope>, mpsc::UnboundedSender<Feedback>)
where
    St: commonware_parallel::Strategy + Send + 'static,
{
    let (batch_tx, batch_rx) = mpsc::channel(presigned_batches);
    let (feedback_tx, mut feedback_rx) = mpsc::unbounded_channel();
    // Keep the synchronous producer and bounded-channel backpressure off Tokio
    // worker threads; `sign_batch` uses the shared Rayon strategy for CPU parallelism.
    tokio::task::spawn_blocking(move || {
        let mut rng = JitterRng::new(account_offset.wrapping_add(1));
        let mut nonces = vec![0; accounts.len()];
        let mut chains = PrivateChains::new(accounts.len(), starting_balance);
        let mut cursor = 0;
        let mut seq = 0u64;
        let mut epoch = 0u64;
        // Rollback metadata for every signed-but-unresolved batch, oldest
        // first. Entries are pruned as the submitter confirms batches and
        // consumed wholesale when one fails.
        let mut inflight: VecDeque<(u64, BatchMeta)> = VecDeque::new();

        loop {
            // Apply outcome reports before signing further ahead.
            while let Ok(feedback) = feedback_rx.try_recv() {
                apply_feedback(
                    feedback,
                    &mut inflight,
                    &mut nonces,
                    &mut chains,
                    &mut cursor,
                    &mut epoch,
                );
            }

            let batch_size = jittered_batch_size(accounts.len(), accounts_jitter, &mut rng);
            let envelope = if private {
                let (txs, meta) = sign_batch_private(
                    &strategy,
                    &accounts,
                    value,
                    &mut nonces,
                    &mut chains,
                    &mut cursor,
                    batch_size,
                    epoch,
                );
                if txs.is_empty() {
                    // Confirmed state is drained — but a still-unresolved
                    // batch may yet fail and roll balance back, so wait for
                    // the in-flight pipeline to settle before concluding.
                    if inflight.is_empty() {
                        info!(
                            batches = seq,
                            "all accounts drained their balances, presigner exiting"
                        );
                        return;
                    }
                    let Some(feedback) = feedback_rx.blocking_recv() else {
                        return;
                    };
                    apply_feedback(
                        feedback,
                        &mut inflight,
                        &mut nonces,
                        &mut chains,
                        &mut cursor,
                        &mut epoch,
                    );
                    continue;
                }
                inflight.push_back((seq, meta.clone()));
                Envelope {
                    seq,
                    epoch,
                    txs,
                    meta: Some(meta),
                }
            } else {
                let txs = sign_batch(
                    &strategy,
                    &accounts,
                    value,
                    &mut nonces,
                    &mut cursor,
                    batch_size,
                );
                Envelope {
                    seq,
                    epoch,
                    txs,
                    meta: None,
                }
            };
            if batch_tx.blocking_send(envelope).is_err() {
                return;
            }
            seq += 1;
        }
    });
    (batch_rx, feedback_tx)
}

/// Applies one submitter outcome report to the presigner's state.
///
/// `Resolved` prunes confirmed rollback metadata. `Failed` unwinds every
/// batch signed at or after the failed one (newest first, since each later
/// batch was built on state that never landed), re-applies the failed batch's
/// confirmed subset, and bumps the epoch so the submitter discards stale
/// presigned envelopes; the epoch also salts the next signing pass so the
/// re-signed bytes always differ from the failed body.
fn apply_feedback(
    feedback: Feedback,
    inflight: &mut VecDeque<(u64, BatchMeta)>,
    nonces: &mut [u64],
    chains: &mut PrivateChains,
    cursor: &mut usize,
    epoch: &mut u64,
) {
    match feedback {
        Feedback::Resolved { seq: resolved } => {
            while inflight
                .front()
                .is_some_and(|(signed, _)| *signed <= resolved)
            {
                inflight.pop_front();
            }
        }
        Feedback::Failed {
            seq: failed,
            landed,
        } => {
            while let Some((signed, meta)) = inflight.pop_back() {
                unwind_batch(&meta, nonces, chains);
                if signed == failed {
                    *cursor = meta.pre_cursor;
                    replay_landed(&meta, &landed, nonces, chains);
                    break;
                }
            }
            debug_assert!(inflight.is_empty(), "feedback arrives in order");
            inflight.clear();
            *epoch += 1;
        }
    }
}

fn jittered_batch_size(accounts: usize, accounts_jitter: f64, rng: &mut JitterRng) -> usize {
    let extra = max_extra_accounts(accounts, accounts_jitter);
    if extra == 0 {
        return accounts;
    }
    accounts.saturating_add(rng.range(0, extra))
}

fn max_extra_accounts(accounts: usize, accounts_jitter: f64) -> usize {
    (accounts as f64 * accounts_jitter).floor() as usize
}

fn relayer_target_for(targets: &[String], index: usize) -> Option<String> {
    if targets.is_empty() {
        return None;
    }

    targets.get(index % targets.len()).cloned()
}

/// Tiny inline xorshift64 used to jitter per-batch sizes. We don't pull
/// `rand` in here because we only need a few bits per submission and the
/// statistical quality of xorshift is more than sufficient for visual block
/// size variance.
struct JitterRng {
    state: u64,
}

impl JitterRng {
    /// `seed` of zero would lock the generator; we map it to a non-zero value.
    const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
        }
    }

    const fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Uniform integer in `lo..=hi` (inclusive). Caller must pass `lo <= hi`.
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        debug_assert!(lo <= hi);
        let span = (hi - lo) as u64 + 1;
        lo + (self.next_u64() % span) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::{
        JitterRng, jittered_batch_size, max_extra_accounts, relayer_target_for, spawn_presigner,
    };
    use crate::accounts::generate_accounts;
    use commonware_parallel::Sequential;
    use core::num::NonZeroU64;
    use std::time::Duration;

    /// `range` must hit both endpoints over enough draws and never escape them.
    #[test]
    fn jitter_rng_range_is_inclusive_and_bounded() {
        let mut rng = JitterRng::new(42);
        let mut hit_lo = false;
        let mut hit_hi = false;
        for _ in 0..2_000 {
            let v = rng.range(1, 5);
            assert!((1..=5).contains(&v));
            if v == 1 {
                hit_lo = true;
            }
            if v == 5 {
                hit_hi = true;
            }
        }
        assert!(hit_lo, "should sample the lower bound");
        assert!(hit_hi, "should sample the upper bound");
    }

    /// `range(lo, lo)` collapses to the constant `lo`.
    #[test]
    fn jitter_rng_range_collapses_when_lo_equals_hi() {
        let mut rng = JitterRng::new(7);
        for _ in 0..32 {
            assert_eq!(rng.range(3, 3), 3);
        }
    }

    #[test]
    fn max_extra_accounts_uses_fractional_jitter() {
        assert_eq!(max_extra_accounts(100, 0.0), 0);
        assert_eq!(max_extra_accounts(100, 0.25), 25);
        assert_eq!(max_extra_accounts(3, 0.5), 1);
        assert_eq!(max_extra_accounts(10, 1.0), 10);
    }

    #[test]
    fn jittered_batch_size_only_adds_transactions() {
        let mut rng = JitterRng::new(42);
        let mut saw_base = false;
        let mut saw_max = false;

        for _ in 0..2_000 {
            let size = jittered_batch_size(10, 0.5, &mut rng);
            assert!((10..=15).contains(&size));
            if size == 10 {
                saw_base = true;
            }
            if size == 15 {
                saw_max = true;
            }
        }

        assert!(saw_base, "should sample the base account count");
        assert!(saw_max, "should sample the upper jitter bound");
    }

    #[test]
    fn relayer_targets_are_selected_by_submitter_index() {
        let targets = vec!["primary-0".to_string(), "primary-1".to_string()];

        assert_eq!(
            relayer_target_for(&targets, 0).as_deref(),
            Some("primary-0")
        );
        assert_eq!(
            relayer_target_for(&targets, 1).as_deref(),
            Some("primary-1")
        );
        assert_eq!(
            relayer_target_for(&targets, 2).as_deref(),
            Some("primary-0")
        );
        assert!(relayer_target_for(&[], 0).is_none());
    }

    #[tokio::test]
    async fn presigner_keeps_one_batch_ready_without_unbounded_local_queue() {
        let accounts = generate_accounts(3, 1000);
        let value = NonZeroU64::new(1).expect("non-zero value");
        let presigned_batches = 4;
        let (mut batches, _feedback) = spawn_presigner(
            Sequential,
            accounts,
            value,
            0.0,
            1000,
            presigned_batches,
            false,
            constantinople_primitives::DEFAULT_ACCOUNT_BALANCE,
        );

        let first = batches.recv().await.expect("first batch should be signed");
        assert_eq!(batch_nonces(&first.txs), vec![0, 0, 0]);

        wait_for_presigned_batches(&batches, presigned_batches).await;
        assert_eq!(batches.len(), presigned_batches);

        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(batches.len(), presigned_batches);

        let second = batches.recv().await.expect("second batch should be ready");
        assert_eq!(batch_nonces(&second.txs), vec![1, 1, 1]);
    }

    /// A fully failed private batch is unwound — together with everything
    /// presigned after it — and re-signed against the confirmed state in a
    /// new epoch whose salt changes the bytes (the mempool caches batch
    /// status by body hash, so the resigned batch must not be
    /// byte-identical).
    #[tokio::test]
    async fn private_failed_batch_is_resigned_from_confirmed_state() {
        use commonware_codec::Encode;

        let accounts = generate_accounts(3, 2000);
        let value = NonZeroU64::new(2).expect("non-zero value");
        let (mut batches, feedback) =
            spawn_presigner(Sequential, accounts, value, 0.0, 2000, 4, true, 100);

        let first = batches.recv().await.expect("first batch");
        assert_eq!(first.epoch, 0);
        assert_eq!(batch_nonces(&first.txs), vec![0, 0, 0]);

        feedback
            .send(super::Feedback::Failed {
                seq: first.seq,
                landed: vec![],
            })
            .expect("presigner alive");
        let resigned = loop {
            let envelope = batches.recv().await.expect("envelope");
            if envelope.epoch == 1 {
                break envelope;
            }
        };
        assert_eq!(batch_nonces(&resigned.txs), vec![0, 0, 0]);
        assert_ne!(
            first.txs.encode(),
            resigned.txs.encode(),
            "resigned bytes must differ from the failed batch"
        );
    }

    /// A partially finalized batch re-applies the confirmed transactions:
    /// the landed account continues its chain (next action is a transfer
    /// with the next nonce) while the rest restart from scratch.
    #[tokio::test]
    async fn private_partial_failure_keeps_landed_transactions() {
        use constantinople_primitives::Payload;

        let accounts = generate_accounts(3, 2100);
        let value = NonZeroU64::new(2).expect("non-zero value");
        let (mut batches, feedback) =
            spawn_presigner(Sequential, accounts, value, 0.0, 2100, 4, true, 100);

        let first = batches.recv().await.expect("first batch");
        assert!(matches!(first.txs[0].value().payload, Payload::Fund { .. }));

        // Only the first transaction (account 0's fund) landed.
        feedback
            .send(super::Feedback::Failed {
                seq: first.seq,
                landed: vec![0],
            })
            .expect("presigner alive");
        let resigned = loop {
            let envelope = batches.recv().await.expect("envelope");
            if envelope.epoch == 1 {
                break envelope;
            }
        };

        // Ring restarts at account 0, which now transfers on top of its
        // confirmed fund; the other accounts re-fund from nonce zero.
        assert_eq!(batch_nonces(&resigned.txs), vec![1, 0, 0]);
        assert!(matches!(
            resigned.txs[0].value().payload,
            Payload::PrivateTransfer { .. }
        ));
        assert!(matches!(
            resigned.txs[1].value().payload,
            Payload::Fund { .. }
        ));
        assert!(matches!(
            resigned.txs[2].value().payload,
            Payload::Fund { .. }
        ));
    }

    /// When every account exhausts its public and private balance the
    /// presigner waits for the in-flight pipeline to settle, then closes the
    /// pipeline instead of emitting empty batches.
    #[tokio::test]
    async fn presigner_exits_cleanly_when_accounts_drain() {
        let accounts = generate_accounts(2, 3000);
        let value = NonZeroU64::new(1).expect("non-zero value");
        // Starting balance 1: each account funds once, transfers once, done.
        let (mut batches, feedback) =
            spawn_presigner(Sequential, accounts, value, 0.0, 3000, 4, true, 1);

        let mut total = 0;
        while let Some(envelope) = batches.recv().await {
            assert!(!envelope.txs.is_empty(), "no empty batches");
            total += envelope.txs.len();
            feedback
                .send(super::Feedback::Resolved { seq: envelope.seq })
                .expect("presigner alive");
        }
        assert_eq!(total, 4, "2 funds + 2 transfers, then a clean shutdown");
    }

    /// A drained presigner must not exit while a batch is unresolved: a late
    /// failure rolls balance back, and the freed balance is re-signed.
    #[tokio::test]
    async fn drained_presigner_waits_for_inflight_and_resigns_on_late_failure() {
        let accounts = generate_accounts(2, 3100);
        let value = NonZeroU64::new(1).expect("non-zero value");
        let (mut batches, feedback) =
            spawn_presigner(Sequential, accounts, value, 0.0, 3100, 4, true, 1);

        // Batch 0 (funds) resolves; batch 1 (transfers) fails entirely.
        let funds = batches.recv().await.expect("funds batch");
        feedback
            .send(super::Feedback::Resolved { seq: funds.seq })
            .expect("presigner alive");
        let transfers = batches.recv().await.expect("transfers batch");
        assert_eq!(batch_nonces(&transfers.txs), vec![1, 1]);
        feedback
            .send(super::Feedback::Failed {
                seq: transfers.seq,
                landed: vec![],
            })
            .expect("presigner alive");

        // The rolled-back balance is re-signed in the next epoch rather than
        // abandoned to a premature "drained" exit.
        let resigned = batches.recv().await.expect("re-signed transfers");
        assert_eq!(resigned.epoch, 1);
        assert_eq!(batch_nonces(&resigned.txs), vec![1, 1]);
        feedback
            .send(super::Feedback::Resolved { seq: resigned.seq })
            .expect("presigner alive");

        assert!(
            batches.recv().await.is_none(),
            "presigner exits once truly drained"
        );
    }

    async fn wait_for_presigned_batches(
        batches: &tokio::sync::mpsc::Receiver<super::Envelope>,
        expected: usize,
    ) {
        for _ in 0..50 {
            if batches.len() == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("presigner did not fill the local queue");
    }

    fn batch_nonces(batch: &[super::signer::Tx]) -> Vec<u64> {
        batch
            .iter()
            .map(|transaction| transaction.value().nonce)
            .collect()
    }
}
