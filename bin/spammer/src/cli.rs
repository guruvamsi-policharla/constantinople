//! CLI definition.

use crate::config::{PrivateProofMode, Workload};
use std::path::PathBuf;

#[derive(Debug, clap::Parser)]
#[command(name = "constantinople-spammer")]
pub struct Cli {
    /// Path to the spammer config YAML (required for deployer mode, optional for local).
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Path to the deployer-generated hosts file.
    #[arg(long)]
    pub hosts: Option<PathBuf>,

    /// Relayer base URL for transaction submission.
    #[arg(long)]
    pub relayer_url: Option<String>,

    /// Independent target-leader streams to run in relayer mode.
    #[arg(long, default_value_t = 1)]
    pub relayer_submitters: usize,

    /// Fully signed local batches to keep ready per submitter.
    #[arg(long, default_value_t = crate::config::DEFAULT_PRESIGNED_BATCHES)]
    pub presigned_batches: usize,

    /// Hex-encoded primary validator keys used as exact relayer targets.
    #[arg(long, value_delimiter = ',')]
    pub relayer_targets: Vec<String>,

    /// Number of spam accounts per relayer submitter.
    #[arg(long, default_value_t = 10)]
    pub accounts: u32,

    /// Value to transfer per transaction (must be > 0 and <= 100).
    #[arg(long, default_value_t = 1)]
    pub value: u64,

    /// Seed offset for spam account keys (avoids collision with validator keys).
    #[arg(long, default_value_t = 1000)]
    pub seed_offset: u64,

    /// Number of async runtime worker threads.
    #[arg(long, default_value_t = crate::config::DEFAULT_WORKER_THREADS)]
    pub worker_threads: usize,

    /// Number of rayon threads for parallel signing.
    #[arg(long, default_value_t = crate::config::DEFAULT_RAYON_THREADS)]
    pub rayon_threads: usize,

    /// Fractional account-count jitter per submitted batch.
    ///
    /// `0.2` submits `accounts + rand(0..=floor(accounts * 0.2))` txs per
    /// batch. Must be in `0..=1`.
    #[arg(long, default_value_t = 0.0, value_parser = parse_accounts_jitter)]
    pub accounts_jitter: f64,

    /// Transaction workload to submit.
    #[arg(long, value_enum, default_value_t = Workload::Public)]
    pub workload: Workload,

    /// Independent private global-ring groups per relayer submitter.
    ///
    /// Only used for private workload. `--accounts` is the size of each group.
    #[arg(long, default_value_t = crate::config::DEFAULT_PRIVATE_GROUPS)]
    pub private_groups: usize,

    /// Proof mode for private transfers.
    #[arg(long, value_enum, default_value_t = PrivateProofMode::Real)]
    pub private_proof_mode: PrivateProofMode,
}

fn parse_accounts_jitter(value: &str) -> Result<f64, String> {
    let parsed = value
        .parse::<f64>()
        .map_err(|error| format!("invalid jitter: {error}"))?;
    if !(0.0..=1.0).contains(&parsed) {
        return Err("jitter must be between 0 and 1".to_string());
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use crate::config::{PrivateProofMode, Workload};
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn parses_relayer_invocation() {
        let cli = Cli::try_parse_from([
            "constantinople-spammer",
            "--relayer-url",
            "http://127.0.0.1:8084",
        ])
        .expect("relayer invocation should parse");

        assert_eq!(cli.relayer_url, Some("http://127.0.0.1:8084".to_string()));
        assert_eq!(cli.relayer_submitters, 1);
        assert_eq!(
            cli.presigned_batches,
            crate::config::DEFAULT_PRESIGNED_BATCHES
        );
        assert!(cli.relayer_targets.is_empty());
        assert!(cli.hosts.is_none());
        assert_eq!(cli.workload, Workload::Public);
        assert_eq!(cli.private_groups, crate::config::DEFAULT_PRIVATE_GROUPS);
        assert_eq!(cli.private_proof_mode, PrivateProofMode::Real);
        assert_eq!(cli.worker_threads, crate::config::DEFAULT_WORKER_THREADS);
    }

    #[test]
    fn parses_presigned_batches() {
        let cli = Cli::try_parse_from([
            "constantinople-spammer",
            "--relayer-url",
            "http://127.0.0.1:8084",
            "--presigned-batches",
            "32",
        ])
        .expect("relayer invocation should parse");

        assert_eq!(cli.presigned_batches, 32);
    }

    #[test]
    fn parses_relayer_submitters() {
        let cli = Cli::try_parse_from([
            "constantinople-spammer",
            "--relayer-url",
            "http://127.0.0.1:8084",
            "--relayer-submitters",
            "4",
        ])
        .expect("relayer invocation should parse");

        assert_eq!(cli.relayer_submitters, 4);
    }

    #[test]
    fn parses_relayer_targets() {
        let cli = Cli::try_parse_from([
            "constantinople-spammer",
            "--relayer-url",
            "http://127.0.0.1:8084",
            "--relayer-targets",
            "aa,bb",
        ])
        .expect("relayer invocation should parse");

        assert_eq!(cli.relayer_targets, vec!["aa", "bb"]);
    }

    #[test]
    fn parses_fractional_accounts_jitter() {
        let cli = Cli::try_parse_from([
            "constantinople-spammer",
            "--relayer-url",
            "http://127.0.0.1:8084",
            "--accounts-jitter",
            "0.25",
        ])
        .expect("relayer invocation should parse");

        assert_eq!(cli.accounts_jitter, 0.25);
    }

    #[test]
    fn parses_worker_threads() {
        let cli = Cli::try_parse_from([
            "constantinople-spammer",
            "--relayer-url",
            "http://127.0.0.1:8084",
            "--worker-threads",
            "6",
        ])
        .expect("relayer invocation should parse");

        assert_eq!(cli.worker_threads, 6);
    }

    #[test]
    fn parses_private_workload() {
        let cli = Cli::try_parse_from([
            "constantinople-spammer",
            "--relayer-url",
            "http://127.0.0.1:8084",
            "--workload",
            "private",
        ])
        .expect("relayer invocation should parse");

        assert_eq!(cli.workload, Workload::Private);
    }

    #[test]
    fn parses_private_groups() {
        let cli = Cli::try_parse_from([
            "constantinople-spammer",
            "--relayer-url",
            "http://127.0.0.1:8084",
            "--private-groups",
            "4",
        ])
        .expect("relayer invocation should parse");

        assert_eq!(cli.private_groups, 4);
    }

    #[test]
    fn parses_private_proof_mode() {
        let cli = Cli::try_parse_from([
            "constantinople-spammer",
            "--relayer-url",
            "http://127.0.0.1:8084",
            "--private-proof-mode",
            "simulated",
        ])
        .expect("relayer invocation should parse");

        assert_eq!(cli.private_proof_mode, PrivateProofMode::Simulated);
    }

    #[test]
    fn rejects_accounts_jitter_above_one() {
        let error = Cli::try_parse_from([
            "constantinople-spammer",
            "--relayer-url",
            "http://127.0.0.1:8084",
            "--accounts-jitter",
            "1.1",
        ])
        .expect_err("jitter above one should fail");

        assert!(error.to_string().contains("invalid value"));
    }

    #[test]
    fn parses_deployer_invocation() {
        let cli = Cli::try_parse_from([
            "constantinople-spammer",
            "--config",
            "spammer.yaml",
            "--hosts",
            "hosts.yaml",
        ])
        .expect("deployer invocation should parse");

        assert_eq!(cli.config, Some(PathBuf::from("spammer.yaml")));
        assert_eq!(cli.hosts, Some(PathBuf::from("hosts.yaml")));
        assert!(cli.relayer_url.is_none());
    }

    #[test]
    fn parses_config_only_for_deployer_mode() {
        let result = Cli::try_parse_from(["constantinople-spammer"]);
        assert!(result.is_ok());
    }
}
