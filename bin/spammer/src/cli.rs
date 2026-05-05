//! CLI definition.

use clap::ArgGroup;
use std::path::PathBuf;

#[derive(Debug, clap::Parser)]
#[command(name = "constantinople-spammer")]
#[command(group(
    ArgGroup::new("network_source")
        .args(["relayer_url", "peers", "hosts"])
))]
pub struct Cli {
    /// Path to the spammer config YAML (required for deployer mode, optional for local).
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Path to the local peer topology YAML file.
    #[arg(long, conflicts_with_all = ["hosts", "relayer_url"])]
    pub peers: Option<PathBuf>,

    /// Path to the deployer-generated hosts file.
    #[arg(long, conflicts_with_all = ["peers", "relayer_url"])]
    pub hosts: Option<PathBuf>,

    /// Relayer base URL for normal single-endpoint submission.
    #[arg(long, conflicts_with_all = ["peers", "hosts"])]
    pub relayer_url: Option<String>,

    /// Independent nonce-ordered streams to run in relayer mode.
    #[arg(long, default_value_t = 1)]
    pub relayer_submitters: usize,

    /// Hex-encoded primary validator keys used as exact relayer targets.
    #[arg(long, value_delimiter = ',')]
    pub relayer_targets: Vec<String>,

    /// Number of spam accounts per validator in the ring transfer.
    #[arg(long, default_value_t = 10)]
    pub accounts: u32,

    /// Value to transfer per transaction (must be > 0 and <= 100).
    #[arg(long, default_value_t = 1)]
    pub value: u64,

    /// Seed offset for spam account keys (avoids collision with validator keys).
    #[arg(long, default_value_t = 1000)]
    pub seed_offset: u64,

    /// HTTP port for validators (only used in --hosts mode).
    #[arg(long, default_value_t = 8080)]
    pub http_port: u16,

    /// Number of rayon threads for parallel signing.
    #[arg(long, default_value_t = 2)]
    pub rayon_threads: usize,

    /// Fractional account-count jitter per submitted batch.
    ///
    /// `0.2` submits `accounts + rand(0..=floor(accounts * 0.2))` txs per
    /// batch. Must be in `0..=1`.
    #[arg(long, default_value_t = 0.0, value_parser = parse_accounts_jitter)]
    pub accounts_jitter: f64,
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
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn parses_local_invocation() {
        let cli = Cli::try_parse_from([
            "constantinople-spammer",
            "--peers",
            "peers.yaml",
            "--accounts",
            "20",
        ])
        .expect("local invocation should parse");

        assert_eq!(cli.peers, Some(PathBuf::from("peers.yaml")));
        assert!(cli.hosts.is_none());
        assert!(cli.config.is_none());
        assert_eq!(cli.accounts, 20);
    }

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
        assert!(cli.relayer_targets.is_empty());
        assert!(cli.peers.is_none());
        assert!(cli.hosts.is_none());
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
            "--peers",
            "peers.yaml",
            "--accounts-jitter",
            "0.25",
        ])
        .expect("local invocation should parse");

        assert_eq!(cli.accounts_jitter, 0.25);
    }

    #[test]
    fn rejects_accounts_jitter_above_one() {
        let error = Cli::try_parse_from([
            "constantinople-spammer",
            "--peers",
            "peers.yaml",
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
        assert!(cli.peers.is_none());
    }

    #[test]
    fn rejects_both_peers_and_hosts() {
        let result = Cli::try_parse_from([
            "constantinople-spammer",
            "--peers",
            "peers.yaml",
            "--hosts",
            "hosts.yaml",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn parses_config_only_for_deployer_mode() {
        let result = Cli::try_parse_from(["constantinople-spammer"]);
        assert!(result.is_ok());
    }
}
