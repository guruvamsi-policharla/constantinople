use crate::spam;
use clap::ArgGroup;
use commonware_deployer::aws::Hosts;
use serde::Deserialize;
use std::{collections::HashMap, path::Path};

#[derive(Debug, clap::Parser)]
#[command(name = "constantinople-spammer")]
#[command(group(
    ArgGroup::new("network_source")
        .required(true)
        .args(["peers", "hosts"])
))]
pub struct Cli {
    /// Path to the spammer YAML config.
    #[arg(long)]
    pub config: std::path::PathBuf,
    /// Path to the local peer topology YAML file.
    #[arg(long, conflicts_with = "hosts")]
    pub peers: Option<std::path::PathBuf>,
    /// Path to the deployer-generated hosts file.
    #[arg(long, conflicts_with = "peers")]
    pub hosts: Option<std::path::PathBuf>,
}

#[derive(Debug, Deserialize)]
struct SpammerConfig {
    count: usize,
    validator_names: Vec<String>,
    http_port: u16,
    #[serde(default)]
    seed_start: u64,
    #[serde(default)]
    nonce: u64,
}

#[derive(Debug, Deserialize)]
struct PeerEntry {
    name: String,
    p2p: String,
    http: String,
}

#[derive(Debug, Deserialize)]
struct PeersFile {
    validators: Vec<PeerEntry>,
}

fn load_spammer_config(path: &Path) -> Result<SpammerConfig, String> {
    let raw =
        std::fs::read_to_string(path).map_err(|err| format!("failed to read config: {err}"))?;
    serde_yaml::from_str(&raw).map_err(|err| format!("failed to parse config: {err}"))
}

pub fn load_local_args(peers_path: &Path, config_path: &Path) -> Result<spam::Args, String> {
    let config = load_spammer_config(config_path)?;
    let raw_peers = std::fs::read_to_string(peers_path)
        .map_err(|err| format!("failed to read peers: {err}"))?;
    let peers: PeersFile =
        serde_yaml::from_str(&raw_peers).map_err(|err| format!("failed to parse peers: {err}"))?;
    let peers_by_name = peers
        .validators
        .into_iter()
        .map(|peer| {
            let _ = peer.p2p;
            (peer.name, peer.http)
        })
        .collect::<HashMap<_, _>>();

    let mut endpoints = Vec::with_capacity(config.validator_names.len());
    for name in &config.validator_names {
        let http = peers_by_name
            .get(name)
            .ok_or_else(|| format!("missing validator peer '{name}'"))?;
        endpoints.push(format!("http://{http}"));
    }

    spam::Args::new(config.count, endpoints, config.seed_start, config.nonce)
}

pub fn load_remote_args(hosts_path: &Path, config_path: &Path) -> Result<spam::Args, String> {
    let config = load_spammer_config(config_path)?;
    let raw_hosts = std::fs::read_to_string(hosts_path)
        .map_err(|err| format!("failed to read hosts: {err}"))?;
    let hosts: Hosts =
        serde_yaml::from_str(&raw_hosts).map_err(|err| format!("failed to parse hosts: {err}"))?;
    let hosts_by_name = hosts
        .hosts
        .into_iter()
        .map(|host| (host.name, host.ip))
        .collect::<HashMap<_, _>>();

    let mut endpoints = Vec::with_capacity(config.validator_names.len());
    for name in &config.validator_names {
        let ip = hosts_by_name
            .get(name)
            .ok_or_else(|| format!("missing validator host '{name}'"))?;
        endpoints.push(format!("http://{ip}:{}", config.http_port));
    }

    spam::Args::new(config.count, endpoints, config.seed_start, config.nonce)
}

#[cfg(test)]
mod tests {
    use super::{Cli, load_local_args, load_remote_args};
    use clap::Parser;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_path(prefix: &str, suffix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{unique}{suffix}"))
    }

    #[test]
    fn parses_local_spam_invocation() {
        let cli = Cli::try_parse_from([
            "constantinople-spammer",
            "--config",
            "spammer.yaml",
            "--peers",
            "peers.yaml",
        ])
        .expect("local spam invocation should parse");

        assert_eq!(cli.config, PathBuf::from("spammer.yaml"));
        assert_eq!(cli.peers, Some(PathBuf::from("peers.yaml")));
        assert!(cli.hosts.is_none());
    }

    #[test]
    fn parses_deployer_style_invocation() {
        let cli = Cli::try_parse_from([
            "constantinople-spammer",
            "--hosts",
            "hosts.yaml",
            "--config",
            "spammer.yaml",
        ])
        .expect("deployer invocation should parse");

        assert_eq!(cli.hosts, Some(PathBuf::from("hosts.yaml")));
        assert_eq!(cli.config, PathBuf::from("spammer.yaml"));
        assert!(cli.peers.is_none());
    }

    #[test]
    fn load_local_args_uses_validator_order_from_config() {
        let peers_path = temp_path("spammer-peers", ".yaml");
        let config_path = temp_path("spammer-config", ".yaml");

        fs::write(
            &peers_path,
            r#"validators:
  - name: "validator-b"
    p2p: "127.0.0.1:9001"
    http: "127.0.0.1:8081"
  - name: "validator-a"
    p2p: "127.0.0.1:9000"
    http: "127.0.0.1:8080"
"#,
        )
        .expect("failed to write peers");
        fs::write(
            &config_path,
            r#"count: 8
validator_names: ["validator-a", "validator-b"]
http_port: 8080
seed_start: 3
nonce: 9
"#,
        )
        .expect("failed to write config");

        let args = load_local_args(&peers_path, &config_path).expect("config should parse");

        assert_eq!(
            args.endpoints(),
            &["http://127.0.0.1:8080", "http://127.0.0.1:8081"]
        );
        assert_eq!(args.count().get(), 8);
        assert_eq!(args.seed_start(), 3);
        assert_eq!(args.nonce(), 9);

        let _ = fs::remove_file(peers_path);
        let _ = fs::remove_file(config_path);
    }

    #[test]
    fn load_remote_args_uses_validator_order_from_config() {
        let hosts_path = temp_path("hosts", ".yaml");
        let config_path = temp_path("spam", ".yaml");

        fs::write(
            &hosts_path,
            r#"monitoring: 10.0.0.1
hosts:
  - name: validator-b
    region: us-west-2
    ip: 203.0.113.2
  - name: validator-a
    region: us-east-1
    ip: 203.0.113.1
"#,
        )
        .expect("failed to write hosts");
        fs::write(
            &config_path,
            r#"count: 8
validator_names: ["validator-a", "validator-b"]
http_port: 8080
seed_start: 3
nonce: 9
"#,
        )
        .expect("failed to write config");

        let args = load_remote_args(&hosts_path, &config_path).expect("config should parse");

        assert_eq!(
            args.endpoints(),
            &["http://203.0.113.1:8080", "http://203.0.113.2:8080"]
        );
        assert_eq!(args.count().get(), 8);
        assert_eq!(args.seed_start(), 3);
        assert_eq!(args.nonce(), 9);

        let _ = fs::remove_file(hosts_path);
        let _ = fs::remove_file(config_path);
    }
}
