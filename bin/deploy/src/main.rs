//! Deployment generator for Constantinople.

mod local;
mod remote;

use clap::{Args, Parser, Subcommand};
use commonware_codec::{Encode, Read as CodecRead};
use commonware_cryptography::{
    Signer,
    bls12381::{
        dkg::feldman_desmedt as dkg,
        primitives::{group::Share, sharing::ModeVersion, variant::MinSig},
    },
    ed25519,
};
use commonware_formatting::{from_hex, hex};
use commonware_math::algebra::Random;
use commonware_utils::{N3f1, NZU32, TryCollect};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::Level;
use tracing_subscriber::fmt;

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

const STORAGE_CLASS: &str = "gp3";
/// Graviton4 instance type for the binary instances. Must stay on Graviton4 to
/// match the `neoverse-v2` graviton build target in `docker/docker-bake.hcl`; a
/// Graviton3 (c7g) type hits illegal instructions on startup.
const DEFAULT_INSTANCE_TYPE: &str = "c8g.4xlarge";
const DEFAULT_CHAIN_INDEXER_INSTANCE_TYPE: &str = "c8gb.4xlarge";
const DEFAULT_CHAIN_INDEXER_STORAGE_SIZE: i32 = 500;
const CHAIN_INDEXER_STORAGE_CLASS: &str = "io2";
const DEFAULT_CHAIN_INDEXER_STORAGE_IOPS: i32 = 16_000;
const EXOWARE_AVAILABILITY_ZONE_GROUP: &str = "exoware";
const DASHBOARD_FILE: &str = "dashboard.json";
const DEPLOYER_CONFIG_FILE: &str = "config.yaml";
const PEERS_CONFIG_FILE: &str = "peers.yaml";
const VALIDATOR_BINARY_FILE: &str = "validator";
const SPAMMER_BINARY_FILE: &str = "spammer";
const SPAMMER_CONFIG_FILE: &str = "spammer.yaml";
const CHAIN_INDEXER_BINARY_FILE: &str = "chain-indexer";
const CHAIN_INDEXER_CONFIG_FILE: &str = "chain-indexer.yaml";
const CHAIN_INDEXER_DATA_DIR: &str = "chain-indexer";
const CHAIN_INDEXER_HOST: &str = "chain-indexer";
const METADATA_INDEXER_BINARY_FILE: &str = "metadata-indexer";
const METADATA_INDEXER_CONFIG_FILE: &str = "metadata-indexer.yaml";
const METADATA_INDEXER_HOST: &str = "metadata-indexer";
const QMDB_INDEXER_BINARY_FILE: &str = "qmdb-indexer";
const QMDB_INDEXER_CONFIG_FILE: &str = "qmdb-indexer.yaml";
const QMDB_INDEXER_HOST: &str = "qmdb-indexer";
const SIMPLEX_VERIFICATION_MATERIAL_FILE: &str = "simplex-verification-material.hex";
const DEFAULT_CHAIN_INDEXER_PORT: u16 = 8090;
const DEFAULT_METADATA_INDEXER_PORT: u16 = 8091;
const DEFAULT_QMDB_INDEXER_PORT: u16 = 8092;
const DEFAULT_BOOTSTRAPPERS: usize = 3;
const INDEXER_UPLOAD_BUFFER: usize = 64;
const DEFAULT_SPAMMER_PRESIGNED_BATCHES: usize = 16;
const DEFAULT_SPAMMER_RAYON_THREADS: usize = 2;
const DEFAULT_PUBLIC_KEY_CACHE_SIZE: usize = 100_000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StartupModeConfig {
    #[default]
    MarshalSync,
    StateSync,
}

#[derive(Debug, Parser)]
#[command(name = "constantinople-deploy")]
struct Cli {
    /// Subcommand to run.
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Generate(Box<GenerateArgs>),
    SimplexVerificationMaterial(SimplexVerificationMaterialArgs),
}

#[derive(Debug, Args)]
struct SimplexVerificationMaterialArgs {
    /// Generated validator or secondary YAML containing `dkg_output`.
    #[arg(long)]
    config: PathBuf,
}

/// Transaction mix the generated spammer runs.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SpammerWorkload {
    #[default]
    Public,
    Private,
}

impl SpammerWorkload {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }
}

/// Proof mode for the generated spammer's private transfers.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SpammerProofMode {
    #[default]
    Real,
    Simulated,
}

impl SpammerProofMode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Real => "real",
            Self::Simulated => "simulated",
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct GenerateArgs {
    /// Number of primary (voting) validators.
    #[arg(long)]
    validators: u32,
    /// Include the full indexer secondary and shared indexer services.
    #[arg(long, default_value_t = false)]
    indexer: bool,
    /// Include a transaction relayer secondary.
    #[arg(long, default_value_t = false)]
    relayer: bool,
    /// Directory to write the generated deployment into.
    #[arg(long)]
    output_dir: PathBuf,
    /// Logging verbosity (e.g. info, debug, trace).
    #[arg(long, default_value = "info")]
    log_level: String,
    /// Tokio worker threads per validator runtime.
    #[arg(long, default_value_t = 2)]
    worker_threads: usize,
    /// Rayon threads per validator for parallel verification.
    #[arg(long, default_value_t = 2)]
    rayon_threads: usize,
    /// Capacity of each node's decompressed public key cache.
    #[arg(long, default_value_t = DEFAULT_PUBLIC_KEY_CACHE_SIZE)]
    public_key_cache_size: usize,
    /// Maximum bytes proposed per block (also the maximum accepted
    /// submission batch size).
    #[arg(long = "max-propose-bytes", default_value_t = default_max_propose_bytes())]
    max_propose_bytes: usize,
    /// Maximum mempool size in bytes.
    #[arg(long = "max-pool-bytes", default_value_t = default_max_pool_bytes())]
    max_pool_bytes: usize,
    /// Capacity in bytes of each validator's state QMDB page cache. Must
    /// hold the state journal's working set: 512 MiB thrashed once the live
    /// account set passed ~2M and build/verify doubled on cache misses.
    #[arg(long = "state-page-cache-bytes", default_value_t = default_page_cache_bytes())]
    state_page_cache_bytes: usize,
    /// Capacity in bytes of each validator's non-state page cache
    /// (archives, transaction history, journal).
    #[arg(long = "other-page-cache-bytes", default_value_t = default_page_cache_bytes())]
    other_page_cache_bytes: usize,
    /// Startup sync mode for the generated validators.
    #[arg(long, value_enum, default_value_t = StartupModeConfig::MarshalSync)]
    startup: StartupModeConfig,
    /// Maximum decoded consensus shard payload bytes accepted from peers.
    ///
    /// Defaults to a bound derived from `--max-propose-bytes` and the
    /// validator count: blocks split into `floor((validators - 1) / 3) + 1`
    /// data shards, so small clusters produce much larger shards than large
    /// ones. Explicit values below the derived bound are rejected — peers
    /// would drop every shard of a full block and consensus would wedge.
    #[arg(long = "max-shard-bytes")]
    max_shard_bytes: Option<usize>,

    /// Include a spammer instance in the deployment.
    #[arg(long, default_value_t = false)]
    spammer: bool,
    /// Number of spam accounts.
    ///
    /// Public workload: accounts per relayer submitter (defaults to 10).
    /// Private workload: total source accounts shared by all lanes. Left
    /// unset it is derived as 2x the in-flight transaction count; explicit
    /// values too small to fill every lane's batch are rejected rather than
    /// silently shrinking batches.
    #[arg(long)]
    spammer_accounts: Option<u32>,
    /// Transfer value per spam transaction.
    #[arg(long, default_value_t = 1)]
    spammer_value: u64,
    /// Seed offset for spam account keys.
    #[arg(long, default_value_t = 1000)]
    spammer_seed_offset: u64,
    /// Number of rayon threads for spammer parallel signing.
    #[arg(long, default_value_t = DEFAULT_SPAMMER_RAYON_THREADS)]
    spammer_rayon_threads: usize,
    /// Fractional account-count jitter per spammer batch.
    ///
    /// `0.2` submits `spammer_accounts + rand(0..=floor(spammer_accounts * 0.2))`
    /// txs per batch.
    #[arg(long, default_value_t = 0.0, value_parser = parse_accounts_jitter)]
    spammer_accounts_jitter: f64,
    /// Fully signed local batches to keep ready per spammer submitter.
    #[arg(long, default_value_t = DEFAULT_SPAMMER_PRESIGNED_BATCHES)]
    spammer_presigned_batches: usize,
    /// Transaction mix the spammer generates.
    #[arg(long, value_enum, default_value_t = SpammerWorkload::Public)]
    spammer_workload: SpammerWorkload,
    /// Proof mode for the spammer's private transfers.
    #[arg(long, value_enum, default_value_t = SpammerProofMode::Real)]
    spammer_private_proof_mode: SpammerProofMode,
    /// Private operations per submitted batch (private workload only).
    #[arg(long)]
    spammer_private_batch: Option<usize>,
    /// Concurrent private lanes per primary validator.
    ///
    /// The deployer multiplies this by `--validators` before writing the
    /// spammer config so private workload pressure scales with cluster size.
    #[arg(long)]
    spammer_private_lanes: Option<usize>,
    /// Target private transactions in flight across the whole cluster
    /// (private workload only).
    ///
    /// Each lane keeps one batch in flight and pins one leader, so a lane
    /// lands one batch per leader rotation: sustained TPS is roughly this
    /// target divided by the rotation period (validators x view time; ~4s at
    /// 50 validators and ~80ms views). Any of `--spammer-private-lanes`,
    /// `--spammer-private-batch`, and `--spammer-accounts` left unset are
    /// derived to satisfy the target; explicit values are respected and
    /// validated against it instead. The resolved plan is logged at generate
    /// time.
    #[arg(long)]
    spammer_target_inflight: Option<usize>,

    /// Deployment target (local or remote).
    #[command(subcommand)]
    target: GenerateTarget,
}

#[derive(Debug, Subcommand)]
#[expect(
    clippy::large_enum_variant,
    reason = "constructed once per invocation, so the size imbalance is harmless"
)]
enum GenerateTarget {
    Local(LocalArgs),
    Remote(RemoteArgs),
}

#[derive(Debug, Args)]
pub(crate) struct LocalArgs {
    /// Base p2p listen port; each validator is offset from this.
    #[arg(long, default_value_t = 9000)]
    base_port: u16,
    /// Base HTTP port; each validator is offset from this.
    #[arg(long, default_value_t = 8080)]
    base_http_port: u16,
    /// Base metrics port; each validator is offset from this.
    #[arg(long, default_value_t = 9090)]
    base_metrics_port: u16,
    /// Local `chain-indexer` Store port.
    #[arg(long = "chain-indexer-port", alias = "indexer-port", default_value_t = DEFAULT_CHAIN_INDEXER_PORT)]
    chain_indexer_port: u16,
    /// RocksDB parallelism for the local `chain-indexer` store. Omitted
    /// leaves RocksDB's stock parallelism.
    #[arg(long = "chain-indexer-db-parallelism")]
    chain_indexer_db_parallelism: Option<i32>,
    /// Local `metadata-indexer` read-service port.
    /// The explorer reads from this port via `VITE_SQL_URL`.
    #[arg(long = "metadata-indexer-port", alias = "sql-port", default_value_t = DEFAULT_METADATA_INDEXER_PORT)]
    metadata_indexer_port: u16,
    /// Local `qmdb-indexer` read-service port.
    #[arg(long = "qmdb-indexer-port", default_value_t = DEFAULT_QMDB_INDEXER_PORT)]
    qmdb_indexer_port: u16,
}

#[derive(Debug, Args)]
pub(crate) struct RemoteArgs {
    /// AWS regions to spread validators across (comma-separated).
    #[arg(long, value_delimiter = ',')]
    regions: Vec<String>,
    /// Graviton4 (c8g) instance type for validators, relayer, indexers, and
    /// spammer. Defaults to a Graviton4 type to match the `neoverse-v2` graviton
    /// build; do not use Graviton3 (c7g) — those binaries fault on startup.
    #[arg(long, default_value = DEFAULT_INSTANCE_TYPE)]
    instance_type: String,
    /// Validator EBS volume size in GiB.
    #[arg(long)]
    storage_size: i32,
    /// Provisioned IOPS for validator gp3 volumes (EBS default when unset).
    #[arg(long = "storage-iops")]
    storage_iops: Option<i32>,
    /// Provisioned throughput (MiB/s) for validator gp3 volumes (EBS default
    /// when unset). Validators write ~4x the raw block per view; the gp3
    /// default of 125 MiB/s throttles the cluster before either the NIC or
    /// consensus does.
    #[arg(long = "storage-throughput")]
    storage_throughput: Option<i32>,
    /// Instance type for the shared chain-indexer instance.
    #[arg(long = "chain-indexer-instance-type", default_value = DEFAULT_CHAIN_INDEXER_INSTANCE_TYPE)]
    chain_indexer_instance_type: String,
    /// Storage size (GiB) for the shared chain-indexer instance.
    #[arg(long = "chain-indexer-storage-size", default_value_t = DEFAULT_CHAIN_INDEXER_STORAGE_SIZE)]
    chain_indexer_storage_size: i32,
    /// Provisioned IOPS for the shared chain-indexer io2 volume.
    #[arg(long = "chain-indexer-storage-iops", default_value_t = DEFAULT_CHAIN_INDEXER_STORAGE_IOPS)]
    chain_indexer_storage_iops: i32,
    /// Graviton4 (c8g) instance type for the monitoring host (Grafana/Prometheus).
    #[arg(long, default_value = DEFAULT_INSTANCE_TYPE)]
    monitoring_instance_type: String,
    /// Monitoring instance EBS volume size in GiB.
    #[arg(long)]
    monitoring_storage_size: i32,
    /// Grafana dashboard JSON to provision on the monitoring instance.
    #[arg(long)]
    dashboard: PathBuf,
    /// Validator p2p listen port.
    #[arg(long, default_value_t = 9000)]
    listen_port: u16,
    /// Validator HTTP port.
    #[arg(long, default_value_t = 8080)]
    http_port: u16,
    /// CIDR ranges allowed to reach the validator HTTP port (comma-separated).
    #[arg(long = "http-cidr", value_delimiter = ',')]
    http_cidrs: Vec<String>,
    /// Shared `chain-indexer` Store port.
    #[arg(long = "chain-indexer-port", default_value_t = DEFAULT_CHAIN_INDEXER_PORT)]
    chain_indexer_port: u16,
    /// RocksDB parallelism for the shared `chain-indexer` store. Omitted
    /// leaves RocksDB's stock parallelism.
    #[arg(long = "chain-indexer-db-parallelism")]
    chain_indexer_db_parallelism: Option<i32>,
    /// Shared `metadata-indexer` query/stream port.
    #[arg(long = "metadata-indexer-port", default_value_t = DEFAULT_METADATA_INDEXER_PORT)]
    metadata_indexer_port: u16,
    /// Shared `qmdb-indexer` query facade port.
    #[arg(long = "qmdb-indexer-port", default_value_t = DEFAULT_QMDB_INDEXER_PORT)]
    qmdb_indexer_port: u16,
    /// Enable validator CPU profiling.
    #[arg(long, default_value_t = false)]
    profiling: bool,
    /// Trace sampling rate (0.0..=1.0) for validator uploads to the monitoring
    /// instance; 0.0 disables uploads.
    #[arg(long, default_value_t = 0.0, value_parser = parse_sampling_rate)]
    traces: f64,
    /// Instance type for the spammer (defaults to --instance-type).
    #[arg(long)]
    spammer_instance_type: Option<String>,
    /// Storage size (GiB) for the spammer instance.
    #[arg(long, default_value_t = 25)]
    spammer_storage_size: i32,
}

/// Spammer configuration, written as YAML by deploy and read by the spammer binary.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct SpammerConfig {
    /// Number of spam accounts per submitter.
    pub accounts: u32,
    /// Transfer value per spam transaction.
    pub value: u64,
    /// Seed offset for spam account keys.
    pub seed_offset: u64,
    /// Number of rayon threads used for parallel signing.
    #[serde(default = "default_spammer_rayon_threads")]
    pub rayon_threads: usize,
    /// Local HTTP port the spammer serves on.
    pub http_port: u16,
    /// Relayer URL used for transaction submission.
    pub relayer_url: String,
    /// Independent target-leader streams to run when submitting through a relayer.
    #[serde(default, skip_serializing_if = "usize_is_zero")]
    pub relayer_submitters: usize,
    /// Fully signed local batches to keep ready per submitter.
    #[serde(default = "default_spammer_presigned_batches")]
    pub presigned_batches: usize,
    /// Hex-encoded ed25519 public keys of primary (voting) validators.
    ///
    /// In `--hosts` mode the spammer cannot distinguish primaries from
    /// secondaries by host name alone — both use hex pubkeys. This list lets
    /// the spammer target only primaries.
    #[serde(default)]
    pub primary_validators: Vec<String>,
    /// Fractional account-count jitter per submitted batch.
    ///
    /// `0.2` submits `accounts + rand(0..=floor(accounts * 0.2))` txs per batch.
    #[serde(default)]
    pub accounts_jitter: f64,
    /// Transaction mix to submit.
    #[serde(default)]
    pub workload: SpammerWorkload,
    /// Proof mode for private transfers.
    #[serde(default)]
    pub private_proof_mode: SpammerProofMode,
    /// Private operations per submitted batch.
    #[serde(default = "default_spammer_private_batch")]
    pub private_batch: usize,
    /// Concurrent private lanes.
    #[serde(default = "default_spammer_private_lanes")]
    pub private_lanes: usize,
}

const fn default_spammer_private_batch() -> usize {
    64
}

const fn default_spammer_private_lanes() -> usize {
    8
}

/// Relayer configuration written into the relayer secondary's YAML.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct RelayerConfig {
    /// Per-leader relayer endpoints.
    pub leaders: Vec<RelayerLeaderConfig>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct RelayerLeaderConfig {
    /// Hex-encoded ed25519 public key of the target leader.
    pub public_key: String,
    /// Relayer URL for submitting to this leader.
    pub url: String,
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

fn parse_sampling_rate(value: &str) -> Result<f64, String> {
    let parsed = value
        .parse::<f64>()
        .map_err(|error| format!("invalid sampling rate: {error}"))?;
    if !(0.0..=1.0).contains(&parsed) {
        return Err("sampling rate must be between 0 and 1".to_string());
    }
    Ok(parsed)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct NamedBootstrapperEntry {
    /// Hex-encoded ed25519 public key of the bootstrapper.
    public_key: String,
    /// Host name used to resolve the bootstrapper's address.
    name: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ValidatorConfig {
    /// Hex-encoded ed25519 private key.
    private_key: String,
    /// Hex-encoded DKG output (threshold public material).
    dkg_output: String,
    /// Hex-encoded DKG share for this validator. Empty string `""` indicates
    /// a secondary (non-voting) validator that holds no share.
    dkg_share: String,
    /// Startup sync mode.
    startup: StartupModeConfig,
    /// p2p listen port.
    listen_port: u16,
    /// Hex-encoded ed25519 public key of the genesis leader.
    genesis_leader: String,
    /// Storage partition prefix for this validator.
    partition_prefix: String,
    /// Number of primary validators (DKG participant count).
    num_validators: u32,
    /// Hex-encoded ed25519 public keys of the primary (voting) validators,
    /// in DKG order. Must be identical across every validator config in the
    /// deployment so all peers agree on the discovery bitvec ordering.
    primary_validators: Vec<String>,
    /// Hex-encoded ed25519 public keys of the secondary (non-voting) validators.
    /// Must be identical across every validator config in the deployment.
    secondary_validators: Vec<String>,
    /// Logging verbosity.
    log_level: String,
    /// Tokio worker threads.
    worker_threads: usize,
    /// Rayon threads for parallel verification.
    rayon_threads: usize,
    /// HTTP service port.
    http_port: u16,
    /// Prometheus metrics port.
    metrics_port: u16,
    /// Maximum bytes proposed per block.
    max_propose_bytes: usize,
    /// Maximum mempool size in bytes.
    max_shard_bytes: usize,
    max_pool_bytes: usize,
    /// Capacity in bytes of the engine's state QMDB page cache.
    state_page_cache_bytes: usize,
    /// Capacity in bytes of the engine's non-state page cache (archives,
    /// transaction history, journal).
    other_page_cache_bytes: usize,
    /// Capacity of the decompressed public key cache.
    #[serde(default = "default_public_key_cache_size")]
    public_key_cache_size: usize,
    /// Trace sampling rate (0.0..=1.0); 0.0 disables uploads.
    #[serde(default)]
    traces: f64,
    /// Bootstrapper peers used for initial p2p discovery.
    bootstrappers: Vec<NamedBootstrapperEntry>,
    /// Optional indexer wiring. Set on secondary validators only when the
    /// local or remote deploy job enables the shared `chain-indexer` stack.
    /// Primaries always leave this unset; the validator runtime ignores it for
    /// primaries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    indexer: Option<IndexerConfig>,
    /// Optional relayer wiring for the generated relayer secondary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    relayer: Option<RelayerConfig>,
}

/// Indexer wiring serialized into a secondary validator's YAML.
///
/// Mirrors the schema in `bin/validator/src/config.rs::IndexerConfig`. The
/// shared `chain-indexer` store backs raw KV rows, SQL metadata rows, QMDB
/// operation logs, and simplex artifacts.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct IndexerConfig {
    /// URL of the shared chain-indexer store.
    pub chain_indexer_url: String,
    /// Number of blocks buffered before upload.
    pub upload_buffer: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ChainIndexerConfig {
    /// Store port the chain-indexer listens on.
    pub port: u16,
    /// Directory for chain-indexer data.
    pub data_dir: PathBuf,
    /// RocksDB parallelism (background compaction/flush jobs). Omitted
    /// leaves RocksDB's stock parallelism.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_parallelism: Option<i32>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct MetadataIndexerConfig {
    /// Read-service port the metadata-indexer listens on.
    pub port: u16,
    /// URL of the chain-indexer store to read from.
    pub chain_indexer_url: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct QmdbIndexerConfig {
    /// Query facade port the qmdb-indexer listens on.
    pub port: u16,
    /// URL of the chain-indexer store to read from.
    pub chain_indexer_url: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct PeerEntry {
    /// Host name (hex-encoded public key).
    name: String,
    /// p2p socket address.
    p2p: String,
    /// HTTP socket address.
    http: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct PeersConfig {
    /// Primary validator peers.
    pub validators: Vec<PeerEntry>,
    /// Secondary (non-voting) validator peers.
    #[serde(default)]
    pub secondaries: Vec<PeerEntry>,
}

#[derive(Debug, Deserialize)]
struct SimplexMaterialConfig {
    /// Hex-encoded DKG output.
    dkg_output: String,
    /// Number of primary validators.
    num_validators: u32,
}

pub(crate) struct ClusterMaterial {
    /// Primary (voting) validator private keys.
    pub signers: Vec<ed25519::PrivateKey>,
    /// Primary (voting) validator public keys, in DKG order.
    pub public_keys: Vec<ed25519::PublicKey>,
    /// Secondary (non-voting) validator private keys.
    pub secondary_signers: Vec<ed25519::PrivateKey>,
    /// Secondary (non-voting) validator public keys.
    pub secondary_public_keys: Vec<ed25519::PublicKey>,
    /// DKG output over the primary validators.
    pub dkg_output: dkg::Output<MinSig, ed25519::PublicKey>,
    /// DKG share per primary validator.
    pub shares: BTreeMap<ed25519::PublicKey, Share>,
    /// Hex-encoded genesis leader public key.
    pub genesis_leader: String,
}

impl ClusterMaterial {
    pub fn primary_hex(&self) -> Vec<String> {
        self.public_keys
            .iter()
            .map(|pk| hex(&pk.encode()))
            .collect()
    }

    pub fn secondary_hex(&self) -> Vec<String> {
        self.secondary_public_keys
            .iter()
            .map(|pk| hex(&pk.encode()))
            .collect()
    }

    pub fn simplex_verification_material_hex(&self) -> String {
        hex(&self.dkg_output.public().public().encode())
    }
}

const fn usize_is_zero(value: &usize) -> bool {
    *value == 0
}

const fn default_spammer_presigned_batches() -> usize {
    DEFAULT_SPAMMER_PRESIGNED_BATCHES
}

const fn default_spammer_rayon_threads() -> usize {
    DEFAULT_SPAMMER_RAYON_THREADS
}

fn main() {
    init_tracing();
    let cli = Cli::parse();

    match &cli.command {
        Command::Generate(args) => match &args.target {
            GenerateTarget::Local(local_args) => local::generate(args, local_args),
            GenerateTarget::Remote(remote_args) => remote::generate(args, remote_args),
        },
        Command::SimplexVerificationMaterial(args) => {
            println!(
                "{}",
                simplex_verification_material_from_config(&args.config)
            );
        }
    }
}

/// Secondary ed25519 seeds are drawn from this offset onward to guarantee
/// disjointness from the primary seed range (which uses raw validator indices).
const SECONDARY_SEED_OFFSET: u64 = 1_000_000;

fn init_tracing() {
    fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .without_time()
        .compact()
        .init();
}

pub(crate) fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }

    std::env::current_dir()
        .expect("failed to read current directory")
        .join(path)
}

pub(crate) fn ensure_output_dir_missing(output_dir: &Path) {
    if fs::metadata(output_dir).is_ok() {
        panic!("output directory already exists: {}", output_dir.display());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecondaryRole {
    Indexer,
    Relayer,
}

pub(crate) fn secondary_roles(args: &GenerateArgs) -> Vec<SecondaryRole> {
    let mut roles = Vec::with_capacity(args.indexer as usize + args.relayer as usize);
    if args.indexer {
        roles.push(SecondaryRole::Indexer);
    }
    if args.relayer {
        roles.push(SecondaryRole::Relayer);
    }
    roles
}

pub(crate) fn total_secondaries(args: &GenerateArgs) -> u32 {
    secondary_roles(args).len() as u32
}

pub(crate) const fn indexer_enabled(args: &GenerateArgs) -> bool {
    args.indexer
}

pub(crate) fn validate_generate_args(args: &GenerateArgs) {
    assert!(
        !args.spammer || args.relayer,
        "--spammer requires --relayer"
    );
    // Trigger the spammer sizing assertions before any files are written.
    let _ = resolve_spammer_plan(args);
    if let Some(max_shard_bytes) = args.max_shard_bytes {
        let bound = derived_shard_bound(args.max_propose_bytes, args.validators);
        assert!(
            max_shard_bytes >= bound,
            "--max-shard-bytes {max_shard_bytes} cannot carry a full \
             --max-propose-bytes {} block: {} validators split blocks into \
             {} data shards, so peers need to accept shards up to {bound} \
             bytes (raise --max-shard-bytes or lower --max-propose-bytes)",
            args.max_propose_bytes,
            args.validators,
            (args.validators.saturating_sub(1) as usize) / 3 + 1,
        );
    }
}

/// Conservative encoded size of one private transaction on the zkpari
/// backend (a transfer: 32 B output commitment + 192 B transfer proof plus
/// key/nonce/signature ≈ 365 B; funds are smaller). Deliberately not the
/// compile-time `Transaction::MAX_SIZE`: the deploy binary builds against the
/// mock backend, which would understate what a zkpari cluster sees.
const PRIVATE_TX_BYTES: usize = 512;

/// Source accounts provisioned per in-flight transaction slot when
/// `--spammer-accounts` is derived. Lanes skip exhausted or mid-retry sources
/// when filling a batch, so they need spare accounts to keep batches full.
const PRIVATE_ACCOUNTS_HEADROOM: u32 = 2;

/// Spam accounts per relayer submitter when `--spammer-accounts` is unset
/// (public workload).
const DEFAULT_SPAMMER_ACCOUNTS: u32 = 10;

/// Resolved spammer sizing shared by the local and remote generators.
pub(crate) struct SpammerPlan {
    /// Total spam accounts (public: per submitter; private: shared by lanes).
    pub accounts: u32,
    /// Private operations per submitted batch.
    pub private_batch: usize,
    /// Total private lanes across the cluster (per-validator lanes summed).
    pub total_private_lanes: usize,
    /// Private transactions in flight once every lane has a batch out.
    pub inflight: usize,
}

/// Resolves the spammer sizing knobs, deriving whatever the operator left
/// unset and rejecting combinations that would silently degrade (the
/// `--max-shard-bytes` philosophy: impossible explicit values are errors).
///
/// The private workload keeps one batch per lane in flight and fills each
/// batch with at most one operation per source account, so the knobs are
/// coupled: `validators x lanes x batch` is the in-flight count and accounts
/// must cover it. `--spammer-target-inflight` states the in-flight count
/// directly and lets this function do the division.
pub(crate) fn resolve_spammer_plan(args: &GenerateArgs) -> SpammerPlan {
    let validators = usize::try_from(args.validators).expect("validator count fits usize");
    assert!(validators > 0, "--validators must be > 0");
    let lanes_and_batch = |lanes: usize, batch: usize| {
        assert!(lanes > 0, "--spammer-private-lanes must be > 0");
        assert!(batch > 0, "--spammer-private-batch must be > 0");
        (lanes, batch)
    };

    if !matches!(args.spammer_workload, SpammerWorkload::Private) {
        assert!(
            args.spammer_target_inflight.is_none(),
            "--spammer-target-inflight only applies to --spammer-workload private"
        );
        let (lanes, batch) = lanes_and_batch(
            args.spammer_private_lanes
                .unwrap_or_else(default_spammer_private_lanes),
            args.spammer_private_batch
                .unwrap_or_else(default_spammer_private_batch),
        );
        return SpammerPlan {
            accounts: args.spammer_accounts.unwrap_or(DEFAULT_SPAMMER_ACCOUNTS),
            private_batch: batch,
            total_private_lanes: lanes
                .checked_mul(validators)
                .expect("--spammer-private-lanes * --validators must fit usize"),
            inflight: 0,
        };
    }

    let (lanes, batch) = match (
        args.spammer_private_lanes,
        args.spammer_private_batch,
        args.spammer_target_inflight,
    ) {
        (Some(lanes), Some(batch), Some(target)) => {
            let (lanes, batch) = lanes_and_batch(lanes, batch);
            let capacity = validators
                .checked_mul(lanes)
                .and_then(|lanes| lanes.checked_mul(batch))
                .expect("in-flight capacity fits usize");
            assert!(
                capacity >= target,
                "--spammer-private-lanes {lanes} x --spammer-private-batch {batch} \
                 across {validators} validators holds only {capacity} transactions \
                 in flight, below --spammer-target-inflight {target}; raise one of \
                 them or leave one unset to derive it"
            );
            (lanes, batch)
        }
        (Some(lanes), None, Some(target)) => {
            let (lanes, _) = lanes_and_batch(lanes, 1);
            (lanes, target.div_ceil(validators * lanes).max(1))
        }
        (None, Some(batch), Some(target)) => {
            let (_, batch) = lanes_and_batch(1, batch);
            (target.div_ceil(validators * batch).max(1), batch)
        }
        (None, None, Some(target)) => {
            // Split the target at the default batch size, then tighten the
            // batch so the overshoot stays below one batch per lane.
            let batch = default_spammer_private_batch();
            let lanes = target.div_ceil(validators * batch).max(1);
            (lanes, target.div_ceil(validators * lanes).max(1))
        }
        (lanes, batch, None) => lanes_and_batch(
            lanes.unwrap_or_else(default_spammer_private_lanes),
            batch.unwrap_or_else(default_spammer_private_batch),
        ),
    };

    let total_private_lanes = validators
        .checked_mul(lanes)
        .expect("--spammer-private-lanes * --validators must fit usize");
    let inflight = total_private_lanes
        .checked_mul(batch)
        .expect("in-flight transaction count fits usize");

    // One batch is also one relayer submission, which leaders bound by
    // `--max-propose-bytes`.
    let batch_bytes = batch
        .checked_mul(PRIVATE_TX_BYTES)
        .expect("batch byte size fits usize");
    assert!(
        batch_bytes <= args.max_propose_bytes,
        "--spammer-private-batch {batch} encodes to ~{batch_bytes} bytes per \
         submission, above --max-propose-bytes {}; lower the batch or raise \
         the propose limit",
        args.max_propose_bytes,
    );

    // Each in-flight transaction occupies its own source account (a batch
    // takes at most one operation per source).
    let floor = u32::try_from(inflight).expect("in-flight transaction count fits u32");
    let accounts = args.spammer_accounts.map_or_else(
        || {
            floor
                .checked_mul(PRIVATE_ACCOUNTS_HEADROOM)
                .expect("derived --spammer-accounts fits u32")
        },
        |accounts| {
            assert!(
                accounts >= floor,
                "--spammer-accounts {accounts} cannot fill {total_private_lanes} \
                 lanes x {batch}-transaction batches: each in-flight transaction \
                 needs its own source account ({floor} minimum, {} recommended); \
                 raise --spammer-accounts or leave it unset to derive it",
                floor.saturating_mul(PRIVATE_ACCOUNTS_HEADROOM),
            );
            accounts
        },
    );

    SpammerPlan {
        accounts,
        private_batch: batch,
        total_private_lanes,
        inflight,
    }
}

/// Logs the resolved private-workload sizing so derived values are
/// inspectable rather than implicit. No-op for the public workload.
pub(crate) fn log_spammer_plan(args: &GenerateArgs) {
    if !args.spammer || !matches!(args.spammer_workload, SpammerWorkload::Private) {
        return;
    }
    let plan = resolve_spammer_plan(args);

    // Runway: each source clears ~balance/value transfers plus one fund and
    // one rollover before it is exhausted. Mirrors the primitives crate's
    // DEFAULT_ACCOUNT_BALANCE (not imported to keep deploy off the privacy
    // backend dependency tree).
    const ACCOUNT_BALANCE: u64 = 1_000;
    let ops_per_account = ACCOUNT_BALANCE / args.spammer_value.max(1) + 2;
    let total_ops = u64::from(plan.accounts).saturating_mul(ops_per_account);
    // Assumes TPS ~= the in-flight count (a ~1s effective round-trip). Pinned
    // lanes on large clusters cycle once per leader rotation, which is
    // slower, so this is a floor on the actual runway.
    let est_runway_minutes = total_ops / (plan.inflight.max(1) as u64) / 60;

    tracing::info!(
        total_lanes = plan.total_private_lanes,
        batch = plan.private_batch,
        inflight = plan.inflight,
        accounts = plan.accounts,
        est_runway_minutes,
        "private spammer plan (sustained TPS ~= inflight / leader rotation seconds)"
    );

    // Lanes pin distinct leaders, so each leader's mempool sees roughly its
    // own lanes' share of the in-flight bytes.
    let validators = args.validators.max(1) as usize;
    let per_leader_bytes = plan.inflight / validators * PRIVATE_TX_BYTES;
    if per_leader_bytes > args.max_pool_bytes {
        tracing::warn!(
            per_leader_bytes,
            max_pool_bytes = args.max_pool_bytes,
            "in-flight private transactions may exceed each leader's mempool; \
             raise --max-pool-bytes or lower --spammer-target-inflight"
        );
    }
}

pub(crate) fn generate_local_cluster_material(
    validators: u32,
    secondaries: u32,
) -> ClusterMaterial {
    let signers = (0..validators)
        .map(|index| ed25519::PrivateKey::from_seed(index.into()))
        .collect::<Vec<_>>();
    let secondary_signers = (0..secondaries)
        .map(|index| ed25519::PrivateKey::from_seed(SECONDARY_SEED_OFFSET + u64::from(index)))
        .collect::<Vec<_>>();
    build_cluster_material(
        signers,
        secondary_signers,
        &mut commonware_utils::test_rng(),
    )
}

pub(crate) fn generate_remote_cluster_material(
    validators: u32,
    secondaries: u32,
) -> ClusterMaterial {
    let mut rng = UnwrapErr(SysRng);
    let mut signers = (0..validators)
        .map(|_| ed25519::PrivateKey::random(rng))
        .collect::<Vec<_>>();
    signers.sort_by_key(Signer::public_key);
    let mut secondary_signers = (0..secondaries)
        .map(|_| ed25519::PrivateKey::random(rng))
        .collect::<Vec<_>>();
    secondary_signers.sort_by_key(Signer::public_key);
    build_cluster_material(signers, secondary_signers, &mut rng)
}

fn build_cluster_material(
    signers: Vec<ed25519::PrivateKey>,
    secondary_signers: Vec<ed25519::PrivateKey>,
    rng: &mut impl rand::CryptoRng,
) -> ClusterMaterial {
    let public_keys = signers.iter().map(Signer::public_key).collect::<Vec<_>>();
    let secondary_public_keys = secondary_signers
        .iter()
        .map(Signer::public_key)
        .collect::<Vec<_>>();

    // DKG runs over primary validators only; secondaries hold ed25519 identities
    // but no threshold share. The resulting polynomial's total must equal the
    // primary count or `threshold_scheme` will panic at validator load.
    let participants = public_keys.clone().into_iter().try_collect().unwrap();
    let (dkg_output, raw_shares) =
        dkg::deal::<MinSig, _, N3f1>(rng, Default::default(), participants)
            .expect("DKG deal failed");
    let shares = raw_shares.into_iter().collect();
    let genesis_leader = hex(&public_keys[0].encode());

    ClusterMaterial {
        signers,
        public_keys,
        secondary_signers,
        secondary_public_keys,
        dkg_output,
        shares,
        genesis_leader,
    }
}

pub(crate) fn write_yaml_config<T: Serialize>(path: &Path, config: &T) {
    let raw = serde_yaml::to_string(config).expect("failed to serialize config");
    fs::write(path, raw).expect("failed to write config");
}

pub(crate) fn write_simplex_verification_material(output_dir: &Path, material: &ClusterMaterial) {
    fs::write(
        output_dir.join(SIMPLEX_VERIFICATION_MATERIAL_FILE),
        material.simplex_verification_material_hex(),
    )
    .expect("failed to write simplex verification material");
}

fn simplex_verification_material_from_config(config_path: &Path) -> String {
    let raw = fs::read_to_string(config_path).expect("failed to read validator config");
    let config: SimplexMaterialConfig =
        serde_yaml::from_str(&raw).expect("failed to parse validator config");
    let bytes = from_hex(&config.dkg_output).expect("bad dkg_output hex");
    let dkg_output = dkg::Output::<MinSig, ed25519::PublicKey>::read_cfg(
        &mut &bytes[..],
        &(NZU32!(config.num_validators), ModeVersion::v0()),
    )
    .expect("failed to decode dkg_output");
    hex(&dkg_output.public().public().encode())
}

pub(crate) fn default_bootstrappers(
    public_keys: &[ed25519::PublicKey],
) -> Vec<NamedBootstrapperEntry> {
    public_keys
        .iter()
        .take(DEFAULT_BOOTSTRAPPERS.min(public_keys.len()))
        .map(|public_key| {
            let name = hex(&public_key.encode());
            NamedBootstrapperEntry {
                public_key: name.clone(),
                name,
            }
        })
        .collect()
}

pub(crate) const fn default_max_propose_bytes() -> usize {
    8 * 1024 * 1024
}

pub(crate) const fn default_max_shard_bytes() -> usize {
    1024 * 1024
}

/// Largest shard a full proposal can produce for this cluster size, with
/// 25% headroom for chunk proofs and framing.
///
/// Mirrors the marshal's coding config: blocks split into
/// `max_faults + 1 = floor((validators - 1) / 3) + 1` data shards.
pub(crate) const fn derived_shard_bound(max_propose_bytes: usize, validators: u32) -> usize {
    let minimum_shards = (validators.saturating_sub(1) as usize) / 3 + 1;
    (max_propose_bytes.div_ceil(minimum_shards)) * 5 / 4
}

/// The shard limit written to node configs: the explicit `--max-shard-bytes`
/// when given, otherwise the derived bound (but never below the historical
/// 1 MiB default, which large clusters already run with).
pub(crate) fn resolved_max_shard_bytes(args: &GenerateArgs) -> usize {
    args.max_shard_bytes.unwrap_or_else(|| {
        derived_shard_bound(args.max_propose_bytes, args.validators).max(default_max_shard_bytes())
    })
}

pub(crate) const fn default_max_pool_bytes() -> usize {
    64 * 1024 * 1024
}

pub(crate) const fn default_page_cache_bytes() -> usize {
    2 * 1024 * 1024 * 1024
}

pub(crate) const fn default_public_key_cache_size() -> usize {
    DEFAULT_PUBLIC_KEY_CACHE_SIZE
}

pub(crate) fn generate_deployer_tag() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    let process_id = std::process::id();
    format!("{timestamp:x}-{process_id:x}")
}

#[cfg(test)]
mod tests {
    use super::{
        Cli, Command, GenerateTarget, SIMPLEX_VERIFICATION_MATERIAL_FILE,
        generate_local_cluster_material, simplex_verification_material_from_config,
        write_simplex_verification_material,
    };
    use clap::Parser;
    use commonware_codec::Encode;
    use commonware_formatting::hex;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn remote_parses_http_cidrs() {
        let cli = Cli::try_parse_from([
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
            "remote",
            "--regions",
            "us-east-1,us-west-2",
            "--instance-type",
            "c8g.large",
            "--storage-size",
            "25",
            "--monitoring-instance-type",
            "c8g.2xlarge",
            "--monitoring-storage-size",
            "100",
            "--dashboard",
            "dashboard.json",
            "--http-cidr",
            "10.0.0.0/8,198.51.100.4/32",
        ])
        .expect("remote invocation should parse");

        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };
        let generate = *generate;
        let GenerateTarget::Remote(remote) = generate.target else {
            panic!("expected remote target");
        };

        assert_eq!(
            remote.http_cidrs,
            vec!["10.0.0.0/8".to_string(), "198.51.100.4/32".to_string()]
        );
    }

    #[test]
    fn remote_parses_traces_sampling_rate() {
        let cli = Cli::try_parse_from([
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
            "remote",
            "--regions",
            "us-east-1,us-west-2",
            "--instance-type",
            "c8g.large",
            "--storage-size",
            "25",
            "--monitoring-instance-type",
            "c8g.2xlarge",
            "--monitoring-storage-size",
            "100",
            "--dashboard",
            "dashboard.json",
            "--http-cidr",
            "10.0.0.0/8",
            "--traces",
            "0.5",
        ])
        .expect("remote invocation should parse");

        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };
        let generate = *generate;
        let GenerateTarget::Remote(remote) = generate.target else {
            panic!("expected remote target");
        };
        assert_eq!(remote.traces, 0.5);
    }

    #[test]
    fn rejects_traces_sampling_rate_above_one() {
        let error = Cli::try_parse_from([
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
            "remote",
            "--regions",
            "us-east-1,us-west-2",
            "--instance-type",
            "c8g.large",
            "--storage-size",
            "25",
            "--monitoring-instance-type",
            "c8g.2xlarge",
            "--monitoring-storage-size",
            "100",
            "--dashboard",
            "dashboard.json",
            "--http-cidr",
            "10.0.0.0/8",
            "--traces",
            "1.5",
        ])
        .expect_err("sampling rate above one should fail");

        assert!(error.to_string().contains("invalid value"));
    }

    #[test]
    fn parses_max_propose_bytes() {
        let cli = Cli::try_parse_from([
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
            "--max-propose-bytes",
            "1150000",
            "local",
        ])
        .expect("local invocation should parse");

        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };
        let generate = *generate;
        assert_eq!(generate.max_propose_bytes, 1_150_000);
    }

    #[test]
    fn parses_max_shard_bytes() {
        let cli = Cli::try_parse_from([
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
            "--max-shard-bytes",
            "2097152",
            "local",
        ])
        .expect("local invocation should parse");

        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };
        let generate = *generate;
        assert_eq!(generate.max_shard_bytes, Some(2_097_152));
    }

    #[test]
    fn derives_shard_bound_from_cluster_size() {
        // 4 validators -> 2 data shards: an 8 MiB block needs ~5 MiB shards.
        assert_eq!(
            super::derived_shard_bound(8 * 1024 * 1024, 4),
            8 * 1024 * 1024 / 2 * 5 / 4
        );
        // 50 validators -> 17 data shards: well under the 1 MiB floor.
        assert!(super::derived_shard_bound(8 * 1024 * 1024, 50) < super::default_max_shard_bytes());
    }

    #[test]
    fn derived_shard_limit_never_drops_below_historical_default() {
        let mut args = generate_args_for_bounds(50);
        args.max_shard_bytes = None;
        assert_eq!(
            super::resolved_max_shard_bytes(&args),
            super::default_max_shard_bytes()
        );

        let args = generate_args_for_bounds(4);
        assert_eq!(
            super::resolved_max_shard_bytes(&args),
            super::derived_shard_bound(args.max_propose_bytes, 4)
        );
    }

    #[test]
    #[should_panic(expected = "cannot carry a full")]
    fn rejects_shard_limit_too_small_for_full_blocks() {
        let mut args = generate_args_for_bounds(4);
        // The historical 1 MiB default cannot carry 8 MiB blocks at 4
        // validators; explicit values must fail at generate time instead of
        // wedging consensus at the first full block.
        args.max_shard_bytes = Some(super::default_max_shard_bytes());
        super::validate_generate_args(&args);
    }

    fn generate_args_for_bounds(validators: u32) -> super::GenerateArgs {
        let cli = Cli::try_parse_from([
            "constantinople-deploy",
            "generate",
            "--validators",
            &validators.to_string(),
            "--output-dir",
            "out",
            "local",
        ])
        .expect("local invocation should parse");
        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };
        *generate
    }

    fn private_plan_args(validators: u32, extra: &[&str]) -> super::GenerateArgs {
        let validators = validators.to_string();
        let mut argv = vec![
            "constantinople-deploy",
            "generate",
            "--validators",
            &validators,
            "--output-dir",
            "out",
            "--relayer",
            "--spammer",
            "--spammer-workload",
            "private",
        ];
        argv.extend_from_slice(extra);
        argv.push("local");
        let cli = Cli::try_parse_from(argv).expect("private invocation should parse");
        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };
        *generate
    }

    #[test]
    fn target_inflight_derives_lanes_batch_and_accounts() {
        let args = private_plan_args(50, &["--spammer-target-inflight", "50000"]);
        let plan = super::resolve_spammer_plan(&args);

        // The plan must meet the target, overshooting by less than one
        // transaction per lane.
        assert!(plan.inflight >= 50_000);
        assert!(plan.inflight - 50_000 < plan.total_private_lanes);
        // Derived batches never exceed the default batch size.
        assert!(plan.private_batch <= 64);
        // Lanes stay a whole multiple of the validator count.
        assert_eq!(plan.total_private_lanes % 50, 0);
        // Accounts cover every in-flight slot with headroom.
        assert_eq!(plan.accounts as usize, plan.inflight * 2);
    }

    #[test]
    fn target_inflight_respects_explicit_lanes() {
        let args = private_plan_args(
            50,
            &[
                "--spammer-target-inflight",
                "50000",
                "--spammer-private-lanes",
                "10",
            ],
        );
        let plan = super::resolve_spammer_plan(&args);

        assert_eq!(plan.total_private_lanes, 500);
        assert_eq!(plan.private_batch, 100);
        assert_eq!(plan.inflight, 50_000);
    }

    #[test]
    fn private_defaults_hold_without_target() {
        let args = private_plan_args(2, &[]);
        let plan = super::resolve_spammer_plan(&args);

        assert_eq!(plan.total_private_lanes, 16);
        assert_eq!(plan.private_batch, 64);
        assert_eq!(plan.inflight, 1024);
        assert_eq!(plan.accounts, 2048);
    }

    #[test]
    fn public_workload_keeps_legacy_defaults() {
        let args = generate_args_for_bounds(4);
        let plan = super::resolve_spammer_plan(&args);

        assert_eq!(plan.accounts, 10);
        assert_eq!(plan.private_batch, 64);
        assert_eq!(plan.total_private_lanes, 32);
    }

    #[test]
    #[should_panic(expected = "only applies to --spammer-workload private")]
    fn rejects_target_inflight_for_public_workload() {
        let mut args = generate_args_for_bounds(4);
        args.spammer_target_inflight = Some(1000);
        super::resolve_spammer_plan(&args);
    }

    #[test]
    #[should_panic(expected = "needs its own source account")]
    fn rejects_accounts_below_lane_capacity() {
        // 2 validators x 8 lanes x 64 batch = 1024 in-flight slots; 100
        // accounts used to silently shrink batches, now it fails.
        let args = private_plan_args(2, &["--spammer-accounts", "100"]);
        super::resolve_spammer_plan(&args);
    }

    #[test]
    #[should_panic(expected = "below --spammer-target-inflight")]
    fn rejects_explicit_sizing_below_target() {
        let args = private_plan_args(
            2,
            &[
                "--spammer-target-inflight",
                "1000",
                "--spammer-private-lanes",
                "1",
                "--spammer-private-batch",
                "1",
            ],
        );
        super::resolve_spammer_plan(&args);
    }

    #[test]
    #[should_panic(expected = "above --max-propose-bytes")]
    fn rejects_batch_larger_than_a_proposal() {
        // 20000 txs x 512 B > the default 8 MiB propose/submission limit.
        let args = private_plan_args(1, &["--spammer-private-batch", "20000"]);
        super::resolve_spammer_plan(&args);
    }

    #[test]
    fn parses_fractional_spammer_accounts_jitter() {
        let cli = Cli::try_parse_from([
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
            "--spammer-accounts-jitter",
            "0.25",
            "local",
        ])
        .expect("local invocation should parse");

        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };
        let generate = *generate;
        assert_eq!(generate.spammer_accounts_jitter, 0.25);
    }

    #[test]
    fn parses_spammer_presigned_batches() {
        let cli = Cli::try_parse_from([
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
            "--spammer-presigned-batches",
            "32",
            "local",
        ])
        .expect("local invocation should parse");

        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };
        let generate = *generate;
        assert_eq!(generate.spammer_presigned_batches, 32);
    }

    #[test]
    fn parses_spammer_rayon_threads() {
        let cli = Cli::try_parse_from([
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
            "--spammer-rayon-threads",
            "6",
            "local",
        ])
        .expect("local invocation should parse");

        let Command::Generate(generate) = cli.command else {
            panic!("expected generate command");
        };
        let generate = *generate;
        assert_eq!(generate.spammer_rayon_threads, 6);
    }

    #[test]
    fn rejects_spammer_accounts_jitter_above_one() {
        let error = Cli::try_parse_from([
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--output-dir",
            "out",
            "--spammer-accounts-jitter",
            "1.1",
            "local",
        ])
        .expect_err("jitter above one should fail");

        assert!(error.to_string().contains("invalid value"));
    }

    #[test]
    fn writes_simplex_verification_material() {
        let material = generate_local_cluster_material(4, 1);
        let output_dir = unique_temp_dir("simplex-verification-material");
        fs::create_dir_all(&output_dir).expect("failed to create temp dir");

        write_simplex_verification_material(&output_dir, &material);

        let path = output_dir.join(SIMPLEX_VERIFICATION_MATERIAL_FILE);
        let written = fs::read_to_string(&path).expect("failed to read material");
        assert_eq!(written, material.simplex_verification_material_hex());

        fs::remove_file(path).expect("failed to remove material");
        fs::remove_dir(output_dir).expect("failed to remove temp dir");
    }

    #[test]
    fn extracts_simplex_verification_material_from_config() {
        let material = generate_local_cluster_material(4, 1);
        let output_dir = unique_temp_dir("extract-simplex-verification-material");
        fs::create_dir_all(&output_dir).expect("failed to create temp dir");
        let config_path = output_dir.join("validator.yaml");
        fs::write(
            &config_path,
            format!(
                "dkg_output: {}\nnum_validators: 4\n",
                hex(&material.dkg_output.encode())
            ),
        )
        .expect("failed to write config");

        let extracted = simplex_verification_material_from_config(&config_path);

        assert_eq!(extracted, material.simplex_verification_material_hex());

        fs::remove_file(config_path).expect("failed to remove config");
        fs::remove_dir(output_dir).expect("failed to remove temp dir");
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "constantinople-deploy-{name}-{}-{nanos}",
            std::process::id()
        ))
    }
}
