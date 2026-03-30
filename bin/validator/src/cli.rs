//! CLI definition.

use std::path::PathBuf;
use tracing::Level;

#[derive(clap::Parser)]
#[command(name = "constantinople-validator")]
pub enum Cli {
    /// Generate TOML config files for a validator set.
    Setup(SetupArgs),
    /// Run a validator from a TOML config file.
    Run {
        /// Path to the validator TOML config.
        #[arg(long)]
        config: PathBuf,
        /// Startup mode: marshal-sync or state-sync.
        #[arg(long, value_enum, default_value_t = StartupArg::MarshalSync)]
        mode: StartupArg,
    },
}

#[derive(clap::Args)]
pub struct SetupArgs {
    /// Number of validators to generate.
    #[arg(long)]
    pub validators: u32,
    /// Directory to write config files into.
    #[arg(long)]
    pub output_dir: PathBuf,
    /// First validator's listen port (increments per validator).
    #[arg(long, default_value_t = 9000)]
    pub base_port: u16,
    /// Log level written into generated config files.
    #[arg(long, default_value_t = Level::INFO)]
    pub log_level: Level,
    /// Number of tokio worker threads for the runtime.
    #[arg(long, default_value_t = 2)]
    pub worker_threads: usize,
    /// First validator's HTTP port (increments per validator).
    #[arg(long, default_value_t = 8080)]
    pub base_http_port: u16,
    /// Path to a TOML file with genesis allocations.
    #[arg(long)]
    pub genesis: Option<PathBuf>,
}

#[derive(Clone, clap::ValueEnum)]
pub enum StartupArg {
    MarshalSync,
    StateSync,
}
