//! CLI definition.

use std::path::PathBuf;

#[derive(Debug, clap::Parser)]
#[command(name = "constantinople-validator")]
pub struct Cli {
    /// Path to the validator TOML config.
    #[arg(long)]
    pub config: PathBuf,
    #[arg(long, hide = true)]
    pub hosts: Option<PathBuf>,
    /// Startup mode: marshal-sync or state-sync.
    #[arg(long, value_enum, default_value_t = StartupArg::MarshalSync)]
    pub mode: StartupArg,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum StartupArg {
    MarshalSync,
    StateSync,
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn parses_local_invocation() {
        let cli = Cli::try_parse_from(["constantinople", "--config", "validator.toml"])
            .expect("local invocation should parse");

        assert_eq!(cli.config, PathBuf::from("validator.toml"));
        assert!(cli.hosts.is_none());
    }

    #[test]
    fn parses_deployer_style_invocation() {
        let cli = Cli::try_parse_from([
            "constantinople",
            "--hosts",
            "hosts.yaml",
            "--config",
            "validator.toml",
        ])
        .expect("deployer invocation should parse");

        assert_eq!(cli.config, PathBuf::from("validator.toml"));
        assert_eq!(cli.hosts, Some(PathBuf::from("hosts.yaml")));
    }
}
