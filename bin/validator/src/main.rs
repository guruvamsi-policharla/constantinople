//! Constantinople validator binary.

mod cli;
mod config;
mod run;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();
    if let Some(hosts) = cli.hosts {
        run::run_deployer(hosts, cli.config, cli.mode);
        return;
    }

    run::run_local(cli.config, cli.mode);
}
