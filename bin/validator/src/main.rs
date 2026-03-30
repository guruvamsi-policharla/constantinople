//! Constantinople validator binary.

mod cli;
mod config;
mod run;
mod setup;

use clap::Parser;

fn main() {
    match cli::Cli::parse() {
        cli::Cli::Setup(args) => setup::setup(args),
        cli::Cli::Run { config, mode } => run::run(config, mode),
    }
}
