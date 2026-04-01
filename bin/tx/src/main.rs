//! Transaction utility for Constantinople.

mod address;
mod keygen;
mod shared;
mod spam;
mod transfer;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "constantinople-tx")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Keygen(keygen::Args),
    Address(address::Args),
    Transfer(transfer::Args),
    Spam(spam::Args),
}

#[tokio::main]
async fn main() {
    let result = match Cli::parse().command {
        Command::Keygen(args) => keygen::run(args),
        Command::Address(args) => address::run(args),
        Command::Transfer(args) => transfer::run(args).await,
        Command::Spam(args) => spam::run(args).await,
    };

    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
