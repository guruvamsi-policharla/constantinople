//! Transaction spammer for Constantinople.

mod config;
mod shared;
mod spam;

use clap::Parser;

#[tokio::main]
async fn main() {
    let cli = config::Cli::parse();

    let args = if let Some(hosts) = cli.hosts {
        match config::load_remote_args(&hosts, &cli.config) {
            Ok(args) => args,
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
    } else {
        let peers = cli.peers.expect("clap should require --peers or --hosts");
        match config::load_local_args(&peers, &cli.config) {
            Ok(args) => args,
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
    };

    if let Err(err) = spam::run(args).await {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
