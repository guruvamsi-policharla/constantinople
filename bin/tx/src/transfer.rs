use crate::shared::{
    build_signed_transaction_bytes, parse_address, parse_private_key, submit_transaction, tx_url,
};
use clap::Args as ClapArgs;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Hex-encoded ed25519 private key.
    #[arg(long)]
    key: String,
    /// Recipient address (hex).
    #[arg(long)]
    to: String,
    /// Amount to transfer.
    #[arg(long)]
    value: u64,
    /// Sender nonce.
    #[arg(long)]
    nonce: u64,
    /// Validator HTTP endpoint (e.g. http://localhost:8080).
    #[arg(long)]
    endpoint: String,
}

pub async fn run(args: Args) -> Result<(), String> {
    let key = parse_private_key(&args.key)?;
    let to = parse_address(&args.to)?;
    let client = reqwest::Client::new();
    let tx_bytes = build_signed_transaction_bytes(&key, to, args.value, args.nonce);
    let url = tx_url(&args.endpoint);

    println!("submitting to {url}...");
    let body = submit_transaction(&client, &args.endpoint, tx_bytes).await?;
    println!("included: {body}");
    Ok(())
}
