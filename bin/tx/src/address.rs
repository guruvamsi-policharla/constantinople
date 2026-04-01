use clap::Args as ClapArgs;
use commonware_codec::ReadExt;
use commonware_cryptography::{Sha256, ed25519};
use commonware_utils::{from_hex, hex};
use constantinople_primitives::Address;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Hex-encoded ed25519 public key.
    #[arg(long)]
    pubkey: String,
}

pub fn run(args: Args) -> Result<(), String> {
    let bytes = from_hex(&args.pubkey).ok_or_else(|| "bad pubkey hex".to_string())?;
    let pubkey = ed25519::PublicKey::read(&mut &bytes[..])
        .map_err(|_| "failed to decode public key".to_string())?;
    let address = Address::from_public_key(&mut Sha256::default(), &pubkey);
    println!("{}", hex(address.as_ref()));
    Ok(())
}
