use clap::Args as ClapArgs;
use commonware_codec::Encode;
use commonware_cryptography::{Sha256, Signer, ed25519};
use commonware_utils::hex;
use constantinople_primitives::Address;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Integer seed for deterministic key generation.
    #[arg(long)]
    seed: u64,
}

pub fn run(args: Args) -> Result<(), String> {
    let key = ed25519::PrivateKey::from_seed(args.seed);
    let pubkey = key.public_key();
    let address = Address::from_public_key(&mut Sha256::default(), &pubkey);
    println!("private_key: {}", hex(&key.encode()));
    println!("public_key:  {}", hex(&pubkey.encode()));
    println!("address:     {}", hex(address.as_ref()));
    Ok(())
}
