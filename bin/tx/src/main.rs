//! Transaction utility for Constantinople.

use clap::Parser;
use commonware_codec::{Encode, ReadExt};
use commonware_cryptography::{Hasher, Sha256, Signer, ed25519};
use commonware_utils::{from_hex, hex};
use constantinople_primitives::{Address, Signable, Transaction};
use std::{
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
};
use tokio::task::JoinSet;

const TX_NAMESPACE: &[u8] = b"constantinople-tx";

type Digest = <Sha256 as Hasher>::Digest;

#[derive(Parser)]
#[command(name = "constantinople-tx")]
enum Cli {
    /// Generate an ed25519 keypair from a seed.
    Keygen {
        /// Integer seed for deterministic key generation.
        #[arg(long)]
        seed: u64,
    },
    /// Derive the address for a public key.
    Address {
        /// Hex-encoded ed25519 public key.
        #[arg(long)]
        pubkey: String,
    },
    /// Build, sign, and send a transfer transaction.
    Transfer {
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
    },
    /// Build a ring of accounts and submit one transfer from each in parallel.
    Spam {
        /// Number of accounts to create.
        #[arg(long)]
        count: NonZeroUsize,
        /// Validator HTTP endpoint (e.g. http://localhost:8080).
        #[arg(long)]
        endpoint: String,
        /// Starting seed for deterministic key generation.
        #[arg(long, default_value_t = 0)]
        seed_start: u64,
        /// Nonce to use for every transfer.
        #[arg(long, default_value_t = 0)]
        nonce: u64,
    },
}

#[derive(Debug)]
struct RingTransfer {
    from: Address,
    to: Address,
    tx_bytes: Vec<u8>,
}

fn parse_private_key(hex_str: &str) -> ed25519::PrivateKey {
    let bytes = from_hex(hex_str).expect("bad private key hex");
    ed25519::PrivateKey::read(&mut &bytes[..]).expect("failed to decode private key")
}

fn parse_address(hex_str: &str) -> Address {
    let bytes = from_hex(hex_str).expect("bad address hex");
    Address::read(&mut &bytes[..]).expect("failed to decode address")
}

fn build_transaction(
    key: &ed25519::PrivateKey,
    to: Address,
    value: u64,
    nonce: u64,
) -> Transaction<Digest, ed25519::PublicKey> {
    Transaction {
        sender: key.public_key(),
        to,
        value: NonZeroU64::new(value).expect("transfer value must be non-zero"),
        nonce,
        _digest: PhantomData,
    }
}

fn build_signed_transaction_bytes(
    key: &ed25519::PrivateKey,
    to: Address,
    value: u64,
    nonce: u64,
) -> Vec<u8> {
    build_transaction(key, to, value, nonce)
        .seal_and_sign(key, TX_NAMESPACE, &mut Sha256::default())
        .encode()
        .to_vec()
}

fn build_ring_transfers(count: NonZeroUsize, seed_start: u64, nonce: u64) -> Vec<RingTransfer> {
    let count = count.get();

    let keys = (0..count)
        .map(|index| {
            let seed = seed_start + u64::try_from(index).expect("ring size exceeded u64");
            ed25519::PrivateKey::from_seed(seed)
        })
        .collect::<Vec<_>>();
    let addresses = keys
        .iter()
        .map(|key| Address::from_public_key(&mut Sha256::default(), &key.public_key()))
        .collect::<Vec<_>>();

    let mut transfers = Vec::with_capacity(count);
    for (index, key) in keys.iter().enumerate() {
        let from = addresses[index];
        let to = addresses[(index + 1) % count];
        let tx_bytes = build_signed_transaction_bytes(key, to, 1, nonce);
        transfers.push(RingTransfer { from, to, tx_bytes });
    }

    transfers
}

fn tx_url(endpoint: &str) -> String {
    format!("{}/tx", endpoint.trim_end_matches('/'))
}

async fn submit_transaction(
    client: &reqwest::Client,
    endpoint: &str,
    tx_bytes: Vec<u8>,
) -> Result<String, String> {
    let resp = client
        .post(tx_url(endpoint))
        .body(hex(&tx_bytes))
        .send()
        .await
        .map_err(|err| format!("request failed: {err}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|err| format!("response body failed: {err}"))?;

    if status.is_success() {
        return Ok(body);
    }

    Err(format!("error ({status}): {body}"))
}

#[tokio::main]
async fn main() {
    match Cli::parse() {
        Cli::Keygen { seed } => {
            let key = ed25519::PrivateKey::from_seed(seed);
            let pubkey = key.public_key();
            let address = Address::from_public_key(&mut Sha256::default(), &pubkey);
            println!("private_key: {}", hex(&key.encode()));
            println!("public_key:  {}", hex(&pubkey.encode()));
            println!("address:     {}", hex(address.as_ref()));
        }
        Cli::Address { pubkey } => {
            let bytes = from_hex(&pubkey).expect("bad pubkey hex");
            let pk = ed25519::PublicKey::read(&mut &bytes[..]).expect("bad pubkey");
            let address = Address::from_public_key(&mut Sha256::default(), &pk);
            println!("{}", hex(address.as_ref()));
        }
        Cli::Transfer {
            key,
            to,
            value,
            nonce,
            endpoint,
        } => {
            let key = parse_private_key(&key);
            let to = parse_address(&to);
            let client = reqwest::Client::new();
            let tx_bytes = build_signed_transaction_bytes(&key, to, value, nonce);
            let url = tx_url(&endpoint);
            println!("submitting to {url}...");
            let body = submit_transaction(&client, &endpoint, tx_bytes)
                .await
                .unwrap_or_else(|err| {
                    eprintln!("{err}");
                    std::process::exit(1);
                });
            println!("included: {body}");
        }
        Cli::Spam {
            count,
            endpoint,
            seed_start,
            nonce,
        } => {
            let transfers = build_ring_transfers(count, seed_start, nonce);
            let client = reqwest::Client::new();
            let url = tx_url(&endpoint);
            let mut tasks = JoinSet::new();

            println!("submitting {} ring transfers to {url}...", transfers.len());

            for transfer in transfers {
                let client = client.clone();
                let endpoint = endpoint.clone();
                tasks.spawn(async move {
                    let RingTransfer { from, to, tx_bytes } = transfer;
                    let result = submit_transaction(&client, &endpoint, tx_bytes).await;
                    (from, to, result)
                });
            }

            let mut submitted = 0usize;
            let mut failed = 0usize;

            while let Some(result) = tasks.join_next().await {
                let (from, to, submission) = result.expect("spam task panicked");
                if submission.is_ok() {
                    submitted += 1;
                    continue;
                }

                failed += 1;
                let from = hex(from.as_ref());
                let to = hex(to.as_ref());
                eprintln!("{from} -> {to}: {}", submission.unwrap_err());
            }

            println!("submitted: {submitted}");
            if failed == 0 {
                return;
            }

            eprintln!("failed: {failed}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Digest, build_ring_transfers, build_transaction};
    use commonware_codec::{Decode, Encode, Read};
    use commonware_cryptography::{Sha256, Signer, ed25519};
    use constantinople_primitives::{Address, Signed, Transaction, TransactionCfg};
    use std::num::NonZeroUsize;

    #[test]
    fn simulation_probe_is_unsigned() {
        let key = ed25519::PrivateKey::from_seed(7);
        let to = Address::from_public_key(&mut Sha256::default(), &key.public_key());
        let probe = build_transaction(&key, to, 10, 3).encode().to_vec();

        let decoded = Transaction::<Digest, ed25519::PublicKey>::decode_cfg(
            probe.as_slice(),
            &TransactionCfg::default(),
        )
        .expect("probe should decode as an unsigned transaction");

        assert_eq!(decoded.sender, key.public_key());
        assert!(Signed::<
            Transaction<Digest, ed25519::PublicKey>,
            Sha256,
            ed25519::Signature,
        >::decode_cfg(probe.as_slice(), &TransactionCfg::default())
        .is_err());
    }

    #[test]
    fn ring_transfers_wrap_back_to_the_first_account() {
        let transfers = build_ring_transfers(NonZeroUsize::new(3).unwrap(), 11, 7);

        assert_eq!(transfers.len(), 3);
        assert_eq!(transfers[0].to, transfers[1].from);
        assert_eq!(transfers[1].to, transfers[2].from);
        assert_eq!(transfers[2].to, transfers[0].from);

        let decoded = Signed::<
            Transaction<Digest, ed25519::PublicKey>,
            Sha256,
            ed25519::Signature,
        >::read_cfg(&mut &transfers[0].tx_bytes[..], &TransactionCfg::default())
        .expect("ring transfer should decode");

        assert_eq!(decoded.value().nonce, 7);
        assert_eq!(decoded.value().value.get(), 1);
    }
}
