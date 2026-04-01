use crate::shared::{build_signed_transaction_bytes, submit_transaction, tx_url};
use clap::Args as ClapArgs;
use commonware_cryptography::{Sha256, Signer, ed25519};
use commonware_utils::hex;
use constantinople_primitives::Address;
use std::{
    num::{NonZeroU32, NonZeroUsize},
    time::Duration,
};
use tokio::{
    task::JoinSet,
    time::{self, MissedTickBehavior},
};

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Number of accounts to create.
    #[arg(long)]
    count: NonZeroUsize,
    /// Validator HTTP endpoint (e.g. http://localhost:8080).
    #[arg(long)]
    endpoint: String,
    /// Starting seed for deterministic key generation.
    #[arg(long, default_value_t = 0)]
    seed_start: u64,
    /// Starting nonce for every sender.
    #[arg(long, default_value_t = 0)]
    nonce: u64,
    /// Fixed submission rate in transactions per second.
    #[arg(long)]
    tps: NonZeroU32,
}

#[derive(Debug)]
struct RingTransfer {
    from: Address,
    to: Address,
    tx_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct RingAccount {
    key: ed25519::PrivateKey,
    from: Address,
    to: Address,
    next_nonce: u64,
}

fn build_ring_accounts(count: NonZeroUsize, seed_start: u64, nonce: u64) -> Vec<RingAccount> {
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

    let mut accounts = Vec::with_capacity(count);
    for (index, key) in keys.iter().enumerate() {
        let from = addresses[index];
        let to = addresses[(index + 1) % count];
        accounts.push(RingAccount {
            key: key.clone(),
            from,
            to,
            next_nonce: nonce,
        });
    }

    accounts
}

fn next_ring_transfer(accounts: &mut [RingAccount], cursor: &mut usize) -> RingTransfer {
    let sender = &mut accounts[*cursor];
    let tx_bytes = build_signed_transaction_bytes(&sender.key, sender.to, 1, sender.next_nonce);
    sender.next_nonce = sender
        .next_nonce
        .checked_add(1)
        .expect("sender nonce overflowed");

    let transfer = RingTransfer {
        from: sender.from,
        to: sender.to,
        tx_bytes,
    };

    *cursor = (*cursor + 1) % accounts.len();
    transfer
}

fn drain_completed_submissions(
    tasks: &mut JoinSet<(Address, Address, Result<String, String>)>,
    completed: &mut usize,
    failed: &mut usize,
) {
    while let Some(result) = tasks.try_join_next() {
        let (from, to, submission) = result.expect("spam task panicked");
        *completed += 1;

        if let Err(err) = submission {
            *failed += 1;
            let from = hex(from.as_ref());
            let to = hex(to.as_ref());
            eprintln!("{from} -> {to}: {err}");
        }
    }
}

pub async fn run(args: Args) -> Result<(), String> {
    let mut accounts = build_ring_accounts(args.count, args.seed_start, args.nonce);
    let mut cursor = 0usize;
    let client = reqwest::Client::new();
    let url = tx_url(&args.endpoint);
    let mut tasks = JoinSet::new();
    let mut ticker = time::interval(Duration::from_secs_f64(1.0 / f64::from(args.tps.get())));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut completed = 0usize;
    let mut failed = 0usize;

    println!(
        "submitting ring transfers to {url} at {} tx/s. Press Ctrl-C to stop.",
        args.tps
    );

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let transfer = next_ring_transfer(&mut accounts, &mut cursor);
                let client = client.clone();
                let endpoint = args.endpoint.clone();

                tasks.spawn(async move {
                    let RingTransfer { from, to, tx_bytes } = transfer;
                    let result = submit_transaction(&client, &endpoint, tx_bytes).await;
                    (from, to, result)
                });

                drain_completed_submissions(&mut tasks, &mut completed, &mut failed);
            }
            _ = tokio::signal::ctrl_c() => {
                println!("stopping spammer...");
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                break;
            }
        }
    }

    println!("completed: {completed}");
    println!("failed: {failed}");

    if failed == 0 {
        return Ok(());
    }

    Err(format!("failed: {failed}"))
}

#[cfg(test)]
mod tests {
    use super::{build_ring_accounts, next_ring_transfer};
    use crate::shared::Digest;
    use commonware_codec::Read;
    use commonware_cryptography::{Sha256, ed25519};
    use constantinople_primitives::{Signed, Transaction, TransactionCfg};
    use std::num::NonZeroUsize;

    #[test]
    fn ring_accounts_wrap_back_to_the_first_account() {
        let accounts = build_ring_accounts(NonZeroUsize::new(3).unwrap(), 11, 7);

        assert_eq!(accounts.len(), 3);
        assert_eq!(accounts[0].to, accounts[1].from);
        assert_eq!(accounts[1].to, accounts[2].from);
        assert_eq!(accounts[2].to, accounts[0].from);
    }

    #[test]
    fn next_ring_transfer_increments_sender_nonce() {
        let mut accounts = build_ring_accounts(NonZeroUsize::new(2).unwrap(), 11, 7);
        let mut cursor = 0usize;

        let first = next_ring_transfer(&mut accounts, &mut cursor);
        let second = next_ring_transfer(&mut accounts, &mut cursor);

        let first_decoded = Signed::<
            Transaction<Digest, ed25519::PublicKey>,
            Sha256,
            ed25519::Signature,
        >::read_cfg(
            &mut &first.tx_bytes[..], &TransactionCfg::default()
        )
        .expect("first ring transfer should decode");
        assert_eq!(first_decoded.value().nonce, 7);
        assert_eq!(first_decoded.value().value.get(), 1);

        let second_decoded = Signed::<
            Transaction<Digest, ed25519::PublicKey>,
            Sha256,
            ed25519::Signature,
        >::read_cfg(
            &mut &second.tx_bytes[..], &TransactionCfg::default()
        )
        .expect("second ring transfer should decode");
        assert_eq!(second_decoded.value().nonce, 7);

        let third = next_ring_transfer(&mut accounts, &mut cursor);
        let third_decoded = Signed::<
            Transaction<Digest, ed25519::PublicKey>,
            Sha256,
            ed25519::Signature,
        >::read_cfg(
            &mut &third.tx_bytes[..], &TransactionCfg::default()
        )
        .expect("third ring transfer should decode");
        assert_eq!(third.from, first.from);
        assert_eq!(third_decoded.value().nonce, 8);
    }
}
