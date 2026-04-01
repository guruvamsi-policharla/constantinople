use crate::shared::{accept_transaction, build_signed_transaction_bytes, tx_url};
use clap::Args as ClapArgs;
use commonware_cryptography::{Sha256, Signer, ed25519};
use commonware_utils::hex;
use constantinople_primitives::Address;
use std::{
    collections::VecDeque,
    num::{NonZeroU32, NonZeroUsize},
    time::Duration,
};
use tokio::{
    task::JoinSet,
    time,
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
    sender_index: usize,
    from: Address,
    to: Address,
    nonce: u64,
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

fn next_ring_transfer(accounts: &[RingAccount], ready: &mut VecDeque<usize>) -> Option<RingTransfer> {
    let sender_index = ready.pop_front()?;
    let sender = &accounts[sender_index];

    Some(RingTransfer {
        sender_index,
        from: sender.from,
        to: sender.to,
        nonce: sender.next_nonce,
        tx_bytes: build_signed_transaction_bytes(&sender.key, sender.to, 1, sender.next_nonce),
    })
}

fn handle_submission_result(
    accounts: &mut [RingAccount],
    ready: &mut VecDeque<usize>,
    sender_index: usize,
    submission: Result<(), String>,
    completed: &mut usize,
    failed: &mut usize,
    from: Address,
    to: Address,
    nonce: u64,
) {
    *completed += 1;
    ready.push_back(sender_index);

    if submission.is_ok() {
        accounts[sender_index].next_nonce = nonce
            .checked_add(1)
            .expect("sender nonce overflowed");
        return;
    }

    *failed += 1;
    let from = hex(from.as_ref());
    let to = hex(to.as_ref());
    let err = submission.expect_err("failed submission should carry an error");
    eprintln!("{from} -> {to} nonce={nonce}: {err}");
}

fn drain_completed_submissions(
    accounts: &mut [RingAccount],
    ready: &mut VecDeque<usize>,
    tasks: &mut JoinSet<(usize, Address, Address, u64, Result<(), String>)>,
    completed: &mut usize,
    failed: &mut usize,
) {
    while let Some(result) = tasks.try_join_next() {
        let (sender_index, from, to, nonce, submission) =
            result.expect("spam task panicked");
        handle_submission_result(
            accounts,
            ready,
            sender_index,
            submission,
            completed,
            failed,
            from,
            to,
            nonce,
        );
    }
}

pub async fn run(args: Args) -> Result<(), String> {
    let mut accounts = build_ring_accounts(args.count, args.seed_start, args.nonce);
    let mut ready = (0..accounts.len()).collect::<VecDeque<_>>();
    let client = reqwest::Client::new();
    let url = tx_url(&args.endpoint);
    let mut tasks = JoinSet::new();
    let mut completed = 0usize;
    let mut failed = 0usize;
    let mut dispatched = 0u64;
    let started = time::Instant::now();
    let tps = u64::from(args.tps.get());

    println!(
        "submitting ring transfers to {url} at {} tx/s. Press Ctrl-C to stop.",
        args.tps
    );

    loop {
        drain_completed_submissions(
            &mut accounts,
            &mut ready,
            &mut tasks,
            &mut completed,
            &mut failed,
        );

        let target = ((started.elapsed().as_nanos() * u128::from(tps)) / 1_000_000_000) as u64;
        let mut submitted = false;

        while dispatched < target {
            let Some(transfer) = next_ring_transfer(&accounts, &mut ready) else {
                break;
            };

            submitted = true;
            dispatched += 1;

            let client = client.clone();
            let endpoint = args.endpoint.clone();

            tasks.spawn(async move {
                let RingTransfer {
                    sender_index,
                    from,
                    to,
                    nonce,
                    tx_bytes,
                } = transfer;
                let result = accept_transaction(&client, &endpoint, tx_bytes).await;
                (sender_index, from, to, nonce, result)
            });
        }

        if submitted {
            tokio::task::yield_now().await;
            continue;
        }

        if tasks.is_empty() {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    println!("stopping spammer...");
                    break;
                }
                _ = time::sleep(Duration::from_millis(1)) => {}
            }
            continue;
        }

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("stopping spammer...");
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                break;
            }
            Some(result) = tasks.join_next() => {
                let (sender_index, from, to, nonce, submission) =
                    result.expect("spam task panicked");
                handle_submission_result(
                    &mut accounts,
                    &mut ready,
                    sender_index,
                    submission,
                    &mut completed,
                    &mut failed,
                    from,
                    to,
                    nonce,
                );
            }
            _ = time::sleep(Duration::from_millis(1)) => {}
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
    use super::{build_ring_accounts, next_ring_transfer, RingAccount};
    use crate::shared::Digest;
    use commonware_codec::Read;
    use commonware_cryptography::{Sha256, ed25519};
    use constantinople_primitives::{Signed, Transaction, TransactionCfg};
    use std::{collections::VecDeque, num::NonZeroUsize};

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
        let accounts = build_ring_accounts(NonZeroUsize::new(2).unwrap(), 11, 7);
        let mut ready = VecDeque::from(vec![0usize, 1]);

        let first = next_ring_transfer(&accounts, &mut ready).expect("first transfer should exist");
        let second =
            next_ring_transfer(&accounts, &mut ready).expect("second transfer should exist");

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

        let mut accounts = accounts;
        accounts[0].next_nonce = 8;
        ready.push_back(0);

        let third = next_ring_transfer(&accounts, &mut ready).expect("third transfer should exist");
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

    #[test]
    fn next_ring_transfer_skips_busy_senders() {
        let accounts: Vec<RingAccount> = build_ring_accounts(NonZeroUsize::new(3).unwrap(), 11, 7);
        let mut ready = VecDeque::from(vec![1usize, 2]);

        let first = next_ring_transfer(&accounts, &mut ready).expect("first transfer should exist");
        let second =
            next_ring_transfer(&accounts, &mut ready).expect("second transfer should exist");

        assert_ne!(first.sender_index, 0);
        assert_ne!(second.sender_index, 0);
        assert!(next_ring_transfer(&accounts, &mut ready).is_none());
    }
}
