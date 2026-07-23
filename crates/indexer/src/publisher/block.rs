//! Block row encoding shared by the combined publisher.

use crate::publisher::{
    SqlRow,
    sql::{
        BlockMetaRow, TxActivityRole, TxActivityRow, TxMetaRow, encode_block_meta_row,
        encode_tx_activity_row, encode_tx_meta_row,
    },
};
use bytes::Bytes;
use commonware_codec::FixedSize;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use constantinople_engine::types::EngineBlock;
use constantinople_primitives::{AccountKey, LazySignedTransaction, Payload, TransactionPublicKey};
use tracing::warn;

/// Encoded block rows split by index surface.
pub(crate) struct IndexedBlockRows<D: Digest> {
    /// SQL rows for block metadata, transaction metadata, and account activity.
    pub sql: Vec<SqlRow>,
    /// Transaction digests in append order.
    pub transaction_digests: Vec<D>,
}

struct IndexedTransaction<D: Digest> {
    block_index: usize,
    digest: D,
    bytes: Bytes,
    sender: AccountKey,
    to: [u8; AccountKey::SIZE],
    value: u64,
    nonce: u64,
}

/// Build every row for a finalized block, partitioned by destination store.
#[cfg(test)]
pub(crate) fn encode_indexed_block_rows<H, P>(
    block: &EngineBlock<H, P>,
) -> IndexedBlockRows<H::Digest>
where
    H: Hasher,
    P: PublicKey,
{
    let finalized_ts_micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0);
    encode_indexed_block_rows_at(block, finalized_ts_micros)
}

pub(crate) fn encode_indexed_block_rows_at<H, P>(
    block: &EngineBlock<H, P>,
    finalized_ts_micros: i64,
) -> IndexedBlockRows<H::Digest>
where
    H: Hasher,
    P: PublicKey,
{
    let block_digest = block.seal();
    let height = block.header.height;
    let body_len = block.body.len();
    // SQL `block_meta.digest` is `FixedSizeBinary(32)` — copy it into a
    // `[u8; 32]` for the typed CellValue path.
    let mut block_digest_arr = [0u8; 32];
    block_digest_arr.copy_from_slice(block_digest.as_ref());
    let mut transactions_root = [0u8; 32];
    transactions_root.copy_from_slice(block.header.transactions_root.as_ref());
    let indexed_txs = block
        .body
        .iter()
        .enumerate()
        .filter_map(|(idx, lazy)| index_transaction::<H>(height, idx, lazy))
        .collect::<Vec<_>>();
    let tx_count = u64::try_from(indexed_txs.len()).expect("transaction count fits u64");
    let append_start = block
        .header
        .transactions_range
        .end()
        .checked_sub(tx_count + 1)
        .expect("transaction range includes appends plus commit");

    let mut sql = Vec::with_capacity(1 + 3 * body_len);

    // One tx_meta row plus sender/receiver tx_activity rows per transaction.
    let mut transaction_digests = Vec::with_capacity(indexed_txs.len());
    for (materialized_idx, tx) in indexed_txs.into_iter().enumerate() {
        transaction_digests.push(tx.digest);
        let idx_u32 = u32::try_from(tx.block_index).expect("transaction index fits u32");
        let qmdb_location = append_start + u64::try_from(materialized_idx).expect("index fits u64");
        let mut digest = [0u8; 32];
        digest.copy_from_slice(tx.digest.as_ref());
        let mut sender = [0u8; AccountKey::SIZE];
        sender.copy_from_slice(tx.sender.as_ref());
        let receiver = tx.to;
        sql.push(encode_tx_meta_row(TxMetaRow {
            digest,
            qmdb_location,
            body: tx.bytes,
        }));
        sql.push(encode_tx_activity_row(TxActivityRow {
            account: sender,
            role: TxActivityRole::Sender,
            height,
            index: idx_u32,
            digest,
            counterparty: receiver,
            value: tx.value,
            nonce: tx.nonce,
        }));
        if receiver != sender {
            sql.push(encode_tx_activity_row(TxActivityRow {
                account: receiver,
                role: TxActivityRole::Receiver,
                height,
                index: idx_u32,
                digest,
                counterparty: sender,
                value: tx.value,
                nonce: tx.nonce,
            }));
        }
    }

    // SQL: one block_meta row per finalized block.
    // `view` is currently 0; see `encode_block_meta_row` docs for why.
    sql.insert(
        0,
        encode_block_meta_row(BlockMetaRow {
            height,
            digest: block_digest_arr,
            tx_count,
            transactions_root,
            transactions_tip: block.header.transactions_range.end() - 1,
            view: 0,
            finalized_ts_micros,
        }),
    );

    IndexedBlockRows {
        sql,
        transaction_digests,
    }
}

fn index_transaction<H>(
    height: u64,
    block_index: usize,
    transaction: &LazySignedTransaction<H>,
) -> Option<IndexedTransaction<H::Digest>>
where
    H: Hasher,
{
    let signed_bytes = transaction.encoded_signed_transaction();
    let Some(signed) = transaction.get() else {
        warn!(
            height,
            block_index, "indexer: skipping malformed transaction"
        );
        return None;
    };
    let tx = signed.value();
    let Some(sender) =
        AccountKey::from_public_key_bytes(&signed_bytes[..TransactionPublicKey::SIZE])
    else {
        warn!(
            height,
            block_index, "indexer: sender public key bytes cannot derive an account key"
        );
        return None;
    };
    let (to_account, value) = match &tx.payload {
        Payload::PublicTransfer { to, value } => (*to, value.get()),
        Payload::PrivateTransfer { to, .. } => (*to, 0),
        Payload::PrivateFund { .. } | Payload::PrivateBurn { .. } | Payload::PrivateRollover => {
            (sender, 0)
        }
    };
    let mut to = [0u8; AccountKey::SIZE];
    to.copy_from_slice(to_account.as_ref());

    Some(IndexedTransaction {
        block_index,
        digest: *signed.message_digest(),
        bytes: signed_bytes,
        sender,
        to,
        value,
        nonce: tx.nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_schema::{TX_ACTIVITY_TABLE, TX_META_TABLE};
    use commonware_codec::{DecodeExt as _, EncodeSize as _, FixedSize, ReadExt as _, Write as _};
    use commonware_consensus::{
        simplex::types::Context,
        types::{Epoch, Round, View, coding::Commitment},
    };
    use commonware_cryptography::{
        Digest, Signer,
        ed25519::{self, PublicKey},
        secp256r1::standard as secp256r1,
        sha256::{self, Sha256},
    };
    use commonware_math::algebra::Random;
    use commonware_utils::{NZU16, non_empty_range, range::NonEmptyRange};
    use constantinople_primitives::{
        Block, ChainPrivatePaymentBackend, Header, LazySignedTransaction, PrivatePaymentBackend,
        Sealable, Sealed, TRANSACTION_NAMESPACE, Transaction, TransactionPublicKey,
    };
    use core::num::NonZeroU64;
    use exoware_sql::CellValue;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn r1_sender_history_uses_account_key() {
        let mut rng = StdRng::from_seed([3; 32]);
        let consensus_key = ed25519::PrivateKey::random(&mut rng);
        let signer = ed25519::PrivateKey::random(&mut rng);
        let sender =
            TransactionPublicKey::secp256r1(secp256r1::PrivateKey::random(&mut rng).public_key());
        let recipient =
            TransactionPublicKey::ed25519(ed25519::PrivateKey::random(&mut rng).public_key());
        let sender_account = AccountKey::from_public_key(&sender);
        let transaction = Transaction::<sha256::Digest>::new(
            sender,
            recipient,
            NonZeroU64::new(1).expect("test value should be non-zero"),
            0,
        )
        .seal_and_sign(&signer, TRANSACTION_NAMESPACE, &mut Sha256::default());
        let block = Block::<Commitment, PublicKey, Sha256>::new(
            test_header(consensus_key.public_key(), 1),
            vec![transaction],
        )
        .seal(&mut Sha256::default());

        let rows = encode_indexed_block_rows(&block);
        assert_activity_sender(&rows.sql, sender_account.as_ref());
    }

    #[test]
    fn row_encoding_uses_lazy_transaction_bytes_without_materializing() {
        let mut rng = StdRng::from_seed([9; 32]);
        let consensus_key = ed25519::PrivateKey::random(&mut rng);
        let signer = ed25519::PrivateKey::random(&mut rng);
        let sender = TransactionPublicKey::ed25519(signer.public_key());
        let recipient =
            TransactionPublicKey::ed25519(ed25519::PrivateKey::random(&mut rng).public_key());
        let signed = Transaction::<sha256::Digest>::new(
            sender,
            recipient,
            NonZeroU64::new(1).expect("test value should be non-zero"),
            0,
        )
        .seal_and_sign(&signer, TRANSACTION_NAMESPACE, &mut Sha256::default());

        let mut transaction = Vec::with_capacity(signed.encode_size());
        signed.write(&mut transaction);
        let invalid_sender = invalid_public_key_bytes();
        let sender_account = AccountKey::from_public_key_bytes(&invalid_sender)
            .expect("invalid ed25519 curve bytes still define an account key");
        transaction[..TransactionPublicKey::SIZE].copy_from_slice(&invalid_sender);
        let mut encoded = Vec::with_capacity(transaction.len().encode_size() + transaction.len());
        transaction.len().write(&mut encoded);
        encoded.extend_from_slice(&transaction);
        let lazy = LazySignedTransaction::<Sha256>::read(&mut &encoded[..])
            .expect("outer lazy transaction should decode");

        let block = Sealed::new_unchecked(
            Block {
                header: test_header(consensus_key.public_key(), 1),
                body: vec![lazy],
            },
            sha256::Digest::EMPTY,
        );

        let rows = encode_indexed_block_rows(&block);
        assert_activity_sender(&rows.sql, sender_account.as_ref());
        assert_eq!(rows.transaction_digests.len(), 1);
        assert_tx_meta_body(&rows.sql, &transaction);
    }

    #[test]
    fn private_payloads_index_zero_value_with_per_arm_recipients() {
        let mut rng = StdRng::from_seed([11; 32]);
        let consensus_key = ed25519::PrivateKey::random(&mut rng);
        let signer = ed25519::PrivateKey::random(&mut rng);
        let sender = TransactionPublicKey::ed25519(signer.public_key());
        let sender_account = AccountKey::from_public_key(&sender);
        let recipient = AccountKey::from_public_key(&TransactionPublicKey::ed25519(
            ed25519::PrivateKey::random(&mut rng).public_key(),
        ));

        let payloads = private_payloads::<ChainPrivatePaymentBackend>(recipient, &mut rng);
        let transactions = payloads
            .into_iter()
            .enumerate()
            .map(|(index, payload)| {
                // Offset nonces so they never coincide with block indices,
                // keeping the index and nonce row columns distinguishable.
                let nonce = u64::try_from(index).expect("index fits u64") + 10;
                Transaction::<sha256::Digest>::from_payload(sender.clone(), payload, nonce)
                    .seal_and_sign(&signer, TRANSACTION_NAMESPACE, &mut Sha256::default())
            })
            .collect::<Vec<_>>();
        let block = Block::<Commitment, PublicKey, Sha256>::new(
            test_header(consensus_key.public_key(), transactions.len()),
            transactions,
        )
        .seal(&mut Sha256::default());

        let rows = encode_indexed_block_rows(&block);
        assert_eq!(rows.transaction_digests.len(), 4);

        // PrivateFund has no recipient: the sender self-references and no
        // receiver row is emitted.
        let fund = activity_rows_for_index(&rows.sql, 0);
        assert_eq!(fund.len(), 1, "fund should index one sender row");
        assert_activity_row(
            fund[0],
            sender_account.as_ref(),
            TxActivityRole::Sender,
            sender_account.as_ref(),
            0,
            10,
        );

        // PrivateRollover has the same self-referential shape as fund.
        let rollover = activity_rows_for_index(&rows.sql, 1);
        assert_eq!(rollover.len(), 1, "rollover should index one sender row");
        assert_activity_row(
            rollover[0],
            sender_account.as_ref(),
            TxActivityRole::Sender,
            sender_account.as_ref(),
            0,
            11,
        );

        // PrivateTransfer names a public recipient but hides the amount, so
        // both activity rows carry the counterparty with value zero.
        let transfer = activity_rows_for_index(&rows.sql, 2);
        assert_eq!(
            transfer.len(),
            2,
            "transfer should index sender and receiver rows"
        );
        assert_activity_row(
            transfer[0],
            sender_account.as_ref(),
            TxActivityRole::Sender,
            recipient.as_ref(),
            0,
            12,
        );
        assert_activity_row(
            transfer[1],
            recipient.as_ref(),
            TxActivityRole::Receiver,
            sender_account.as_ref(),
            0,
            12,
        );

        // PrivateBurn has no recipient and the de-shielded value stays
        // unindexed.
        let burn = activity_rows_for_index(&rows.sql, 3);
        assert_eq!(burn.len(), 1, "burn should index one sender row");
        assert_activity_row(
            burn[0],
            sender_account.as_ref(),
            TxActivityRole::Sender,
            sender_account.as_ref(),
            0,
            13,
        );
    }

    /// One payload per private arm, built with the configured chain backend.
    ///
    /// Generic over the backend so the prover methods resolve through the
    /// `PrivatePaymentBackend` supertrait (mock under default features, real
    /// zkpari proving under `--all-features`). Mirrors the executor's
    /// `private_ops` construction: fund proofs bind the public value and
    /// transfer proofs bind the sender's current commitment.
    fn private_payloads<B>(to: AccountKey, rng: &mut StdRng) -> [Payload<B>; 4]
    where
        B: PrivatePaymentBackend,
    {
        let params = B::params();
        let (commitment, _opening, fund_proof) = B::fund(params, 4, rng);
        let (current, current_opening, _current_proof) = B::fund(params, 7, rng);
        let (amount, _amount_opening, transfer_proof) =
            B::transfer(params, &current, &current_opening, 3, rng);
        let burn_proof = B::burn(params, &current, &current_opening, 2, rng);
        [
            Payload::PrivateFund {
                value: NonZeroU64::new(4).expect("test value should be non-zero"),
                commitment,
                proof: fund_proof,
            },
            Payload::PrivateRollover,
            Payload::PrivateTransfer {
                to,
                amount,
                proof: transfer_proof,
            },
            Payload::PrivateBurn {
                value: NonZeroU64::new(2).expect("test value should be non-zero"),
                proof: burn_proof,
            },
        ]
    }

    fn activity_rows_for_index(rows: &[SqlRow], index: u64) -> Vec<&SqlRow> {
        rows.iter()
            .filter(|row| {
                row.table == TX_ACTIVITY_TABLE
                    && matches!(row.values.get(2), Some(CellValue::UInt64(i)) if *i == index)
            })
            .collect()
    }

    fn assert_activity_row(
        row: &SqlRow,
        expected_account: &[u8],
        expected_role: TxActivityRole,
        expected_counterparty: &[u8],
        expected_value: u64,
        expected_nonce: u64,
    ) {
        let Some(CellValue::FixedBinary(account)) = row.values.first() else {
            panic!("activity account should be fixed binary");
        };
        assert_eq!(account.as_slice(), expected_account);
        let Some(CellValue::UInt64(role)) = row.values.get(3) else {
            panic!("activity role should be u64");
        };
        let expected_role = match expected_role {
            TxActivityRole::Sender => 0,
            TxActivityRole::Receiver => 1,
        };
        assert_eq!(*role, expected_role, "activity role mismatch");
        let Some(CellValue::FixedBinary(counterparty)) = row.values.get(5) else {
            panic!("activity counterparty should be fixed binary");
        };
        assert_eq!(counterparty.as_slice(), expected_counterparty);
        let Some(CellValue::UInt64(value)) = row.values.get(6) else {
            panic!("activity value should be u64");
        };
        assert_eq!(*value, expected_value, "activity value mismatch");
        let Some(CellValue::UInt64(nonce)) = row.values.get(7) else {
            panic!("activity nonce should be u64");
        };
        assert_eq!(*nonce, expected_nonce, "activity nonce mismatch");
    }

    fn assert_activity_sender(rows: &[SqlRow], expected_account: &[u8]) {
        let sender = rows
            .iter()
            .find(|row| {
                row.table == TX_ACTIVITY_TABLE
                    && matches!(row.values.get(3), Some(CellValue::UInt64(0)))
            })
            .expect("sender activity row should be indexed");
        let Some(CellValue::FixedBinary(account)) = sender.values.first() else {
            panic!("sender activity account should be fixed binary");
        };
        assert_eq!(account.as_slice(), expected_account);
    }

    fn assert_tx_meta_body(rows: &[SqlRow], expected_body: &[u8]) {
        let meta = rows
            .iter()
            .find(|row| row.table == TX_META_TABLE)
            .expect("tx_meta row should be indexed");
        let Some(CellValue::Binary(body)) = meta.values.get(2) else {
            panic!("tx_meta body should be binary");
        };
        assert_eq!(body.as_slice(), expected_body);
    }

    fn test_header(
        leader: PublicKey,
        tx_count: usize,
    ) -> Header<Commitment, sha256::Digest, PublicKey> {
        let transactions_end = u64::try_from(tx_count).expect("tx count fits u64") + 1;
        Header {
            context: Context {
                round: Round::new(Epoch::zero(), View::zero()),
                leader,
                parent: (View::zero(), valid_commitment()),
            },
            parent: sha256::Digest::EMPTY,
            height: 7,
            timestamp: 1_000,
            state_root: sha256::Digest::EMPTY,
            state_range: non_empty_range!(0u64, 1u64) as NonEmptyRange<u64>,
            transactions_root: sha256::Digest::EMPTY,
            transactions_range: non_empty_range!(0u64, transactions_end) as NonEmptyRange<u64>,
        }
    }

    fn valid_commitment() -> Commitment {
        Commitment::from((
            sha256::Digest::EMPTY,
            sha256::Digest::EMPTY,
            sha256::Digest::EMPTY,
            commonware_coding::Config {
                minimum_shards: NZU16!(1),
                extra_shards: NZU16!(1),
            },
        ))
    }

    fn invalid_public_key_bytes() -> [u8; TransactionPublicKey::SIZE] {
        (0u8..=u8::MAX)
            .flat_map(|first| (0u8..=u8::MAX).map(move |last| (first, last)))
            .find_map(|(first, last)| {
                let mut candidate = [0; TransactionPublicKey::SIZE];
                candidate[0] = 0;
                candidate[1] = first;
                candidate[TransactionPublicKey::SIZE - 1] = last;

                TransactionPublicKey::decode(&mut &candidate[..])
                    .is_err()
                    .then_some(candidate)
            })
            .expect("test should find invalid public key bytes")
    }
}
