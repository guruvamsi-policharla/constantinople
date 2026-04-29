// Streaming client for the constantinople indexer (exoware simulator).
//
// Subscribes to the `TX_BY_H` key family (reservedBits=4, prefix=0x6) which
// gives us all three things the explorer wants in a single stream:
//
//   key   = u64 BE height ‖ u32 BE index   (12 bytes after prefix decoding)
//   value = 32-byte transaction digest
//
// The TX family (0x5) holds the encoded `SignedTransaction` body itself; we
// deliberately leave full decode out of v1 — the spammer transactions encode
// their full address+value+signature and adding a wasm-friendly decoder is
// scope-creep. Pulling the digest + height + index from TX_BY_H is enough
// for a useful live feed.
//
// Family prefixes mirror crates/indexer/src/keys.rs:
//
//   pub const RESERVED_BITS: u8 = 4;
//   pub const TX_BY_H: KeyCodec = KeyCodec::new(RESERVED_BITS, 0x6);

import { Client, HttpError, StoreKeyPrefix, type StoreBatch } from '@exowarexyz/sdk';

/** Mirrors `RESERVED_BITS` in `crates/indexer/src/keys.rs`. */
export const KEY_RESERVED_BITS = 4;
/** Mirrors the `TX_BY_H` family prefix in `crates/indexer/src/keys.rs`. */
export const KEY_FAMILY_TX_BY_H = 0x6;

/** Length of the decoded `TX_BY_H` key payload: u64 height + u32 index. */
const TX_BY_H_PAYLOAD_LEN = 12;
/** Length of the value stored at every `TX_BY_H` key. */
const TX_DIGEST_LEN = 32;

/** A single transaction observed on the live stream. */
export interface ObservedTx {
    /** Block height the transaction was finalized at. */
    readonly height: bigint;
    /** Position of the transaction within its block. */
    readonly index: number;
    /** Hex-encoded transaction digest (`tx_digest` in the indexer). */
    readonly digestHex: string;
    /** Wall-clock arrival time on this client, in epoch milliseconds. */
    readonly arrivedAt: number;
    /** Stream sequence number; useful as a stable React key. */
    readonly sequence: bigint;
}

/** A batch as emitted by the indexer subscription, post-decoding. */
export interface ObservedBatch {
    readonly sequence: bigint;
    readonly transactions: readonly ObservedTx[];
}

/**
 * Open a streaming subscription to every transaction newly indexed by the
 * exoware simulator at `baseUrl`. The returned async generator yields one
 * `ObservedBatch` per atomic store batch — i.e. each yielded batch is the
 * set of transactions from a single finalized block. Yielding per-batch
 * (rather than per-row) lets the UI flush a whole block in one render.
 *
 * Transient `OUT_OF_RANGE` errors from the simulator (see
 * [`isTransientBatchRaceError`]) are caught and the subscription is
 * automatically reopened — they're a documented race against concurrent
 * uploads and reconnecting fresh always recovers.
 */
export async function* subscribeTransactions(
    baseUrl: string,
    signal?: AbortSignal,
): AsyncGenerator<ObservedBatch, void, void> {
    const client = new Client(baseUrl);
    const txByH = client.store(
        new StoreKeyPrefix(KEY_RESERVED_BITS, KEY_FAMILY_TX_BY_H),
    );

    // Cap consecutive transient retries so a genuinely broken simulator
    // can't trap us in a tight reconnect loop. A single successful batch
    // resets the counter.
    const MAX_TRANSIENT_RETRIES = 10;
    let transientRetries = 0;

    while (!signal?.aborted) {
        try {
            // The SDK rewrites this match key with our store's prefix before
            // sending, so reservedBits=0/prefix=0/payload_regex=".*" means
            // "every key in the TX_BY_H family". Same trick the SDK README uses.
            const stream = txByH.subscribe(
                {
                    matchKeys: [
                        {
                            reservedBits: 0,
                            prefix: 0,
                            payloadRegex: '(?s-u).*',
                        },
                    ],
                },
                { signal },
            );

            for await (const batch of stream) {
                transientRetries = 0;
                const decoded = decodeBatch(batch);
                if (decoded.transactions.length > 0) {
                    yield decoded;
                }
            }
            // Server-streaming RPC ended cleanly (no more frames). Loop and
            // re-subscribe so the UI keeps following the live tail.
        } catch (error) {
            if (signal?.aborted) {
                return;
            }
            if (
                !isTransientBatchRaceError(error) ||
                transientRetries >= MAX_TRANSIENT_RETRIES
            ) {
                throw error;
            }
            transientRetries++;
            // Brief backoff before reconnecting; the race window is short
            // (commit ordering across the simulator's three concurrent
            // uploaders) so a single reconnect almost always succeeds.
            await sleep(250);
        }
    }
}

/**
 * The simulator publishes an in-memory "next published sequence" before each
 * commit lands in its batch_log column family. With our three indexer
 * uploaders racing concurrently against the same simulator, a subscriber that
 * wakes mid-commit can briefly observe `current_sequence` ahead of the
 * batch_log row, and the server returns
 * `OUT_OF_RANGE { reason: BATCH_EVICTED }` instead of waiting. The race
 * window is on the order of milliseconds; reopening the subscription resyncs
 * past it and the new floor sits at the (now-committed) latest sequence.
 *
 * The SDK maps `OUT_OF_RANGE` to `HttpError { status: 400 }` — we recognize
 * it by the eviction reason embedded in the underlying ConnectError details
 * to avoid swallowing unrelated 400s.
 */
function isTransientBatchRaceError(error: unknown): boolean {
    return (
        error instanceof HttpError &&
        error.status === 400 &&
        /evicted|out_of_range/i.test(error.message)
    );
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function decodeBatch(batch: StoreBatch): ObservedBatch {
    const arrivedAt = Date.now();
    const transactions: ObservedTx[] = [];
    for (const entry of batch.entries) {
        const tx = tryDecodeEntry(entry.key, entry.value, arrivedAt, batch.sequenceNumber);
        if (tx) {
            transactions.push(tx);
        }
    }
    // Sort within a batch so the UI shows transactions in block order even if
    // RocksDB happens to enumerate them differently.
    transactions.sort((a, b) => {
        if (a.height !== b.height) {
            return a.height < b.height ? -1 : 1;
        }
        return a.index - b.index;
    });
    return { sequence: batch.sequenceNumber, transactions };
}

function tryDecodeEntry(
    key: Uint8Array,
    value: Uint8Array,
    arrivedAt: number,
    sequence: bigint,
): ObservedTx | undefined {
    if (key.length !== TX_BY_H_PAYLOAD_LEN || value.length !== TX_DIGEST_LEN) {
        // Skip rows that don't look like a TX_BY_H entry. The simulator may
        // grow new families later that incidentally match the prefix range
        // (it shouldn't, but better silent-skip than crashing the whole
        // subscription).
        return undefined;
    }
    const view = new DataView(key.buffer, key.byteOffset, key.byteLength);
    const height = view.getBigUint64(0, false);
    const index = view.getUint32(8, false);
    return {
        height,
        index,
        digestHex: hex(value),
        arrivedAt,
        sequence,
    };
}

const HEX = '0123456789abcdef';

function hex(bytes: Uint8Array): string {
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i];
        out += HEX[(b >> 4) & 0xf];
        out += HEX[b & 0xf];
    }
    return out;
}
