// Streaming client for the constantinople indexer (exoware simulator).
//
// Subscribes to the `TX_BY_H` key family (reservedBits=4, prefix=0x6) which
// is keyed by `(u64 BE height, u32 BE index)` and valued by the 32-byte
// transaction digest. Each atomic store batch corresponds to the
// transactions of a single finalized block, so we aggregate per-batch into
// an `ObservedBlock` summary instead of streaming every transaction
// individually — at spammer-grade rates a single block can contain tens of
// thousands of transactions and per-row UI updates would melt the browser.
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

/** Aggregate summary of one finalized block as observed on the live stream. */
export interface ObservedBlock {
    /** Finalized block height the batch corresponds to. */
    readonly height: bigint;
    /** Number of transactions contained in the block. */
    readonly txCount: number;
    /** Wall-clock arrival time on this client, in epoch milliseconds. */
    readonly arrivedAt: number;
    /** Stream sequence number; useful as a stable React key. */
    readonly sequence: bigint;
}

/**
 * Open a streaming subscription to every block newly indexed by the exoware
 * simulator at `baseUrl`. The returned async generator yields one
 * `ObservedBlock` per atomic store batch.
 *
 * Transient `OUT_OF_RANGE` errors from the simulator (see
 * [`isTransientBatchRaceError`]) are caught and the subscription is
 * automatically reopened — they're a documented race against concurrent
 * uploads and reconnecting fresh always recovers.
 */
export async function* subscribeBlocks(
    baseUrl: string,
    signal?: AbortSignal,
): AsyncGenerator<ObservedBlock, void, void> {
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
                const block = summarizeBatch(batch);
                if (block) {
                    yield block;
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

/**
 * Collapse a batch of `TX_BY_H` rows into a single block summary.
 *
 * Returns `undefined` for empty or malformed batches so the UI never has to
 * deal with a "block of zero transactions" row. Every row in a single batch
 * carries the same block height by construction of the indexer publisher;
 * we still take the max defensively in case future families share the
 * stream.
 */
function summarizeBatch(batch: StoreBatch): ObservedBlock | undefined {
    let height: bigint | undefined;
    let txCount = 0;
    for (const entry of batch.entries) {
        const decoded = decodeTxByHeightKey(entry.key, entry.value);
        if (decoded === undefined) {
            continue;
        }
        if (height === undefined || decoded > height) {
            height = decoded;
        }
        txCount++;
    }
    if (height === undefined || txCount === 0) {
        return undefined;
    }
    return {
        height,
        txCount,
        arrivedAt: Date.now(),
        sequence: batch.sequenceNumber,
    };
}

function decodeTxByHeightKey(key: Uint8Array, value: Uint8Array): bigint | undefined {
    if (key.length !== TX_BY_H_PAYLOAD_LEN || value.length !== TX_DIGEST_LEN) {
        // Skip rows that don't look like a TX_BY_H entry. The simulator may
        // grow new families later that incidentally match the prefix range
        // (it shouldn't, but better silent-skip than crashing the whole
        // subscription).
        return undefined;
    }
    const view = new DataView(key.buffer, key.byteOffset, key.byteLength);
    return view.getBigUint64(0, false);
}
