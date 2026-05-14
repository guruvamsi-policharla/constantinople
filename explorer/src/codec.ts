const TX_NAMESPACE = new TextEncoder().encode('constantinople-tx');
const PUBLIC_KEY_BYTES = 32;
const SIGNATURE_BYTES = 64;
const U64_BYTES = 8;
const MAX_U64 = (1n << 64n) - 1n;

export interface TransactionDraft {
    readonly senderPublicKey: Uint8Array;
    readonly toPublicKey: Uint8Array;
    readonly value: bigint;
    readonly nonce: bigint;
}

export interface EncodedTransaction {
    readonly digestHex: string;
    readonly bytes: Uint8Array;
}

export function parsePublicKeyHex(value: string): Uint8Array {
    const normalized = value.trim().replace(/^0x/i, '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(normalized)) {
        throw new Error('expected a 32-byte hex public key');
    }
    return fromHex(normalized);
}

export function parseU64(value: string, field: string): bigint {
    if (!/^\d+$/.test(value.trim())) {
        throw new Error(`${field} must be an unsigned integer`);
    }

    const parsed = BigInt(value.trim());
    if (parsed > MAX_U64) {
        throw new Error(`${field} must fit in u64`);
    }
    return parsed;
}

export async function encodeSignedTransaction(
    draft: TransactionDraft,
    sign: (namespace: Uint8Array, message: Uint8Array) => Promise<Uint8Array>,
): Promise<EncodedTransaction> {
    if (draft.value === 0n) {
        throw new Error('value must be greater than zero');
    }

    const body = encodeTransactionBody(draft);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body)));
    const signature = await sign(TX_NAMESPACE, digest);
    if (signature.length !== SIGNATURE_BYTES) {
        throw new Error(`expected ${SIGNATURE_BYTES}-byte Ed25519 signature`);
    }

    return {
        digestHex: toHex(digest),
        bytes: bytesConcat(body, signature),
    };
}

export function encodeTransactionBatch(transactions: Uint8Array[]): Uint8Array {
    return bytesConcat(encodeUsize(transactions.length), ...transactions);
}

export function toHex(bytes: Uint8Array): string {
    return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    const copy = new Uint8Array(bytes.length);
    copy.set(bytes);
    return copy.buffer;
}

export function fromHex(value: string): Uint8Array {
    const bytes = new Uint8Array(value.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

function encodeTransactionBody(draft: TransactionDraft): Uint8Array {
    assertByteLength(draft.senderPublicKey, PUBLIC_KEY_BYTES, 'sender public key');
    assertByteLength(draft.toPublicKey, PUBLIC_KEY_BYTES, 'recipient public key');

    return bytesConcat(
        draft.senderPublicKey,
        draft.toPublicKey,
        encodeU64(draft.value),
        encodeU64(draft.nonce),
    );
}

function encodeU64(value: bigint): Uint8Array {
    if (value < 0n || value > MAX_U64) {
        throw new Error('u64 value out of range');
    }

    const bytes = new Uint8Array(U64_BYTES);
    new DataView(bytes.buffer).setBigUint64(0, value, false);
    return bytes;
}

function encodeUsize(value: number): Uint8Array {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
        throw new Error('usize value out of range');
    }

    const bytes: number[] = [];
    let next = value;
    while (next >= 0x80) {
        bytes.push((next & 0x7f) | 0x80);
        next = Math.floor(next / 0x80);
    }
    bytes.push(next);
    return new Uint8Array(bytes);
}

function bytesConcat(...chunks: Uint8Array[]): Uint8Array {
    const len = chunks.reduce((total, chunk) => total + chunk.length, 0);
    const out = new Uint8Array(len);
    let offset = 0;
    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.length;
    }
    return out;
}

function assertByteLength(bytes: Uint8Array, expected: number, label: string) {
    if (bytes.length !== expected) {
        throw new Error(`${label} must be ${expected} bytes`);
    }
}
