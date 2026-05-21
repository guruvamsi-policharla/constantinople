import { SimplexClient, SimplexRecordKind } from '@exowarexyz/simplex';
import initCrypto, { verifyFinalization } from './crypto-wasm/constantinople_explorer_crypto';
import type {
    CertificateWorkerRequest,
    CertificateWorkerResponse,
} from './certificateWorkerTypes';

const RETRY_DELAY_MS = 1_000;

interface CertificateStreamConfig {
    readonly storeUrl: string;
    readonly simplexVerificationMaterial: string;
}

interface FinalizedTransactionTarget {
    readonly height: bigint;
    readonly view: bigint;
}

const verified = new Set<number>();
let cryptoReady: Promise<unknown> | null = null;
let streamController: AbortController | null = null;
let streamRetryTimer: number | null = null;
let streamConfig: CertificateStreamConfig | null = null;

const workerScope = self as unknown as {
    onmessage: ((event: MessageEvent<CertificateWorkerRequest>) => void) | null;
    postMessage: (message: CertificateWorkerResponse) => void;
    setTimeout: typeof setTimeout;
    clearTimeout: typeof clearTimeout;
};

workerScope.onmessage = (event) => {
    const request = event.data;
    startStream({
        storeUrl: request.storeUrl,
        simplexVerificationMaterial: request.simplexVerificationMaterial,
    });
};

function startStream(config: CertificateStreamConfig) {
    streamConfig = config;
    streamController?.abort();
    if (streamRetryTimer !== null) {
        workerScope.clearTimeout(streamRetryTimer);
        streamRetryTimer = null;
    }

    streamController = new AbortController();
    void runStream(config, streamController.signal);
}

async function runStream(config: CertificateStreamConfig, signal: AbortSignal) {
    try {
        await loadCrypto();
        const simplex = new SimplexClient(trimTrailingSlash(config.storeUrl));
        for await (const batch of simplex.subscribeRaw(
            SimplexRecordKind.FinalizedByHeight,
            {},
            { signal },
        )) {
            for (const entry of batch.entries) {
                if (entry.type !== 'finalization' || entry.index !== 'height') continue;
                verifyFinalizationEntry(config, Number(entry.height), entry.finalized);
            }
        }
        if (!signal.aborted) {
            scheduleStreamRetry(config);
        }
    } catch (error) {
        if (signal.aborted) return;
        const detail = error instanceof Error ? error.message : String(error);
        if (!isRetryableCertificateError(detail)) {
            workerScope.postMessage({ kind: 'error', height: 0, detail });
            return;
        }
        scheduleStreamRetry(config);
    }
}

function verifyFinalizationEntry(
    config: CertificateStreamConfig,
    height: number,
    finalized: Uint8Array,
) {
    if (verified.has(height)) return;

    try {
        const target = verifyFinalization(
            fromHex(config.simplexVerificationMaterial),
            finalized,
        ) as FinalizedTransactionTarget;
        verified.add(height);
        workerScope.postMessage({
            kind: 'verified',
            height: Number(target.height),
            view: target.view.toString(),
        });
    } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        workerScope.postMessage({ kind: 'error', height, detail });
    }
}

function scheduleStreamRetry(config: CertificateStreamConfig) {
    if (streamRetryTimer !== null) return;
    streamRetryTimer = workerScope.setTimeout(() => {
        streamRetryTimer = null;
        if (streamConfig !== config) return;
        startStream(config);
    }, RETRY_DELAY_MS);
}

async function loadCrypto() {
    cryptoReady ??= initCrypto();
    await cryptoReady;
}

function isRetryableCertificateError(detail: string): boolean {
    return /finalization missing|not found|missing proof|failed to decode Simplex identity|failed to decode Simplex verification material|Simplex verification material contains trailing bytes|out_of_range|unavailable|fetch/i.test(
        detail,
    );
}

function fromHex(value: string): Uint8Array {
    const normalized = value.trim().replace(/^0x/i, '');
    if (!/^[0-9a-fA-F]*$/.test(normalized) || normalized.length % 2 !== 0) {
        throw new Error('invalid hex');
    }

    const bytes = new Uint8Array(normalized.length / 2);
    for (let index = 0; index < bytes.length; index++) {
        bytes[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
    }
    return bytes;
}

function trimTrailingSlash(value: string): string {
    return value.replace(/\/+$/, '');
}
