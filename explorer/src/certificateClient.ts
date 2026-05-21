import type {
    CertificateWorkerRequest,
    CertificateWorkerResponse,
} from './certificateWorkerTypes';

type CertificateListener = (response: CertificateWorkerResponse) => void;

let certificateWorker: Worker | null = null;
let activeStreamKey = '';
const listeners = new Set<CertificateListener>();

export function startCertificateVerificationStream({
    storeUrl,
    simplexVerificationMaterial,
}: {
    readonly storeUrl: string;
    readonly simplexVerificationMaterial: string;
}) {
    const streamKey = `${storeUrl}\n${simplexVerificationMaterial}`;
    if (activeStreamKey === streamKey) return;
    activeStreamKey = streamKey;

    const request: CertificateWorkerRequest = {
        kind: 'start',
        storeUrl,
        simplexVerificationMaterial,
    };
    getCertificateWorker().postMessage(request);
}

export function subscribeCertificateVerification(
    listener: CertificateListener,
): () => void {
    listeners.add(listener);
    getCertificateWorker();
    return () => {
        listeners.delete(listener);
    };
}

function getCertificateWorker(): Worker {
    if (certificateWorker) {
        return certificateWorker;
    }

    certificateWorker = new Worker(new URL('./certificateWorker.ts', import.meta.url), {
        type: 'module',
    });
    certificateWorker.onmessage = (event: MessageEvent<CertificateWorkerResponse>) => {
        for (const listener of listeners) {
            listener(event.data);
        }
    };
    certificateWorker.onerror = (event) => {
        const detail = event.message || 'certificate worker failed';
        for (const listener of listeners) {
            listener({ kind: 'error', height: 0, detail });
        }
        certificateWorker?.terminate();
        certificateWorker = null;
        activeStreamKey = '';
    };
    return certificateWorker;
}
