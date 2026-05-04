import initCrypto, { ChainKey } from './crypto-wasm/constantinople_explorer_crypto';
import { toHex } from './codec';

// Passkeys gate local key activation. Chain transactions are still signed by
// a Constantinople Ed25519 account key, using the same payload shape as
// commonware-cryptography.
const DB_NAME = 'constantinople-wallet';
const DB_VERSION = 1;
const KEY_STORE = 'keys';
const META_STORAGE_KEY = 'constantinople.wallets.v1';
const SESSION_STORAGE_KEY = 'constantinople.session.v1';
const PASSKEY_TIMEOUT_MS = 90_000;

export interface WalletProfile {
    readonly publicKeyHex: string;
    readonly credentialId: string;
    readonly createdAt: number;
}

export interface ActiveWallet extends WalletProfile {
    readonly publicKey: Uint8Array;
    readonly sign: (namespace: Uint8Array, message: Uint8Array) => Promise<Uint8Array>;
}

interface StoredKey {
    readonly publicKeyHex: string;
    readonly publicKey: Uint8Array;
    readonly privateKeySeed: Uint8Array;
}

let cryptoReady: Promise<unknown> | null = null;

export function listWallets(): WalletProfile[] {
    return readProfiles().sort((a, b) => b.createdAt - a.createdAt);
}

export function readSession(): string | null {
    return window.localStorage.getItem(SESSION_STORAGE_KEY);
}

export function clearSession() {
    window.localStorage.removeItem(SESSION_STORAGE_KEY);
}

export async function createWallet(): Promise<ActiveWallet> {
    assertWalletSupport();
    await loadCrypto();

    const credential = await createPasskey();
    const privateKeySeed = randomSeed();
    const chainKey = ChainKey.fromSeed(privateKeySeed);
    const publicKey = chainKey.publicKey();
    const publicKeyHex = toHex(publicKey);
    const profile = {
        publicKeyHex,
        credentialId: encodeBase64Url(new Uint8Array(credential.rawId)),
        createdAt: Date.now(),
    };

    await putStoredKey({
        publicKeyHex,
        publicKey,
        privateKeySeed,
    });
    writeProfiles([profile, ...readProfiles().filter((item) => item.publicKeyHex !== publicKeyHex)]);
    writeSession(publicKeyHex);

    return activeWallet(profile, chainKey);
}

export async function signInWithPasskey(): Promise<ActiveWallet> {
    assertWalletSupport();
    await loadCrypto();

    const profiles = readProfiles();
    if (profiles.length === 0) {
        throw new Error('create a passkey wallet first');
    }

    const assertion = await navigator.credentials.get({
        publicKey: {
            challenge: randomChallenge(),
            timeout: PASSKEY_TIMEOUT_MS,
            userVerification: 'required',
            allowCredentials: profiles.map((profile) => ({
                type: 'public-key',
                id: decodeBase64Url(profile.credentialId),
                transports: ['internal'],
            })),
        },
    });
    if (!(assertion instanceof PublicKeyCredential)) {
        throw new Error('passkey sign-in was cancelled');
    }

    const credentialId = encodeBase64Url(new Uint8Array(assertion.rawId));
    const profile = profiles.find((candidate) => candidate.credentialId === credentialId);
    if (!profile) {
        throw new Error('passkey is not linked to a local wallet');
    }

    const stored = await getStoredKey(profile.publicKeyHex);
    if (!stored) {
        throw new Error('local Ed25519 key is missing for this passkey');
    }

    writeSession(profile.publicKeyHex);
    return activeWallet(profile, ChainKey.fromSeed(stored.privateKeySeed));
}

function activeWallet(profile: WalletProfile, chainKey: ChainKey): ActiveWallet {
    const publicKey = chainKey.publicKey();
    return {
        ...profile,
        publicKey,
        sign: async (namespace, message) => chainKey.sign(namespace, message),
    };
}

async function loadCrypto() {
    cryptoReady ??= initCrypto();
    await cryptoReady;
}

async function createPasskey(): Promise<PublicKeyCredential> {
    const credential = await navigator.credentials.create({
        publicKey: {
            challenge: randomChallenge(),
            rp: { name: 'Constantinople Explorer' },
            user: {
                id: randomChallenge(),
                name: 'constantinople-wallet',
                displayName: 'Constantinople Wallet',
            },
            pubKeyCredParams: [{ type: 'public-key', alg: -8 }],
            authenticatorSelection: {
                authenticatorAttachment: 'platform',
                residentKey: 'preferred',
                userVerification: 'required',
            },
            timeout: PASSKEY_TIMEOUT_MS,
            attestation: 'none',
        },
    });

    if (!(credential instanceof PublicKeyCredential)) {
        throw new Error('passkey creation was cancelled');
    }
    return credential;
}

function assertWalletSupport() {
    if (!window.isSecureContext) {
        throw new Error('passkeys and Ed25519 require a secure context');
    }
    if (!navigator.credentials || !window.PublicKeyCredential) {
        throw new Error('this browser does not expose passkeys');
    }
    if (!crypto.getRandomValues) {
        throw new Error('this browser does not expose secure randomness');
    }
}

function randomSeed(): Uint8Array {
    const seed = new Uint8Array(32);
    crypto.getRandomValues(seed);
    return seed;
}

function randomChallenge(): ArrayBuffer {
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);
    return challenge.buffer;
}

async function putStoredKey(key: StoredKey): Promise<void> {
    const db = await openDb();
    await requestToPromise(db.transaction(KEY_STORE, 'readwrite').objectStore(KEY_STORE).put(key));
    db.close();
}

async function getStoredKey(publicKeyHex: string): Promise<StoredKey | null> {
    const db = await openDb();
    const result = await requestToPromise<StoredKey | undefined>(
        db.transaction(KEY_STORE, 'readonly').objectStore(KEY_STORE).get(publicKeyHex),
    );
    db.close();
    return result ?? null;
}

function openDb(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        request.onupgradeneeded = () => {
            request.result.createObjectStore(KEY_STORE, { keyPath: 'publicKeyHex' });
        };
        request.onerror = () => reject(request.error ?? new Error('failed to open wallet database'));
        request.onsuccess = () => resolve(request.result);
    });
}

function requestToPromise<T = unknown>(request: IDBRequest<T>): Promise<T> {
    return new Promise((resolve, reject) => {
        request.onerror = () => reject(request.error ?? new Error('wallet database request failed'));
        request.onsuccess = () => resolve(request.result);
    });
}

function readProfiles(): WalletProfile[] {
    const raw = window.localStorage.getItem(META_STORAGE_KEY);
    if (!raw) {
        return [];
    }

    try {
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed.filter(isWalletProfile) : [];
    } catch {
        return [];
    }
}

function writeProfiles(profiles: WalletProfile[]) {
    window.localStorage.setItem(META_STORAGE_KEY, JSON.stringify(profiles));
}

function writeSession(publicKeyHex: string) {
    window.localStorage.setItem(SESSION_STORAGE_KEY, publicKeyHex);
}

function isWalletProfile(value: unknown): value is WalletProfile {
    return (
        typeof value === 'object' &&
        value !== null &&
        'publicKeyHex' in value &&
        'credentialId' in value &&
        'createdAt' in value &&
        typeof value.publicKeyHex === 'string' &&
        typeof value.credentialId === 'string' &&
        typeof value.createdAt === 'number'
    );
}

function encodeBase64Url(bytes: Uint8Array): string {
    let value = '';
    for (const byte of bytes) {
        value += String.fromCharCode(byte);
    }
    return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeBase64Url(value: string): ArrayBuffer {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
    const raw = atob(padded);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) {
        bytes[i] = raw.charCodeAt(i);
    }
    return bytes.buffer;
}
