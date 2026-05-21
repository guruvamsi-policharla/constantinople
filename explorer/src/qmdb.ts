import { create } from '@bufbuild/protobuf';
import { createClient } from '@connectrpc/connect';
import { createTransport } from '@exowarexyz/sdk';
import { fromHex, toHex } from './codec';
import { SimplexClient } from '@exowarexyz/simplex';
import { verifyFinalization, verifyTransactionProof } from './crypto-wasm/constantinople_explorer_crypto';
import { loadCrypto } from './wallet';
import { type DecodedRow, SqlClient } from '@exowarexyz/sql';
import {
    GetOperationRangeRequestSchema,
    OperationLogService,
} from '../vendor/exoware-qmdb/src/generated/proto/qmdb/v1/operation_log_pb';

const TX_META_TABLE = 'tx_meta';
const TX_META_HEIGHT = 'height';
const TX_META_DIGEST = 'tx_digest';
const TX_META_QMDB_LOCATION = 'qmdb_location';
const TX_META_HEIGHT_SEARCH_WINDOW = 16;

export interface VerifiedTransactionProof {
    readonly location: bigint;
    readonly tip: bigint;
    readonly height: bigint;
    readonly view: bigint;
    readonly proofSizeBytes: number;
}

interface TransactionProofMetadata {
    readonly location: bigint;
    readonly height: bigint;
}

interface FinalizedTransactionTarget {
    readonly height: bigint;
    readonly view: bigint;
    readonly transactionsRoot: Uint8Array;
    readonly transactionsStart: bigint;
    readonly transactionsTip: bigint;
}

export async function fetchAndVerifyTransactionProof({
    sqlUrl,
    qmdbUrl,
    storeUrl,
    simplexVerificationMaterial,
    digest,
    height,
    signal,
}: {
    sqlUrl: string;
    qmdbUrl: string;
    storeUrl: string;
    simplexVerificationMaterial: string;
    digest: string;
    height: number;
    signal?: AbortSignal;
}): Promise<VerifiedTransactionProof> {
    await loadCrypto();
    const metadata = await fetchTransactionProofMetadata(sqlUrl, digest, height, signal);
    const target = await fetchFinalizedTransactionTarget(
        storeUrl,
        simplexVerificationMaterial,
        metadata.height,
        signal,
    );
    if (target.height !== metadata.height) {
        throw new Error(`finalized certificate height ${target.height} does not match tx height ${metadata.height}`);
    }
    if (metadata.location < target.transactionsStart || metadata.location >= target.transactionsTip) {
        throw new Error(`transaction location ${metadata.location} is outside finalized block range`);
    }

    const proof = await fetchOperationProof(qmdbUrl, metadata.location, target.transactionsTip, signal);
    const verification = verifyTransactionProof(
        target.transactionsRoot,
        proof.proof,
        proof.opsRoot,
        proof.opsRootWitness,
        proof.startLocation,
        proof.encodedOperations,
        metadata.location,
        fromHex(digest),
    ) as WasmTransactionProof;

    return {
        location: metadata.location,
        tip: target.transactionsTip,
        height: target.height,
        view: target.view,
        proofSizeBytes: verification.proofSizeBytes,
    };
}

async function fetchTransactionProofMetadata(
    sqlUrl: string,
    digest: string,
    height: number,
    signal?: AbortSignal,
): Promise<TransactionProofMetadata> {
    const sql = new SqlClient(sqlUrl);
    const minHeight = Math.max(0, height - TX_META_HEIGHT_SEARCH_WINDOW);
    const maxHeight = height + TX_META_HEIGHT_SEARCH_WINDOW;
    const digestLiteral = fixedBinarySqlLiteral(digest);
    const txRows = await sql.query(
        `SELECT ${TX_META_HEIGHT}, ${TX_META_DIGEST}, ${TX_META_QMDB_LOCATION} FROM ${TX_META_TABLE} WHERE ${TX_META_DIGEST} = ${digestLiteral} AND ${TX_META_HEIGHT} >= ${minHeight} AND ${TX_META_HEIGHT} <= ${maxHeight}`,
        { signal },
    );
    const tx = txRows.rows.find((row) => cellDigestHex(row, TX_META_DIGEST) === digest);
    if (!tx) {
        throw new Error(`tx_meta missing ${shortHex(digest)} near height ${height}`);
    }

    const location = bigintCell(tx, TX_META_QMDB_LOCATION);
    const actualHeight = Number(bigintCell(tx, TX_META_HEIGHT));
    return {
        location,
        height: BigInt(actualHeight),
    };
}

async function fetchOperationProof(
    qmdbUrl: string,
    location: bigint,
    tip: bigint,
    signal?: AbortSignal,
) {
    const rpc = createClient(OperationLogService, createTransport(`${trimTrailingSlash(qmdbUrl)}/transactions`));
    const response = await rpc.getOperationRange(
        create(GetOperationRangeRequestSchema, {
            tip,
            startLocation: location,
            maxLocations: 1,
        }),
        { signal },
    );
    if (!response.proof) {
        throw new Error('QMDB transaction proof response missing proof');
    }
    return response.proof;
}

async function fetchFinalizedTransactionTarget(
    storeUrl: string,
    simplexVerificationMaterial: string,
    height: bigint,
    _signal?: AbortSignal,
): Promise<FinalizedTransactionTarget> {
    if (simplexVerificationMaterial.trim().length === 0) {
        throw new Error('Simplex verification material is not configured');
    }
    const simplex = new SimplexClient(trimTrailingSlash(storeUrl));
    const finalized = await simplex.getFinalizationByHeightRaw(height.toString());
    if (!finalized) {
        throw new Error(`finalization missing at height ${height}`);
    }
    return verifyFinalization(fromHex(simplexVerificationMaterial), finalized) as FinalizedTransactionTarget;
}

function bytesCell(row: DecodedRow, column: string): Uint8Array {
    const value = row.values[column];
    if (!(value instanceof Uint8Array)) {
        throw new Error(`${column} was not bytes`);
    }
    return value;
}

function bigintCell(row: DecodedRow, column: string): bigint {
    const value = row.values[column];
    if (typeof value !== 'bigint') {
        throw new Error(`${column} was not u64`);
    }
    return value;
}

function cellDigestHex(row: DecodedRow, column: string): string {
    return toHex(bytesCell(row, column));
}

function shortHex(value: string): string {
    return value.length <= 18 ? value : `${value.slice(0, 10)}...${value.slice(-8)}`;
}

function fixedBinarySqlLiteral(value: string): string {
    if (!/^[0-9a-fA-F]+$/.test(value) || value.length % 2 !== 0) {
        throw new Error(`invalid fixed binary hex literal ${shortHex(value)}`);
    }
    return `X'${value.toUpperCase()}'`;
}

function trimTrailingSlash(value: string): string {
    return value.replace(/\/+$/, '');
}

interface WasmTransactionProof {
    readonly proofSizeBytes: number;
}
