export interface HeightedBlock {
    readonly height: bigint;
}

export interface BlockSequenceCursor {
    latestHeight: bigint | null;
    readonly seenHeights: Set<string>;
    readonly seenHeightOrder: string[];
    readonly maxSeenHeights: number;
}

const DEFAULT_MAX_SEEN_HEIGHTS = 4_096;

export function createBlockSequenceCursor(
    maxSeenHeights = DEFAULT_MAX_SEEN_HEIGHTS,
): BlockSequenceCursor {
    return {
        latestHeight: null,
        seenHeights: new Set(),
        seenHeightOrder: [],
        maxSeenHeights: Math.max(1, Math.floor(maxSeenHeights)),
    };
}

export function collectLiveBlocks<T extends HeightedBlock>(
    cursor: BlockSequenceCursor,
    blocks: Iterable<T>,
): T[] {
    const next: T[] = [];
    for (const block of blocks) {
        if (hasSeen(cursor, block.height)) {
            continue;
        }

        if (cursor.latestHeight === null || block.height > cursor.latestHeight) {
            cursor.latestHeight = block.height;
        }
        addIfNew(cursor, next, block);
    }
    return next;
}

export async function collectNewBlocks<T extends HeightedBlock>(
    cursor: BlockSequenceCursor,
    blocks: Iterable<T>,
    fetchMissing: (fromHeight: bigint, toHeight: bigint) => Promise<readonly T[]>,
): Promise<T[]> {
    const next: T[] = [];
    for (const block of blocks) {
        if (hasSeen(cursor, block.height)) {
            continue;
        }

        if (cursor.latestHeight !== null && block.height > cursor.latestHeight + 1n) {
            for (const missing of await fetchMissing(cursor.latestHeight + 1n, block.height - 1n)) {
                addIfNew(cursor, next, missing);
            }
        }

        if (cursor.latestHeight === null || block.height > cursor.latestHeight) {
            cursor.latestHeight = block.height;
        }
        addIfNew(cursor, next, block);
    }
    return next;
}

function addIfNew<T extends HeightedBlock>(
    cursor: BlockSequenceCursor,
    blocks: T[],
    block: T,
): void {
    if (hasSeen(cursor, block.height)) {
        return;
    }
    rememberHeight(cursor, block.height);
    blocks.push(block);
}

function hasSeen(cursor: BlockSequenceCursor, height: bigint): boolean {
    return cursor.seenHeights.has(heightKey(height));
}

function rememberHeight(cursor: BlockSequenceCursor, height: bigint): void {
    const key = heightKey(height);
    cursor.seenHeights.add(key);
    cursor.seenHeightOrder.push(key);

    while (cursor.seenHeightOrder.length > cursor.maxSeenHeights) {
        const stale = cursor.seenHeightOrder.shift();
        if (stale !== undefined) {
            cursor.seenHeights.delete(stale);
        }
    }
}

function heightKey(height: bigint): string {
    return height.toString();
}
