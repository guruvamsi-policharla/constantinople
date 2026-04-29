import { useEffect, useMemo, useRef, useState } from 'react';
import { type ObservedBlock, subscribeBlocks } from './indexer';

/** Most recent batches to keep in the live feed. Old entries fall off the table. */
const MAX_ROWS = 200;
/** Width (chars) of the per-row throughput bar. */
const BAR_WIDTH = 48;
/** Width (chars) of the rolling sparkline in the header. */
const SPARK_WIDTH = 60;
/** 8-step unicode block ramp used for the sparkline. `' '` slot keeps zero values readable. */
const SPARK_GLYPHS = ' ▁▂▃▄▅▆▇█';

type Status =
    | { kind: 'connecting' }
    | { kind: 'live' }
    | { kind: 'error'; message: string };

const DEFAULT_INDEXER_URL = 'http://127.0.0.1:8090';

const indexerUrl = import.meta.env.VITE_INDEXER_URL ?? DEFAULT_INDEXER_URL;

export default function App() {
    const [blocks, setBlocks] = useState<ObservedBlock[]>([]);
    const [status, setStatus] = useState<Status>({ kind: 'connecting' });
    const lastSequenceRef = useRef<bigint | null>(null);

    useEffect(() => {
        const controller = new AbortController();
        let cancelled = false;

        (async () => {
            try {
                for await (const block of subscribeBlocks(indexerUrl, controller.signal)) {
                    if (cancelled) return;
                    lastSequenceRef.current = block.sequence;
                    setBlocks((current) => prependBounded(block, current));
                    setStatus({ kind: 'live' });
                }
            } catch (error) {
                if (cancelled || controller.signal.aborted) return;
                setStatus({
                    kind: 'error',
                    message: error instanceof Error ? error.message : String(error),
                });
            }
        })();

        return () => {
            cancelled = true;
            controller.abort();
        };
    }, []);

    return (
        <div className="app">
            <header className="app__header">
                <h1 className="app__title">
                    <span className="accent">constantinople</span> / explorer
                </h1>
                <StatusBadge status={status} url={indexerUrl} />
            </header>
            <SummaryPanel blocks={blocks} />
            <main className="app__main">
                <BlockTable blocks={blocks} latestSequence={lastSequenceRef.current} />
            </main>
        </div>
    );
}

function prependBounded(block: ObservedBlock, current: ObservedBlock[]): ObservedBlock[] {
    const next = [block, ...current];
    if (next.length > MAX_ROWS) {
        next.length = MAX_ROWS;
    }
    return next;
}

function StatusBadge({ status, url }: { status: Status; url: string }) {
    if (status.kind === 'connecting') {
        return (
            <span className="app__status">
                <span className="dot" />
                connecting to {url}
            </span>
        );
    }
    if (status.kind === 'error') {
        return (
            <span className="app__status error">
                <span className="dot" />
                {status.message}
            </span>
        );
    }
    return (
        <span className="app__status live">
            <span className="dot" />
            live · {url}
        </span>
    );
}

function SummaryPanel({ blocks }: { blocks: ObservedBlock[] }) {
    const stats = useMemo(() => computeStats(blocks), [blocks]);
    return (
        <section className="summary">
            <Stat label="latest height" value={stats.latestHeight ?? '—'} />
            <Stat label="blocks" value={stats.blockCount.toLocaleString()} />
            <Stat label="total txs" value={stats.totalTx.toLocaleString()} />
            <Stat label="peak txs/block" value={stats.peakTx.toLocaleString()} />
            <Stat
                label="recent throughput"
                value={
                    <span className="summary__spark" title="txs per block, oldest → newest">
                        {stats.spark}
                    </span>
                }
            />
        </section>
    );
}

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
    return (
        <div className="summary__stat">
            <div className="summary__label">{label}</div>
            <div className="summary__value">{value}</div>
        </div>
    );
}

interface DerivedStats {
    latestHeight: string | null;
    blockCount: number;
    totalTx: number;
    peakTx: number;
    spark: string;
}

function computeStats(blocks: ObservedBlock[]): DerivedStats {
    if (blocks.length === 0) {
        return {
            latestHeight: null,
            blockCount: 0,
            totalTx: 0,
            peakTx: 0,
            spark: ' '.repeat(SPARK_WIDTH),
        };
    }
    let totalTx = 0;
    let peakTx = 0;
    let maxHeight = blocks[0].height;
    for (const block of blocks) {
        totalTx += block.txCount;
        if (block.txCount > peakTx) peakTx = block.txCount;
        if (block.height > maxHeight) maxHeight = block.height;
    }
    return {
        latestHeight: maxHeight.toString(),
        blockCount: blocks.length,
        totalTx,
        peakTx,
        spark: renderSparkline(blocks, peakTx),
    };
}

/**
 * Render an oldest→newest sparkline of the last `SPARK_WIDTH` blocks. Each
 * column uses one of `SPARK_GLYPHS` (8-step unicode block ramp) sized to the
 * current peak so a single huge block doesn't crush all the others into the
 * baseline.
 */
function renderSparkline(blocks: ObservedBlock[], peakTx: number): string {
    if (peakTx <= 0) {
        return ' '.repeat(SPARK_WIDTH);
    }
    // Blocks list is newest-first; sparkline reads left-to-right oldest→newest.
    const recent = blocks.slice(0, SPARK_WIDTH).reverse();
    let out = '';
    // Left-pad with spaces if we don't have enough history yet.
    for (let pad = recent.length; pad < SPARK_WIDTH; pad++) {
        out += ' ';
    }
    for (const block of recent) {
        out += sparkGlyph(block.txCount, peakTx);
    }
    return out;
}

function sparkGlyph(value: number, peak: number): string {
    if (value <= 0) return SPARK_GLYPHS[0];
    // 8 non-empty steps (indices 1..8). Round up so any non-zero value is at
    // least visible.
    const ramp = SPARK_GLYPHS.length - 1;
    const step = Math.min(ramp, Math.max(1, Math.ceil((value / peak) * ramp)));
    return SPARK_GLYPHS[step];
}

function BlockTable({
    blocks,
    latestSequence,
}: {
    blocks: ObservedBlock[];
    latestSequence: bigint | null;
}) {
    const formatter = useMemo(
        () =>
            new Intl.DateTimeFormat(undefined, {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                fractionalSecondDigits: 3,
            }),
        [],
    );
    const peak = useMemo(() => {
        let max = 0;
        for (const block of blocks) {
            if (block.txCount > max) max = block.txCount;
        }
        return max;
    }, [blocks]);

    if (blocks.length === 0) {
        return (
            <div className="empty">
                waiting for blocks… (start the spammer to see them stream in)
            </div>
        );
    }
    return (
        <table className="block-table">
            <thead>
                <tr>
                    <th className="col-height">height</th>
                    <th className="col-txs">txs</th>
                    <th className="col-bar">throughput</th>
                    <th className="col-time">arrived</th>
                </tr>
            </thead>
            <tbody>
                {blocks.map((block) => {
                    const isFresh = latestSequence !== null && block.sequence === latestSequence;
                    return (
                        <tr key={block.sequence.toString()} className={isFresh ? 'is-fresh' : undefined}>
                            <td className="col-height">{block.height.toString()}</td>
                            <td className="col-txs">{block.txCount.toLocaleString()}</td>
                            <td className="col-bar">
                                <span className="bar">{renderBar(block.txCount, peak)}</span>
                            </td>
                            <td className="col-time">{formatter.format(block.arrivedAt)}</td>
                        </tr>
                    );
                })}
            </tbody>
        </table>
    );
}

function renderBar(value: number, peak: number): string {
    if (peak <= 0 || value <= 0) {
        return '';
    }
    // One full block per 1/BAR_WIDTH of peak; fractional remainder picks an
    // intermediate glyph so small differences are still visible.
    const exact = (value / peak) * BAR_WIDTH;
    const full = Math.floor(exact);
    const remainder = exact - full;
    const finalGlyph =
        remainder > 0 && full < BAR_WIDTH
            ? SPARK_GLYPHS[Math.min(SPARK_GLYPHS.length - 1, Math.ceil(remainder * (SPARK_GLYPHS.length - 1)))]
            : '';
    return '█'.repeat(full) + finalGlyph;
}
