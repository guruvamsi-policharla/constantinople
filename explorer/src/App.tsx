import { useEffect, useMemo, useRef, useState } from 'react';
import {
    type ObservedBatch,
    type ObservedTx,
    subscribeTransactions,
} from './indexer';

/** Most recent transactions to keep in the live feed. */
const MAX_ROWS = 500;

type Status =
    | { kind: 'connecting' }
    | { kind: 'live'; batches: number }
    | { kind: 'error'; message: string };

const DEFAULT_INDEXER_URL = 'http://127.0.0.1:8090';

const indexerUrl =
    import.meta.env.VITE_INDEXER_URL ?? DEFAULT_INDEXER_URL;

export default function App() {
    const [transactions, setTransactions] = useState<ObservedTx[]>([]);
    const [status, setStatus] = useState<Status>({ kind: 'connecting' });
    // The latest batch sequence — used to highlight rows that just arrived.
    const lastBatchRef = useRef<bigint | null>(null);

    useEffect(() => {
        const controller = new AbortController();
        let cancelled = false;
        let batchCount = 0;

        (async () => {
            try {
                for await (const batch of subscribeTransactions(
                    indexerUrl,
                    controller.signal,
                )) {
                    if (cancelled) return;
                    batchCount++;
                    appendBatch(batch, setTransactions, lastBatchRef);
                    setStatus({ kind: 'live', batches: batchCount });
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
            <main className="app__main">
                <TxTable transactions={transactions} latestBatch={lastBatchRef.current} />
            </main>
        </div>
    );
}

function appendBatch(
    batch: ObservedBatch,
    setTransactions: React.Dispatch<React.SetStateAction<ObservedTx[]>>,
    lastBatchRef: React.MutableRefObject<bigint | null>,
) {
    lastBatchRef.current = batch.sequence;
    setTransactions((current) => {
        // Newest at the top. Trim to MAX_ROWS so the DOM stays bounded during
        // long spammer runs.
        const next = [...batch.transactions].reverse().concat(current);
        if (next.length > MAX_ROWS) {
            next.length = MAX_ROWS;
        }
        return next;
    });
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
            live · {status.batches} batch{status.batches === 1 ? '' : 'es'} · {url}
        </span>
    );
}

function TxTable({
    transactions,
    latestBatch,
}: {
    transactions: ObservedTx[];
    latestBatch: bigint | null;
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

    if (transactions.length === 0) {
        return (
            <div className="empty">
                waiting for transactions… (start the spammer to see them stream in)
            </div>
        );
    }
    return (
        <table className="tx-table">
            <thead>
                <tr>
                    <th className="col-height">height</th>
                    <th className="col-index">idx</th>
                    <th className="col-digest">tx digest</th>
                    <th className="col-time">arrived</th>
                </tr>
            </thead>
            <tbody>
                {transactions.map((tx) => {
                    const key = `${tx.height.toString()}:${tx.index}:${tx.digestHex}`;
                    const isFresh = latestBatch !== null && tx.sequence === latestBatch;
                    return (
                        <tr key={key} className={isFresh ? 'is-fresh' : undefined}>
                            <td className="col-height">{tx.height.toString()}</td>
                            <td className="col-index">{tx.index}</td>
                            <td className="col-digest" title={tx.digestHex}>
                                {tx.digestHex}
                            </td>
                            <td className="col-time">{formatter.format(tx.arrivedAt)}</td>
                        </tr>
                    );
                })}
            </tbody>
        </table>
    );
}
