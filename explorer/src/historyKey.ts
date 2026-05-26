export interface HistoryScope {
    readonly indexerUrl: string;
    readonly qmdbUrl: string;
    readonly storeUrl: string;
    readonly mempoolUrl: string;
    readonly simplexVerificationMaterial: string;
}

const HISTORY_KEY_PREFIX = 'constantinople.submitted-transactions.v2';

export function submittedTransactionHistoryKey(
    scope: HistoryScope,
    walletPublicKeyHex: string | null,
): string | null {
    if (walletPublicKeyHex === null) return null;

    return [
        HISTORY_KEY_PREFIX,
        normalizeScopeValue(scope.indexerUrl),
        normalizeScopeValue(scope.qmdbUrl),
        normalizeScopeValue(scope.storeUrl),
        normalizeScopeValue(scope.mempoolUrl),
        normalizeScopeValue(scope.simplexVerificationMaterial),
        normalizeScopeValue(walletPublicKeyHex),
    ].join(':');
}

function normalizeScopeValue(value: string): string {
    return encodeURIComponent(value.trim().replace(/\/+$/, '').toLowerCase());
}
