// The phone's and the dashboard's own read-only view of a public XRPL node over JSON-RPC (OD-10): the validated ledger
// index (the signed-request ledger index), its close time, and the ledger index of a transaction. No xrpl.js, so it
// costs nothing in the entry bundle; the node's origin must be in `connect-src` (`LEGX_CONNECT_SRC`, csp.ts).
// Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/ledger-methods/ledger
// Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/transaction-methods/tx
type Result = Record<string, unknown> & { validated?: unknown; status?: unknown };

export function xrplRpc(url: string, fetchImpl: typeof fetch = (...a) => fetch(...a)) {
  const call = async (method: string, params: object): Promise<Result | undefined> => {
    const res = await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ method, params: [params] }),
    });
    const { result } = (await res.json()) as { result?: Result };
    return result?.status === 'error' ? undefined : result;
  };
  /** A validated ledger header by index or the newest one. A ledger the node does not hold, or has not validated, throws. */
  const header = async (at: number | 'validated') => {
    const r = await call('ledger', { ledger_index: at });
    const ledger = r?.ledger as { ledger_index?: unknown; close_time?: unknown } | undefined;
    const index = Number(r?.ledger_index ?? ledger?.ledger_index);
    if (r?.validated === false || !Number.isInteger(index) || (at !== 'validated' && r?.validated !== true))
      throw new Error('no validated ledger');
    return { index, hash: String(r?.ledger_hash ?? ''), closeTime: Number(ledger?.close_time ?? 0) };
  };
  const latest = () => header('validated');
  return {
    header,
    latest,
    validatedIndex: async () => (await latest()).index,
    /** Only a validated transaction counts: anything else is `undefined`. */
    txLedgerIndex: async (hash: string): Promise<number | undefined> => {
      const r = await call('tx', { transaction: hash });
      return r?.validated === true && Number.isInteger(r.ledger_index) ? (r.ledger_index as number) : undefined;
    },
  };
}
