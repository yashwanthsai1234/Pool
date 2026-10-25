// The coordinator's ledger relay over HTTP. These routes are not in `@legx/contracts` yet (request in the status file),
// so the adapter takes a `fetch` that signs requests (the API client's signing) and the tests answer it with MSW.
// Byte fields travel as `{"$b64": "..."}`.
import { fromBase64Strict, toBase64 } from '@legx/core/pq';
import type { ReleaseInput } from '@legx/core/releaseGate';
import type { LedgerRelay } from './ports.ts';

type Fetch = (path: string, init?: RequestInit) => Promise<Response>;

export const encodeSnapshot = (i: ReleaseInput): string =>
  JSON.stringify(i, (_k, v) => (v instanceof Uint8Array ? { $b64: toBase64(v) } : v));

export const decodeSnapshot = (text: string): ReleaseInput =>
  JSON.parse(text, (_k, v) =>
    v && typeof v === 'object' && typeof v.$b64 === 'string' ? (fromBase64Strict(v.$b64) as Uint8Array) : v,
  );

export function httpLedgerRelay(doFetch: Fetch, base = '/api'): LedgerRelay {
  const ok = async (r: Response) => {
    if (!r.ok) throw new Error(`ledger relay answered ${r.status}`);
    return r;
  };
  return {
    async snapshot(dealId) {
      return decodeSnapshot(await (await ok(await doFetch(`${base}/deals/${dealId}/ledger-snapshot`))).text());
    },
    async accountSequence(address) {
      const r = await ok(await doFetch(`${base}/ledger/accounts/${address}/sequence`));
      return ((await r.json()) as { sequence: number }).sequence;
    },
    async submit(txBlobHex) {
      const r = await ok(
        await doFetch(`${base}/ledger/submit`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ tx_blob: txBlobHex }),
        }),
      );
      return (await r.json()) as Awaited<ReturnType<LedgerRelay['submit']>>;
    },
  };
}
