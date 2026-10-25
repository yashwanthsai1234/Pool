// The console ports that the contract routes and the public node already serve (I-W-10), built from the shared pieces: the
// frame-signed API client (`frameApiClient`) and the JSON-RPC reader (`xrplRpc`). Nothing here holds a key.
import { fromBase64Strict } from '@legx/core/pq';
import type { ReleaseInput } from '@legx/core/releaseGate';
import type { ApiClient } from '../../../lib/api.ts';
import { xrplRpc } from '../../../lib/xrpl-rpc.ts';
import type { LedgerRelay, PublicLedger } from './ports.ts';

/** `ledger.*` of the contracts: the gate's validated snapshot (bytes travel as `{"$b64"}`), the sequence, and the submit path. */
export function contractLedgerRelay(api: ApiClient): LedgerRelay {
  return {
    async snapshot(dealId) {
      const { releaseInput } = await api.ledger.snapshot({ dealId });
      return JSON.parse(JSON.stringify(releaseInput), (_k, v) =>
        v && typeof v === 'object' && typeof v.$b64 === 'string' ? fromBase64Strict(v.$b64) : v,
      ) as ReleaseInput;
    },
    async accountSequence(address) {
      const r = await api.ledger.accountInfo({ address });
      if (!r.exists) throw new Error('ACCOUNT_NOT_FOUND');
      return r.sequence;
    },
    async submit(txBlobHex) {
      const r = await api.ledger.submit({ txBlob: txBlobHex });
      return r.status === 'validated'
        ? { validated: true, hash: r.hash, ledgerIndex: r.ledgerIndex, result: r.result }
        : { validated: false, hash: '', ledgerIndex: 0, result: r.status === 'rejected' ? r.result : 'expired' };
    },
  };
}

/** The lawyer's own read-only connection to a public node (OD-10): the coordinator is never the only source of a ledger hash. */
export function rpcPublicLedger(url: string, fetchImpl?: typeof fetch): PublicLedger {
  const rpc = xrplRpc(url, fetchImpl);
  return {
    async latest() {
      const l = await rpc.header('validated');
      return { index: l.index, hash: l.hash, closeTime: l.closeTime };
    },
    async hashAt(index) {
      return (await rpc.header(index).catch(() => undefined))?.hash;
    },
  };
}
