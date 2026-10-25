// The projector dashboard's own signed feed upgrade (OD-31, I-W-11). The demo seeding makes a hybrid `observer`
// enrollment key and registers it like any holder key; the dashboard build receives it as `VITE_LEGX_OBSERVER`
// (JSON `{keyId, ed25519Pkcs8, mlDsa65Pkcs8}`). It signs `GET /ws` only (the observer may subscribe and read, never post),
// and never in the production profile, where an observer key in a bundle would be wrong.
// Source: build/DECISIONS.md OD-31; apps/server/src/live.ts (the upgrade is a signed GET on `/ws`, `?auth=`)
import type { LedgerValidated } from '@legx/contracts/ws';
import { apiRequestSigner, type ObserverKey, observerSigner } from '@legx/vault';
import type { z } from 'zod';
import type { LiveFeedOptions } from './live.ts';
import { LIVE_PATH } from './paths.ts';
import { xrplRpc } from './xrpl-rpc.ts';

type Env = Readonly<Record<string, string | boolean | undefined>>;
type Feed = Required<Pick<LiveFeedOptions, 'auth' | 'onLedger'>>;

function parse(raw: unknown): ObserverKey | undefined {
  if (typeof raw !== 'string' || raw === '') return undefined;
  try {
    const k = JSON.parse(raw) as Partial<ObserverKey>;
    return typeof k.keyId === 'string' && typeof k.ed25519Pkcs8 === 'string' && typeof k.mlDsa65Pkcs8 === 'string'
      ? { keyId: k.keyId, ed25519Pkcs8: k.ed25519Pkcs8, mlDsa65Pkcs8: k.mlDsa65Pkcs8 }
      : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The feed options that sign the upgrade, or undefined when no observer key is configured (then the feed is
 * unauthenticated and the server refuses it: the dashboard shows "reconnecting", never a fake live state).
 * The signed ledger index is the newest `ledger.validated` push; the first connect reads it from the public XRPL node
 * named by `VITE_LEGX_XRPL_RPC` (OD-10: the coordinator is never the only source; `/health` is signed and carries none).
 * Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/ledger-methods/ledger (JSON-RPC)
 */
export function observerFeed(env: Env, fetchRpc: typeof fetch = (...a) => fetch(...a)): Feed | undefined {
  if (env.VITE_LEGX_PROFILE === 'production') return undefined;
  const key = parse(env.VITE_LEGX_OBSERVER);
  if (!key) return undefined;
  let latest: number | undefined;
  const rpc =
    typeof env.VITE_LEGX_XRPL_RPC === 'string' && env.VITE_LEGX_XRPL_RPC !== ''
      ? xrplRpc(env.VITE_LEGX_XRPL_RPC, fetchRpc)
      : undefined;
  const ledgerIndex = async () => {
    if (latest !== undefined) return latest;
    if (!rpc) throw new Error('no ledger source');
    return rpc.validatedIndex();
  };
  const sign = apiRequestSigner(observerSigner(key), ledgerIndex);
  return {
    auth: async () => JSON.stringify(await sign({ method: 'GET', path: LIVE_PATH, body: new Uint8Array() })),
    onLedger: (l: z.infer<typeof LedgerValidated>) => {
      latest = l.index;
    },
  };
}
