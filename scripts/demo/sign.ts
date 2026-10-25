// The demo's request signer (closes I-D-1 to I-D-3): scripts sign hybrid OD-5 requests with the demo enrollment keys
// that `seed.ts` makes (lawyers, observer, operator). It is the same signer the dashboard and the vault use: Ed25519
// plus ML-DSA-65 over tupleHash("legx/api-request/v1", [method, path, SHA-256(body), nonce32, ledgerIndex]), context
// "legx/api-request/v1", and nothing else (the observer signer refuses any other context).
// Source: build/DECISIONS.md OD-5, OD-8 (the path is pathname + search as sent), OD-31 (observer)
import { createHash } from 'node:crypto';
import { API_AUTH_HEADER } from '../../packages/contracts/src/api.ts';
import { apiRequestSigner } from '../../packages/vault/src/pq/apiRequest.ts';
import { observerSigner } from '../../packages/vault/src/pq/observer.ts';

/** A demo enrollment key: the private halves are PKCS#8 DER hex (seed only), the public halves SPKI DER hex. */
export interface DemoKey {
  readonly keyId: string;
  readonly ed25519Private: string;
  readonly mlDsa65Private: string;
  readonly ed25519Public: string;
  readonly mlDsa65Public: string;
}

export interface Signed {
  readonly url: string;
  readonly init: RequestInit;
}

const requestSigner = (key: DemoKey) =>
  observerSigner({ keyId: key.keyId, ed25519Pkcs8: key.ed25519Private, mlDsa65Pkcs8: key.mlDsa65Private });

/** `validated()` returns the newest validated ledger index (the request is valid for 20 ledgers, OD-5). */
export function demoSigner(key: DemoKey, validated: () => Promise<number>) {
  const sign = apiRequestSigner(requestSigner(key), validated);
  return {
    /** A signed request for `fetch`. `body` is JSON and is sent byte for byte as it was signed. */
    async request(serverUrl: string, method: 'GET' | 'POST', path: string, body?: unknown): Promise<Signed> {
      const payload = body === undefined ? undefined : JSON.stringify(body);
      const auth = await sign({ method, path, body: new TextEncoder().encode(payload ?? '') });
      return {
        url: `${serverUrl}${path}`,
        init: {
          method,
          headers: {
            [API_AUTH_HEADER]: JSON.stringify(auth),
            ...(payload === undefined ? {} : { 'content-type': 'application/json' }),
          },
          ...(payload === undefined ? {} : { body: payload }),
        },
      };
    },
    /** The `auth` query value of a live-feed upgrade (browsers cannot set headers on a WebSocket). */
    async feedAuth(path = '/ws'): Promise<string> {
      return JSON.stringify(await sign({ method: 'GET', path, body: new Uint8Array() }));
    },
  };
}

/** The key as the server pins it (`LEGX_LAWYER_KEYS` and the like): raw Ed25519 as hex, raw ML-DSA-65 as base64. */
export function pinnedForm(key: DemoKey): { ed25519: string; mlDsa65: string } {
  return {
    ed25519: key.ed25519Public.slice(-64),
    mlDsa65: Buffer.from(key.mlDsa65Public.slice(-1952 * 2), 'hex').toString('base64'),
  };
}

export const sha256Hex = (b: string | Uint8Array) => createHash('sha256').update(b).digest('hex');
