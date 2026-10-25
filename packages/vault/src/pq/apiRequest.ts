// Hybrid signing of API requests (OD-5, DESIGN 8.10): both enrollment-key halves sign
// tupleHash("legx/api-request/v1", [utf8(method), utf8(path), SHA-256(body), nonce32, uint32_be(ledgerIndex)]),
// ML-DSA under the context `legx/api-request/v1`. The result is the `x-legx-auth` header value (contracts `ApiAuth`).
// Source: DESIGN.md 8.10 "Access"; build/DECISIONS.md OD-5; services/coordinator/src/auth.ts (the verifier)
import type { ApiAuth } from '@legx/contracts/api';
import { bytesToHex, sha256, tupleHash, utf8ToBytes } from '@legx/core/dealcore';
import { toBase64 } from '@legx/core/pq';
import type { z } from 'zod';
import { VaultError } from '../errors.ts';
import type { HybridRaw } from './keys.ts';

const API_REQUEST_TAG = 'legx/api-request/v1';

export interface SignableRequest {
  readonly method: string;
  /** Path and query exactly as sent, including the API prefix. */
  readonly path: string;
  readonly body: Uint8Array;
}

/** The signed message. `ledgerIndex` is a uint32 (XRPL ledger sequence). */
export function apiRequestMessage(req: SignableRequest, nonce: Uint8Array, ledgerIndex: number): Uint8Array {
  if (nonce.length !== 32 || !Number.isInteger(ledgerIndex) || ledgerIndex < 0 || ledgerIndex > 0xffffffff)
    throw new VaultError('INPUT_INVALID');
  const idx = new Uint8Array(4);
  new DataView(idx.buffer).setUint32(0, ledgerIndex);
  return tupleHash(API_REQUEST_TAG, [utf8ToBytes(req.method), utf8ToBytes(req.path), sha256(req.body), nonce, idx]);
}

/**
 * The web client's `signRequest` (apps/web `createApiClient`): a fresh single-use nonce, the latest validated ledger
 * index from `ledgerIndex()`, and both signatures. A failing signer throws, so nothing is sent.
 */
export function apiRequestSigner(sign: HybridRaw, ledgerIndex: () => Promise<number>) {
  return async (req: SignableRequest): Promise<z.infer<typeof ApiAuth>> => {
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    const index = await ledgerIndex();
    const msg = apiRequestMessage(req, nonce, index);
    const sig = await sign(msg, API_REQUEST_TAG);
    return {
      nonce: bytesToHex(nonce),
      ledgerIndex: index,
      signatures: [
        { keyid: sig.keyIds.ed25519, sig: toBase64(sig.ed25519) },
        { keyid: sig.keyIds.mlDsa65, sig: toBase64(sig.mlDsa65) },
      ] as z.infer<typeof ApiAuth>['signatures'],
    } as z.infer<typeof ApiAuth>;
  };
}
