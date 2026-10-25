// OD-5 interop (Node): the vault's API-request signer against the coordinator's own verifier (task 3.2's
// `authenticate`), with the coordinator's database and ledger stubbed. The browser half (vault-held keys) is in
// apiRequest.browser.test.ts; this file shows both sides agree on the bytes, the context and the key ids.

import type { MlDsaContext } from '@legx/contracts/ports';
import type { KeyId } from '@legx/contracts/values';
import { authenticate, apiRequestMessage as coordMessage } from '@legx/coordinator/auth';
import { mldsaSign, pqKeygen, toBase64 } from '@legx/core/pq';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { apiRequestMessage, apiRequestSigner } from '../../src/pq/apiRequest.ts';
import type { HybridRaw } from '../../src/pq/keys.ts';

const DEAL = '0192f3a0-0000-7000-8000-000000000009';
const edSk = ed25519.utils.randomSecretKey();
const pq = pqKeygen();
const ids = { ed25519: 'pair-1#ed25519' as KeyId, mlDsa65: 'pair-1#ml-dsa-65' as KeyId };
const sign: HybridRaw = async (msg, ctx) => ({
  ed25519: ed25519.sign(msg, edSk),
  mlDsa65: mldsaSign('ml-dsa-65', pq.secretKey, msg, ctx as MlDsaContext),
  keyIds: ids,
});

function deps(validated = 1000) {
  const used = new Set<string>();
  return {
    ledger: { validatedLedger: async () => ({ ledgerIndex: validated, closeTime: 10 }) },
    db: {
      repos: {
        enrollmentKeys: {
          getUsable: async () => ({
            valid_from: 0,
            mldsa65_pub: toBase64(pq.publicKey),
            ed25519_pub: bytesToHex(ed25519.getPublicKey(edSk)),
            deal_id: DEAL,
            slot: 'A',
            holder_role: 'phone',
          }),
        },
        usedNonces: { consume: async (n: string) => !used.has(n) && !!used.add(n) },
      },
    },
    lawyerKeys: () => undefined,
  } as never;
}
const rule = { kind: 'signed-request', callers: ['alice'] } as const;

describe('OD-5 API requests: vault signer against the coordinator verifier', () => {
  it('the message bytes are the same for any method, path, body, nonce and ledger index', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('GET', 'POST', 'PUT'),
        fc.string(),
        fc.uint8Array({ maxLength: 300 }),
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        fc.integer({ min: 1, max: 0xffffffff }),
        (method, path, body, nonce, idx) => {
          const mine = apiRequestMessage({ method, path, body }, nonce, idx);
          expect(bytesToHex(mine)).toBe(bytesToHex(coordMessage(method, path, body, bytesToHex(nonce), idx)));
        },
      ),
      { numRuns: 50 },
    );
  });

  it('a signed request authenticates; a replay, an old ledger index and a changed body are refused', async () => {
    const d = deps();
    const req = { method: 'POST', path: `/api/v1/deals/${DEAL}/x`, body: new TextEncoder().encode('{"a":1}') };
    const auth = await apiRequestSigner(sign, async () => 1000)(req);
    const raw = { method: req.method, path: req.path, body: req.body, header: JSON.stringify(auth), dealId: DEAL };
    await expect(authenticate(d, rule as never, raw)).resolves.toMatchObject({ kind: 'deal', role: 'alice' });
    await expect(authenticate(d, rule as never, raw)).rejects.toMatchObject({ code: 'nonce_reused' });
    const old = await apiRequestSigner(sign, async () => 979)(req);
    await expect(authenticate(d, rule as never, { ...raw, header: JSON.stringify(old) })).rejects.toMatchObject({
      code: 'stale_ledger_index',
    });
    const fresh = await apiRequestSigner(sign, async () => 1000)(req);
    const changed = { ...raw, header: JSON.stringify(fresh), body: new TextEncoder().encode('{"a":2}') };
    await expect(authenticate(d, rule as never, changed)).rejects.toMatchObject({ code: 'bad_signature' });
  });

  it('refuses a bad nonce length or ledger index before signing', () => {
    const r = { method: 'GET', path: '/', body: new Uint8Array() };
    expect(() => apiRequestMessage(r, randomBytes(31), 1)).toThrow('INPUT_INVALID');
    expect(() => apiRequestMessage(r, randomBytes(32), -1)).toThrow('INPUT_INVALID');
    expect(() => apiRequestMessage(r, randomBytes(32), 2 ** 32)).toThrow('INPUT_INVALID');
  });
});
