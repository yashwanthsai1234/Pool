// OD-5 in the browser: vault-held hybrid keys sign API requests; core and noble verify them, and the header parses
// as contracts `ApiAuth`. The coordinator's own verifier runs in interop.test.ts (Node).
import { ApiAuth } from '@legx/contracts/api';
import { fromBase64Strict, mldsaVerify } from '@legx/core/pq';
import { ed25519 } from '@noble/curves/ed25519.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { apiRequestMessage, apiRequestSigner } from '../../src/pq/apiRequest.ts';
import { pqKeys } from '../../src/pq/keys.ts';
import { dealId, freshDb } from '../helpers.ts';

describe('OD-5 hybrid API request signing', () => {
  it('both halves verify over the api-request message; each call uses a fresh nonce', async () => {
    const id = dealId();
    const keys = pqKeys({ role: 'bob', dbName: freshDb() });
    await keys.create(id);
    const signer = await keys.hybridSigner(id, 'pair-9');
    const pub = await signer.publicKeys();
    const signRequest = apiRequestSigner(signer.signRaw, async () => 4242);
    const req = { method: 'POST', path: '/api/v1/deals/x?y=1', body: new TextEncoder().encode('{}') };
    const a = ApiAuth.parse(await signRequest(req));
    const b = ApiAuth.parse(await signRequest(req));
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.signatures.map((s) => s.keyid)).toEqual(['pair-9#ed25519', 'pair-9#ml-dsa-65']);
    const msg = apiRequestMessage(req, hexToBytes(a.nonce), a.ledgerIndex);
    const [ed, pq] = a.signatures.map((s) => fromBase64Strict(s.sig) as Uint8Array);
    expect(ed25519.verify(ed as Uint8Array, msg, pub.ed25519, { zip215: false })).toBe(true);
    expect(mldsaVerify('ml-dsa-65', pub.mlDsa65, msg, pq as Uint8Array, 'legx/api-request/v1' as never)).toBe(true);
    expect(mldsaVerify('ml-dsa-65', pub.mlDsa65, msg, pq as Uint8Array, 'legx/dsse/v1')).toBe(false);
  });

  it('a failing ledger lookup or a missing key sends nothing', async () => {
    const id = dealId();
    const keys = pqKeys({ role: 'bob', dbName: freshDb() });
    await keys.create(id);
    const signer = await keys.hybridSigner(id, 'p');
    const req = { method: 'GET', path: '/', body: new Uint8Array() };
    await expect(apiRequestSigner(signer.signRaw, () => Promise.reject(new Error('down')))(req)).rejects.toThrow();
    await expect(keys.hybridSigner(dealId(), 'p')).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });
});
