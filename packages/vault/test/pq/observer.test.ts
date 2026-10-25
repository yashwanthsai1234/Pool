// OD-31: the projector's pinned `observer` key. The demo seeding makes it (Node `crypto`, PKCS#8 hex); the dashboard
// signs its feed upgrade with it. The signatures verify as any enrollment key's would (the coordinator's own verifier
// runs in tests/system). Read-only by construction: the signer only produces API-request signatures.
import { generateKeyPairSync } from 'node:crypto';
import { ApiAuth } from '@legx/contracts/api';
import { fromBase64Strict, mldsaVerify } from '@legx/core/pq';
import { ed25519 } from '@noble/curves/ed25519.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { apiRequestMessage, apiRequestSigner } from '../../src/pq/apiRequest.ts';
import { observerSigner } from '../../src/pq/observer.ts';

const hexOf = (k: Buffer) => k.toString('hex');
function seeded() {
  const ed = generateKeyPairSync('ed25519');
  const pq = generateKeyPairSync('ml-dsa-65');
  return {
    cfg: {
      keyId: 'observer-1',
      ed25519Pkcs8: hexOf(ed.privateKey.export({ format: 'der', type: 'pkcs8' })),
      mlDsa65Pkcs8: hexOf(pq.privateKey.export({ format: 'der', type: 'pkcs8' })),
    },
    edPub: new Uint8Array(ed.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)),
    pqPub: new Uint8Array(pq.publicKey.export({ format: 'der', type: 'spki' }).subarray(-1952)),
  };
}

describe('OD-31 observer signer', () => {
  it('signs the upgrade GET /ws; both halves verify under the pair key ids', async () => {
    const k = seeded();
    const sign = apiRequestSigner(observerSigner(k.cfg), async () => 4242);
    const req = { method: 'GET', path: '/ws', body: new Uint8Array() };
    const auth = ApiAuth.parse(await sign(req));
    expect(auth.signatures.map((s) => s.keyid)).toEqual(['observer-1#ed25519', 'observer-1#ml-dsa-65']);
    const msg = apiRequestMessage(req, hexToBytes(auth.nonce), 4242);
    const [ed, pq] = auth.signatures.map((s) => fromBase64Strict(s.sig) as Uint8Array);
    expect(ed25519.verify(ed as Uint8Array, msg, k.edPub, { zip215: false })).toBe(true);
    expect(mldsaVerify('ml-dsa-65', k.pqPub, msg, pq as Uint8Array, 'legx/api-request/v1' as never)).toBe(true);
  });

  it('refuses any other context: an observer key signs API requests only', async () => {
    const sign = observerSigner(seeded().cfg);
    await expect(sign(new Uint8Array(32), 'legx/dsse/v1')).rejects.toMatchObject({ code: 'INPUT_INVALID' });
  });

  it('refuses a malformed key', () => {
    const k = seeded();
    expect(() => observerSigner({ ...k.cfg, ed25519Pkcs8: 'ab'.repeat(20) })).toThrow();
    expect(() =>
      observerSigner({ ...k.cfg, mlDsa65Pkcs8: `${k.cfg.mlDsa65Pkcs8.slice(0, 20)}ff${k.cfg.mlDsa65Pkcs8.slice(22)}` }),
    ).toThrow();
  });

  it('pins the whole 22-byte RFC 9881 prefix (the last prefix byte 0x20 is the seed length)', () => {
    const k = seeded();
    const pq = k.cfg.mlDsa65Pkcs8;
    expect(pq.slice(0, 44)).toBe('3034020100300b060960864801650304031204228020');
    expect(() => observerSigner({ ...k.cfg, mlDsa65Pkcs8: `${pq.slice(0, 43)}1${pq.slice(44)}` })).toThrow();
  });
});
