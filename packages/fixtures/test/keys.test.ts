import { webcrypto } from 'node:crypto';
import { p256 } from '@noble/curves/nist.js';
import { describe, expect, it } from 'vitest';
import { ecKeyFromSeed, rsaPssKeyFromSeed, sign, spki } from '../src/keys.ts';

const msg = new TextEncoder().encode('to be signed');

describe('signing keys', () => {
  it('P-256: DER ECDSA-SHA256 that WebCrypto verifies; deterministic', async () => {
    const k = ecKeyFromSeed('keys', 'ec', 'P-256');
    const der = sign(k, msg);
    expect(der).toEqual(sign(k, msg));
    const pub = await webcrypto.subtle.importKey('spki', spki(k), { name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'verify',
    ]);
    const p1363 = p256.Signature.fromBytes(der, 'der').toBytes('compact');
    expect(await webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, p1363, msg)).toBe(true);
  });

  it('RSA-PSS: verifies with WebCrypto; deterministic', async () => {
    const k = rsaPssKeyFromSeed('keys', 'rsa', 2048);
    const sig = sign(k, msg);
    expect(sig).toEqual(sign(k, msg));
    const pub = await webcrypto.subtle.importKey('spki', spki(k), { name: 'RSA-PSS', hash: 'SHA-256' }, false, [
      'verify',
    ]);
    expect(await webcrypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, pub, sig, msg)).toBe(true);
  });

  it('brainpoolP256r1: an SPKI with the brainpool curve OID', () => {
    const k = ecKeyFromSeed('keys', 'bp', 'brainpoolP256r1');
    // 06 09 2B2403030208010107 = 1.3.36.3.3.2.8.1.1.7
    expect(Buffer.from(spki(k)).toString('hex')).toContain('06092b2403030208010107');
  });
});
