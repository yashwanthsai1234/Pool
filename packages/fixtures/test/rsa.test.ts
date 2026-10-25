import { webcrypto } from 'node:crypto';
import { sha1 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';
import { bytesToInt, intToBytes, iso9796d2Sign, modPow, rsaKeyFromSeed, rsaPssSign, rsaSpki } from '../src/rsa.ts';

const key1024 = rsaKeyFromSeed('rsa-test', 'k1024', 1024);

describe('deterministic RSA keys', () => {
  it('has the exact size, e = 65537, and d inverts e', () => {
    expect(key1024.n.toString(2)).toHaveLength(1024);
    expect(key1024.e).toBe(65537n);
    const m = 0x1234567890abcdefn;
    expect(modPow(modPow(m, key1024.e, key1024.n), key1024.d, key1024.n)).toBe(m);
    expect(key1024.p * key1024.q).toBe(key1024.n);
  });

  it('is the same for the same seed and different for another seed', () => {
    expect(rsaKeyFromSeed('rsa-test', 'k1024', 1024).n).toBe(key1024.n);
    expect(rsaKeyFromSeed('rsa-test2', 'k1024', 1024).n).not.toBe(key1024.n);
  });

  it('round-trips integers through big-endian bytes', () => {
    expect(bytesToInt(intToBytes(key1024.n, 128))).toBe(key1024.n);
    expect(() => intToBytes(key1024.n, 127)).toThrow(RangeError);
  });
});

describe('RSASSA-PSS (SHA-256, MGF1-SHA-256, salt 32)', () => {
  it('verifies with WebCrypto using the SPKI', async () => {
    const pub = await webcrypto.subtle.importKey(
      'spki',
      rsaSpki(key1024),
      { name: 'RSA-PSS', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    const msg = new TextEncoder().encode('legx');
    const sig = rsaPssSign(key1024, msg, new Uint8Array(32).fill(9));
    expect(sig).toHaveLength(128);
    expect(await webcrypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, pub, sig, msg)).toBe(true);
    sig[5] = (sig[5] ?? 0) ^ 1;
    expect(await webcrypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, pub, sig, msg)).toBe(false);
  });
});

describe('ISO/IEC 9796-2 digital signature scheme 1 (ICAO 9303 Part 11, 6.1.2.2)', () => {
  const recover = (sig: Uint8Array) => intToBytes(modPow(bytesToInt(sig), key1024.e, key1024.n), 128);
  const m2 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

  it('SHA-1: header 6A, M1 of c - 4 bits, H(M1 || M2), trailer BC', () => {
    const m1 = new Uint8Array(106).fill(0x5a);
    const f = recover(iso9796d2Sign(key1024, m1, m2, 'SHA-1'));
    expect(f[0]).toBe(0x6a);
    expect(f.slice(1, 107)).toEqual(m1);
    expect(f.slice(107, 127)).toEqual(sha1(new Uint8Array([...m1, ...m2])));
    expect(f[127]).toBe(0xbc);
  });

  it('SHA-256: trailer 34CC and M1 of 93 bytes for a 1024-bit key', () => {
    const m1 = new Uint8Array(93).fill(0xa5);
    const f = recover(iso9796d2Sign(key1024, m1, m2, 'SHA-256'));
    expect(f[0]).toBe(0x6a);
    expect(f.slice(94, 126)).toEqual(sha256(new Uint8Array([...m1, ...m2])));
    expect([f[126], f[127]]).toEqual([0x34, 0xcc]);
  });

  it('refuses an M1 of the wrong length', () => {
    expect(() => iso9796d2Sign(key1024, new Uint8Array(105), m2, 'SHA-1')).toThrow(RangeError);
  });
});
