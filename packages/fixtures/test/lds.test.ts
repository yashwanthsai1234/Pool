import { describe, expect, it } from 'vitest';
import { decodeLds, encodeLds, ID_SHA256, type Lds } from '../src/lds.ts';

const h = (dg: number, len = 32) => ({ dg, hash: new Uint8Array(len).fill(dg) });
const good: Lds = {
  version: 1,
  hashAlgorithm: ID_SHA256,
  hashes: [h(1), h(15)],
  ldsVersion: { lds: '0108', unicode: '040000' },
};

describe('LDSSecurityObject schema (ICAO 9303 Part 10 4.6.2.3)', () => {
  it('round-trips v1 with ldsVersionInfo and v0 without', () => {
    expect(decodeLds(encodeLds(good))).toEqual(good);
    const v0: Lds = { version: 0, hashAlgorithm: ID_SHA256, hashes: [h(1), h(2)] };
    expect(decodeLds(encodeLds(v0))).toEqual(v0);
  });

  it.each([
    ['1 entry', { ...good, hashes: [h(1)] }, /2 to 16 entries, found 1/],
    ['17 entries', { ...good, hashes: Array.from({ length: 17 }, (_, i) => h((i % 16) + 1)) }, /found 17/],
    ['v1 without ldsVersionInfo', { version: 1, hashAlgorithm: ID_SHA256, hashes: [h(1), h(2)] }, /version must be v1/],
    ['v0 with ldsVersionInfo', { ...good, version: 0 }, /version must be v1/],
    ['an unknown hash algorithm', { ...good, hashAlgorithm: '1.2.3' }, /unknown hash algorithm/],
    ['data group 0', { ...good, hashes: [h(0), h(1)] }, /out of 1..16/],
    ['data group 17', { ...good, hashes: [h(1), h(17)] }, /out of 1..16/],
    ['a data group twice', { ...good, hashes: [h(1), h(1)] }, /hashed twice/],
    ['a short hash', { ...good, hashes: [h(1), h(2, 20)] }, /wrong length/],
  ] as const)('refuses %s', (_, lds, msg) => {
    expect(() => decodeLds(encodeLds(lds))).toThrow(msg);
  });
});
