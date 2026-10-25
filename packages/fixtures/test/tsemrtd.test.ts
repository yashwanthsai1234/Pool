import { DG1, DG14, DG15, SOD } from '@li0ard/tsemrtd';
import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';
import { parseSod } from '../src/parse.ts';
import { makePassport } from '../src/passport.ts';
import { makeTestPki } from '../src/pki.ts';

const MRZ = {
  documentNumber: 'XC0000003',
  surname: 'CROSS',
  givenNames: 'CHECK',
  dateOfBirth: '010203',
  sex: '<',
  dateOfExpiry: '310203',
} as const;

describe.each(['ecdsa-p256', 'rsa-pss'] as const)('P1.8-10 @li0ard/tsemrtd parses our files (%s)', (alg) => {
  const pki = makeTestPki({ seed: 'tsemrtd', alg });
  const p = makePassport({ pki, mrz: MRZ, seed: 'x' });

  it('DG1: the same MRZ', () => {
    expect(DG1.load(p.dg1)).toBe(p.mrz);
  });

  it('EF.SOD: the same LDS version, hash algorithm and DG hashes as our parser, and the DS certificate', () => {
    const theirs = SOD.load(p.sod);
    const ours = parseSod(p.sod);
    if (!ours.ok) throw new Error(ours.error);
    expect(theirs.ldsObject.version).toBe(ours.value.lds.version);
    expect(theirs.ldsObject.algorithm.algorithm).toBe(ours.value.lds.hashAlgorithm);
    expect(theirs.ldsObject.hashes.map((h) => [h.number, new Uint8Array(h.hash)])).toEqual(
      ours.value.lds.hashes.map((h) => [h.dg, h.hash]),
    );
    expect(new Uint8Array(theirs.ldsObject.hashes[0]?.hash ?? [])).toEqual(sha256(p.dg1));
    expect(theirs.certificates?.length).toBe(1);
    expect(theirs.signatures).toHaveLength(1);
  });

  it('DG15 and DG14: the Active Authentication key and the ActiveAuthenticationInfo', () => {
    const key = DG15.load(p.dg15 ?? new Uint8Array());
    expect(key.algorithm.algorithm).toBe('1.2.840.10045.2.1');
    const infos = DG14.load(p.dg14 ?? new Uint8Array());
    expect(JSON.stringify(infos)).toContain('2.23.136.1.1.5');
  });
});
