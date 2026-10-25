import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { chipAnswerAA, makePassport } from '../src/passport.ts';
import { makeTestPki } from '../src/pki.ts';
import { OPENSSL, openssl, pem, tempDir, writeFiles } from './helpers.ts';

const MRZ = {
  documentNumber: 'XB0000002',
  surname: 'BUILDER',
  givenNames: 'BOB',
  dateOfBirth: '850615',
  sex: 'M',
  dateOfExpiry: '330615',
} as const;

/** EF.SOD without its tag-77 wrapper is a plain DER CMS ContentInfo. */
const cmsOf = (sod: Uint8Array) => sod.slice((sod[1] ?? 0) & 0x80 ? 2 + ((sod[1] ?? 0) & 0x7f) : 2);

describe.skipIf(!OPENSSL)('P1.8-04 openssl cms -verify against the CSCA (differential)', () => {
  it.each([
    ['ecdsa-p256', 'ec'],
    ['ecdsa-p256', 'rsa'],
    ['rsa-pss', 'ec'],
    ['rsa-pss', 'rsa'],
  ] as const)(
    '%s PKI, %s Active Authentication: the SOD verifies and the content is the LDSSecurityObject',
    (alg, aa) => {
      const pki = makeTestPki({ seed: 'openssl', alg });
      const p = makePassport({ pki, mrz: MRZ, seed: 'bob', aa });
      const dir = tempDir();
      writeFiles(dir, { 'csca.pem': pem(pki.csca.cert), 'ds.pem': pem(pki.ds.cert), 'sod.der': cmsOf(p.sod) });
      const v = openssl(
        ['cms', '-verify', '-inform', 'DER', '-in', 'sod.der', '-CAfile', 'csca.pem', '-out', 'lds.der'],
        dir,
      );
      expect(v.out).toContain('Verification successful');
      expect(v.ok).toBe(true);
      const asn = openssl(['asn1parse', '-inform', 'DER', '-in', join(dir, 'lds.der')], dir);
      expect(asn.out).toContain(':0108');
      const strict = openssl(['verify', '-x509_strict', '-CAfile', 'csca.pem', 'ds.pem'], dir);
      expect(strict.out.trim()).toBe('ds.pem: OK');
    },
  );

  it('OpenSSL rejects the SOD against a CSCA from another seed', () => {
    const p = makePassport({ pki: makeTestPki({ seed: 'openssl' }), mrz: MRZ, seed: 'bob' });
    const dir = tempDir();
    writeFiles(dir, { 'csca.pem': pem(makeTestPki({ seed: 'other' }).csca.cert), 'sod.der': cmsOf(p.sod) });
    const v = openssl(['cms', '-verify', '-inform', 'DER', '-in', 'sod.der', '-CAfile', 'csca.pem', '-out', 'x'], dir);
    expect(v.ok).toBe(false);
  });

  it('OpenSSL recovers the RSA Active Authentication representative 6A .. 34CC with the DG15 key', () => {
    const p = makePassport({ pki: makeTestPki({ seed: 'openssl' }), mrz: MRZ, seed: 'bob', aa: 'rsa' });
    const dir = tempDir();
    writeFiles(dir, {
      'aa.pem': pem(p.dg15.slice(4), 'PUBLIC KEY'),
      'sig.bin': chipAnswerAA(p.aaKey, new Uint8Array(8).fill(0x11)),
    });
    const r = openssl(
      [
        'pkeyutl',
        '-verifyrecover',
        '-pubin',
        '-inkey',
        'aa.pem',
        '-pkeyopt',
        'rsa_padding_mode:none',
        '-in',
        'sig.bin',
        '-hexdump',
      ],
      dir,
    );
    expect(r.ok).toBe(true);
    expect(r.out.slice(0, 10)).toMatch(/^0000 - 6a/);
    expect(r.out).toMatch(/34 cc\s/);
  });
});
