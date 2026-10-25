import { p256 } from '@noble/curves/nist.js';
import { parse as parseMrz } from 'mrz';
import { describe, expect, it } from 'vitest';
import type { MrzInput } from '../src/mrz.ts';
import { makePassport, type Passport } from '../src/passport.ts';
import { makeTestPki } from '../src/pki.ts';
import { makeBadVariants, type Variant, type VariantName } from '../src/variants.ts';
import { certOf, keyUsageOf, OPENSSL, openssl, pem, pkijs, tempDir, writeFiles } from './helpers.ts';

const MRZ: MrzInput = {
  documentNumber: 'XA0000001',
  surname: 'LIDDELL',
  givenNames: 'ALICE',
  dateOfBirth: '900101',
  sex: 'F',
  dateOfExpiry: '340101',
};

type Part = 'dg1' | 'dg14' | 'dg15' | 'lds' | 'eContentType' | 'signedAttrs' | 'signature' | 'dsCert' | 'certificates';

/** Splits a passport into its parts with PKI.js, an implementation independent of the builder. */
function parts(p: Passport): Record<Part, string> {
  const hex = (b?: ArrayBuffer | Uint8Array) => (b ? Buffer.from(new Uint8Array(b)).toString('hex') : '');
  const ci = pkijs.ContentInfo.fromBER(p.sod.slice(4));
  const sd = new pkijs.SignedData({ schema: ci.content });
  const si = sd.signerInfos[0];
  const certs = (sd.certificates ?? []) as pkijs.Certificate[];
  return {
    dg1: hex(p.dg1),
    dg14: hex(p.dg14),
    dg15: hex(p.dg15),
    lds: hex(sd.encapContentInfo.eContent?.getValue()),
    eContentType: sd.encapContentInfo.eContentType,
    signedAttrs: hex(si?.signedAttrs?.encodedValue),
    signature: hex(si?.signature.valueBlock.valueHexView),
    dsCert: certs.length === 1 ? hex(certs[0]?.toSchema().toBER()) : '',
    certificates: String(certs.length),
  };
}

function diff(a: Passport, b: Passport): Part[] {
  const [pa, pb] = [parts(a), parts(b)];
  const d = (Object.keys(pa) as Part[]).filter((k) => pa[k] !== pb[k]);
  return d.includes('certificates') ? d.filter((k) => k !== 'dsCert') : d;
}

const EXPECTED: Record<VariantName, { changes: Part[]; openssl: boolean; expect: 'accept' | 'reject' }> = {
  badSodSignature: { changes: ['signature'], openssl: false, expect: 'reject' },
  wrongCsca: { changes: ['dsCert'], openssl: false, expect: 'reject' },
  changedDg1: { changes: ['dg1'], openssl: true, expect: 'reject' },
  expiredDocument: { changes: ['dg1', 'lds', 'signedAttrs', 'signature'], openssl: true, expect: 'reject' },
  expiredDsCert: { changes: ['dsCert'], openssl: false, expect: 'reject' },
  highS: { changes: ['signature'], openssl: true, expect: 'accept' },
  brainpoolDs: { changes: ['signature', 'dsCert'], openssl: true, expect: 'accept' },
  singleHash: { changes: ['lds', 'signedAttrs', 'signature'], openssl: true, expect: 'reject' },
  messageDigestMismatch: { changes: ['signedAttrs', 'signature'], openssl: false, expect: 'reject' },
  wrongContentType: { changes: ['eContentType', 'signedAttrs', 'signature'], openssl: true, expect: 'reject' },
  noDsCertificate: { changes: ['certificates'], openssl: false, expect: 'reject' },
  dsKeyUsage: { changes: ['dsCert'], openssl: false, expect: 'reject' },
  changedDg15: { changes: ['dg15'], openssl: true, expect: 'reject' },
  badCheckDigit: { changes: ['dg1', 'lds', 'signedAttrs', 'signature'], openssl: true, expect: 'reject' },
};

const pki = makeTestPki({ seed: 'variants' });
const good = makePassport({ pki, mrz: MRZ, seed: 'alice' });
const variants = makeBadVariants({ pki, mrz: MRZ, seed: 'alice' });
const list = Object.values(variants) as Variant[];

describe('P1.8-05 bad variants', () => {
  it('has the 14 named variants, at least 12 bad', () => {
    expect(Object.keys(variants).sort()).toEqual(Object.keys(EXPECTED).sort());
    expect(list.filter((v) => v.expect === 'reject').length).toBeGreaterThanOrEqual(12);
  });

  it.each(list.map((v) => [v.name, v] as const))(
    '%s differs from the good fixture in exactly its one way',
    (name, v) => {
      expect(diff(good, v.passport)).toEqual(EXPECTED[name].changes);
      expect(v.expect).toBe(EXPECTED[name].expect);
      expect(v.reason).toMatch(v.expect === 'accept' ? /^PASS/ : /^[A-Z0-9_]+$/);
    },
  );

  it('wrongCsca: the DS certificate keeps every field but is signed by a rogue CSCA with the same name', async () => {
    const ds = certOf(Buffer.from(parts(variants.wrongCsca.passport).dsCert, 'hex'));
    expect(await ds.verify(certOf(pki.csca.cert))).toBe(false);
    expect(await ds.verify(certOf(variants.wrongCsca.rogueCsca))).toBe(true);
    expect(certOf(variants.wrongCsca.rogueCsca).subject.isEqual(certOf(pki.csca.cert).subject)).toBe(true);
    expect(Buffer.from(ds.tbsView).equals(Buffer.from(certOf(pki.ds.cert).tbsView))).toBe(true);
  });

  it('changedDg1 keeps valid check digits, so only the SOD hash catches it', () => {
    const m = variants.changedDg1.passport.mrz;
    expect(parseMrz([m.slice(0, 44), m.slice(44)]).valid).toBe(true);
    expect(m).not.toBe(good.mrz);
  });

  it('expiredDocument changes only the expiry date (and its check digits) and the expiry is in the past', () => {
    const [g, e] = [good.mrz, variants.expiredDocument.passport.mrz].map(
      (m) => parseMrz([m.slice(0, 44), m.slice(44)]).fields,
    );
    const expiryFields = { expirationDate: '', expirationDateCheckDigit: '', compositeCheckDigit: '' };
    expect({ ...e, ...expiryFields }).toEqual({ ...g, ...expiryFields });
    expect(e?.expirationDate).not.toBe(g?.expirationDate);
    expect(Number(e?.expirationDate?.slice(0, 2))).toBeLessThan(26);
  });

  it('badCheckDigit has exactly one wrong check digit', () => {
    const m = variants.badCheckDigit.passport.mrz;
    const r = parseMrz([m.slice(0, 44), m.slice(44)]);
    expect(r.valid).toBe(false);
    expect(r.details.filter((d) => !d.valid).map((d) => d.field)).toEqual(['documentNumberCheckDigit']);
  });

  it('highS: the SOD signature has s > n / 2 and is otherwise the same signature', () => {
    const sigOf = (p: Passport) => p256.Signature.fromBytes(Buffer.from(parts(p).signature, 'hex'), 'der');
    const [g, h] = [sigOf(good), sigOf(variants.highS?.passport ?? good)];
    expect(h.r).toBe(g.r);
    expect(h.s).toBe(p256.Point.CURVE().n - g.s);
    expect(h.hasHighS()).toBe(true);
  });

  it('expiredDsCert: the DS validity ended before today', () => {
    const ds = certOf(Buffer.from(parts(variants.expiredDsCert.passport).dsCert, 'hex'));
    expect(ds.notAfter.value.getTime()).toBeLessThan(Date.parse('2026-01-01'));
  });

  it('dsKeyUsage: keyCertSign instead of digitalSignature', () => {
    expect(keyUsageOf(Buffer.from(parts(variants.dsKeyUsage.passport).dsCert, 'hex'))).toEqual(['keyCertSign']);
  });

  it('every variant still says DEMO / TEST ONLY (P1.8-08)', () => {
    for (const v of list) expect(v.passport.mrz.slice(5, 44)).toContain('DEMO<TEST<ONLY');
  });

  it('the RSA-PSS set gives the same variants without highS', () => {
    const rsa = makeBadVariants({ pki: makeTestPki({ seed: 'variants', alg: 'rsa-pss' }), mrz: MRZ, seed: 'alice' });
    expect(rsa.highS).toBeUndefined();
    expect(Object.keys(rsa)).toHaveLength(13);
  });
});

describe.skipIf(!OPENSSL)('P1.8-05 x P1.8-04: OpenSSL agrees with each variant at the CMS layer', () => {
  it.each(list.map((v) => [v.name, v] as const))('%s', (name, v) => {
    const dir = tempDir();
    writeFiles(dir, { 'csca.pem': pem(pki.csca.cert), 'sod.der': v.passport.sod.slice(4) });
    const r = openssl(
      ['cms', '-verify', '-inform', 'DER', '-in', 'sod.der', '-CAfile', 'csca.pem', '-out', 'lds.der'],
      dir,
    );
    expect(r.ok, r.out).toBe(EXPECTED[name].openssl);
  });
});
