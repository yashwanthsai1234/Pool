import { webcrypto } from 'node:crypto';
import { fc, test as fcTest } from '@fast-check/vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { parse as parseMrz } from 'mrz';
import { describe, expect, it } from 'vitest';
import type { MrzInput } from '../src/mrz.ts';
import { parseDg1, parseSod } from '../src/parse.ts';
import { chipAnswerAA, makePassport } from '../src/passport.ts';
import { makeTestPki } from '../src/pki.ts';
import { bytesToInt, intToBytes, modPow } from '../src/rsa.ts';
import { arbMrzInput } from './arb.ts';
import { pkijs } from './helpers.ts';

const MRZ: MrzInput = {
  documentNumber: 'XA0000001',
  surname: 'LIDDELL',
  givenNames: 'ALICE',
  dateOfBirth: '900101',
  sex: 'F',
  dateOfExpiry: '340101',
};

const pki = makeTestPki({ seed: 'passport-test' });
const ecPass = makePassport({ pki, mrz: MRZ, seed: 'alice' });
const rsaPass = makePassport({ pki, mrz: MRZ, seed: 'alice', aa: 'rsa' });
const challenge = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]);

const unwrap = (tag: number, b: Uint8Array) => {
  expect(b[0]).toBe(tag);
  const lenBytes = (b[1] ?? 0) & 0x80 ? (b[1] ?? 0) & 0x7f : 0;
  return b.slice(2 + lenBytes);
};
const spkiOfDg15 = (dg15: Uint8Array) => unwrap(0x6f, dg15);

async function pkijsVerify(sod: Uint8Array, csca: Uint8Array): Promise<boolean> {
  const sd = new pkijs.SignedData({ schema: pkijs.ContentInfo.fromBER(unwrap(0x77, sod)).content });
  try {
    return await sd.verify({ signer: 0, checkChain: true, trustedCerts: [pkijs.Certificate.fromBER(csca)] });
  } catch {
    return false;
  }
}

describe('P1.8-02 makePassport', () => {
  it('gives DG1 (61 5B 5F1F 58 + 88 MRZ bytes), DG15 and EF.SOD; DG14 for an EC Active Authentication key', () => {
    expect(Buffer.from(ecPass.dg1.slice(0, 5)).toString('hex')).toBe('615b5f1f58');
    expect(ecPass.dg1).toHaveLength(93);
    expect(new TextDecoder().decode(ecPass.dg1.slice(5))).toBe(ecPass.mrz);
    expect(ecPass.dg15[0]).toBe(0x6f);
    expect(ecPass.sod[0]).toBe(0x77);
    expect(ecPass.dg14?.[0]).toBe(0x6e);
    expect(rsaPass.dg14).toBeUndefined();
  });

  it('DG14 holds ActiveAuthenticationInfo { 2.23.136.1.1.5, 1, ecdsa-plain-SHA256 } (Part 11 9.2.4)', () => {
    const hex = Buffer.from(ecPass.dg14 ?? []).toString('hex');
    // 06 06 67 81 08 01 01 05 = 2.23.136.1.1.5 ; 02 01 01 ; 06 0A 04 00 7F 00 07 01 01 04 01 03 = 0.4.0.127.0.7.1.1.4.1.3
    expect(hex).toContain('0606678108010105020101060a04007f00070101040103');
  });

  it('is deterministic', () => {
    const again = makePassport({ pki, mrz: MRZ, seed: 'alice' });
    expect(again.sod).toEqual(ecPass.sod);
    expect(again.dg15).toEqual(ecPass.dg15);
    expect(makePassport({ pki, mrz: MRZ, seed: 'bob' }).dg15).not.toEqual(ecPass.dg15);
  });
});

describe('P1.8-03 the LDSSecurityObject', () => {
  it('holds SHA-256 of DG1, DG14 and DG15 (2 to 16 entries), version v1 with LDS 0108', () => {
    const r = parseSod(ecPass.sod);
    if (!r.ok) throw new Error(r.error);
    const { lds } = r.value;
    expect(lds.hashAlgorithm).toBe('2.16.840.1.101.3.4.2.1');
    expect(lds.hashes.map((h) => h.dg)).toEqual([1, 14, 15]);
    expect(lds.hashes[0]?.hash).toEqual(sha256(ecPass.dg1));
    expect(lds.hashes[1]?.hash).toEqual(sha256(ecPass.dg14 ?? new Uint8Array()));
    expect(lds.hashes[2]?.hash).toEqual(sha256(ecPass.dg15));
    expect(lds.version).toBe(1);
    expect(lds.ldsVersion).toEqual({ lds: '0108', unicode: '040000' });
  });

  it('the RSA Active Authentication passport hashes DG1 and DG15', () => {
    const r = parseSod(rsaPass.sod);
    if (!r.ok) throw new Error(r.error);
    expect(r.value.lds.hashes.map((h) => h.dg)).toEqual([1, 15]);
  });

  it('a SOD with only 1 hash is refused by our parser', () => {
    const one = makePassport({ pki, mrz: MRZ, seed: 'alice', aa: 'none' });
    expect(one.dg15).toBeUndefined();
    const r = parseSod(one.sod);
    expect(r).toEqual({ ok: false, error: 'LDS: dataGroupHashValues must hold 2 to 16 entries, found 1' });
  });

  it('EF.SOD is CMS SignedData v3 with the DS certificate and one SignerInfo (Part 10 Table 37)', () => {
    const r = parseSod(ecPass.sod);
    if (!r.ok) throw new Error(r.error);
    expect(r.value.eContentType).toBe('2.23.136.1.1.1');
    expect(r.value.certificates).toEqual([pki.ds.cert]);
    expect(r.value.signer.signatureAlgorithm).toBe('1.2.840.10045.4.3.2');
  });

  it('PKI.js verifies the SOD signature and chain against the CSCA', async () => {
    expect(await pkijsVerify(ecPass.sod, pki.csca.cert)).toBe(true);
    expect(await pkijsVerify(ecPass.sod, makeTestPki({ seed: 'someone else' }).csca.cert)).toBe(false);
  });
});

describe('P1.8-09 the RSA-PSS set', () => {
  const pss = makeTestPki({ seed: 'pss', alg: 'rsa-pss' });
  const p = makePassport({ pki: pss, mrz: MRZ, seed: 'a', aa: 'rsa' });

  it('signs the SOD with id-RSASSA-PSS and PKI.js verifies it and the chain like the P-256 set', async () => {
    const r = parseSod(p.sod);
    if (!r.ok) throw new Error(r.error);
    expect(r.value.signer.signatureAlgorithm).toBe('1.2.840.113549.1.1.10');
    expect(await pkijsVerify(p.sod, pss.csca.cert)).toBe(true);
    expect(await pkijsVerify(p.sod, pki.csca.cert)).toBe(false);
  });

  it('has an RSA Active Authentication key in DG15 that answers challenges', () => {
    expect(p.aaKey?.kind).toBe('rsa');
    const spkiInfo = pkijs.PublicKeyInfo.fromBER(spkiOfDg15(p.dg15 ?? new Uint8Array()));
    expect(spkiInfo.algorithm.algorithmId).toBe('1.2.840.113549.1.1.1');
    if (p.aaKey) expect(chipAnswerAA(p.aaKey, challenge)).toHaveLength(256);
  });
});

describe('P1.8-07 chipAnswerAA', () => {
  it('EC: plain r||s over SHA-256(challenge) that verifies with the DG15 key (WebCrypto)', async () => {
    const sig = chipAnswerAA(ecPass.aaKey, challenge);
    expect(sig).toHaveLength(64);
    const pub = await webcrypto.subtle.importKey(
      'spki',
      spkiOfDg15(ecPass.dg15),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
    expect(await webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, sig, challenge)).toBe(true);
    const other = new Uint8Array([0xdf, ...challenge.slice(1)]);
    expect(await webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, sig, other)).toBe(false);
  });

  it('RSA: ISO/IEC 9796-2 scheme 1 that recovers with the DG15 key', () => {
    const sig = chipAnswerAA(rsaPass.aaKey, challenge);
    const spkiInfo = pkijs.PublicKeyInfo.fromBER(spkiOfDg15(rsaPass.dg15));
    const rsa = spkiInfo.parsedKey as pkijs.RSAPublicKey;
    const n = bytesToInt(new Uint8Array(rsa.modulus.valueBlock.valueHexView));
    const e = bytesToInt(new Uint8Array(rsa.publicExponent.valueBlock.valueHexView));
    const k = sig.length;
    const f = intToBytes(modPow(bytesToInt(sig), e, n), k);
    expect(f[0]).toBe(0x6a);
    expect([f[k - 2], f[k - 1]]).toEqual([0x34, 0xcc]);
    const m1 = f.slice(1, k - 34);
    expect(f.slice(k - 34, k - 2)).toEqual(sha256(new Uint8Array([...m1, ...challenge])));
  });

  it('refuses a challenge that is not 8 bytes', () => {
    expect(() => chipAnswerAA(ecPass.aaKey, new Uint8Array(7))).toThrow(RangeError);
    expect(() => chipAnswerAA(rsaPass.aaKey, new Uint8Array(9))).toThrow(RangeError);
  });

  it('is deterministic per challenge, and differs across challenges (RSA M1 nonce)', () => {
    expect(chipAnswerAA(rsaPass.aaKey, challenge)).toEqual(chipAnswerAA(rsaPass.aaKey, challenge));
    expect(chipAnswerAA(rsaPass.aaKey, new Uint8Array(8))).not.toEqual(chipAnswerAA(rsaPass.aaKey, challenge));
  });
});

describe('P1.8-08 DEMO / TEST ONLY', () => {
  it('appears in the MRZ name fields (as DEMO<TEST<ONLY) and in the certificates', () => {
    const m = parseMrz([ecPass.mrz.slice(0, 44), ecPass.mrz.slice(44)]);
    expect(m.fields.firstName).toBe('ALICE DEMO TEST ONLY');
    expect(m.fields.lastName).toBe('LIDDELL');
    expect(Buffer.from(pki.ds.cert).toString('latin1')).toContain('DEMO / TEST ONLY');
  });

  it('a name too long to also hold the marker is refused, not truncated', () => {
    expect(() => makePassport({ pki, mrz: { ...MRZ, surname: 'A'.repeat(20) }, seed: 'x' })).toThrow(RangeError);
  });
});

describe('round trip and hostile input', () => {
  fcTest.prop([arbMrzInput], { numRuns: 25 })('build then parse gives the same MRZ fields and DG hashes', (input) => {
    const p = makePassport({ pki, mrz: input, seed: 'prop' });
    const mrz = parseDg1(p.dg1);
    expect(mrz).toEqual({ ok: true, value: p.mrz });
    const fields = parseMrz([p.mrz.slice(0, 44), p.mrz.slice(44)]);
    expect(fields.valid).toBe(true);
    expect(fields.fields.documentNumber).toBe(input.documentNumber);
    expect(fields.fields.birthDate).toBe(input.dateOfBirth);
    const sod = parseSod(p.sod);
    if (!sod.ok) throw new Error(sod.error);
    expect(sod.value.lds.hashes[0]?.hash).toEqual(sha256(p.dg1));
  });

  it('a SOD truncated at every byte position gives an error result and never throws', () => {
    for (let i = 0; i < ecPass.sod.length; i++) {
      const r = parseSod(ecPass.sod.slice(0, i));
      expect(r.ok).toBe(false);
    }
  });

  it('DG1 truncated at every position, or with trailing bytes, gives an error result', () => {
    for (let i = 0; i < ecPass.dg1.length; i++) expect(parseDg1(ecPass.dg1.slice(0, i)).ok).toBe(false);
    expect(parseDg1(new Uint8Array([...ecPass.dg1, 0])).ok).toBe(false);
  });

  fcTest.prop([fc.uint8Array({ maxLength: 600 })])('random bytes never make the parsers throw', (b) => {
    expect(parseSod(b).ok).toBe(false);
    expect(parseSod(new Uint8Array([0x77, 0x82, b.length >> 8, b.length & 0xff, ...b])).ok).toBe(false);
    parseDg1(b);
  });
});
