// Task 1.9: Active Authentication (ICAO 9303 Part 11, 6.1): P1.9-05, P1.9-06, P1.9-16 and T-U-16n.
// Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p11_cons_en.pdf (6.1.2, Appendix F)
import { execFileSync } from 'node:child_process';
import { createPrivateKey } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chipAnswerAA, makePassport, makeTestPki } from '@legx/fixtures';
import { tlv } from '@legx/fixtures/der';
import { iso9796d2Sign, type RsaKey } from '@legx/fixtures/rsa';
import { p256 } from '@noble/curves/nist.js';
import { sha1 } from '@noble/hashes/legacy.js';
import { bytesToHex, concatBytes, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import * as asn1js from 'asn1js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { presenceMsg } from '../../src/attest.ts';
import { aaChallenge, iso9796d2Recovers, verifyActiveAuth } from '../../src/passport/activeAuth.ts';
import { pyVector } from '../helpers/pyref.ts';

const BSI = join(import.meta.dirname, 'data/bsi-tr03105-5');
const MRZ = {
  documentNumber: 'L898902C3',
  surname: 'ERIKSSON',
  givenNames: 'ANNA MARIA',
  dateOfBirth: '740812',
  sex: 'F',
  dateOfExpiry: '340415',
} as const;
const seed = new Uint8Array(32).fill(7);
const pki = makeTestPki({ seed });
const CH = hexToBytes('0102030405060708');
const flip = (b: Uint8Array, i: number) => {
  const o = b.slice();
  o[i] = (o[i] ?? 0) ^ 0x01;
  return o;
};
const fail = (code: string) => ({ ok: false, code });

// The BSI TR-03105-5 reference data set ships the Active Authentication private key of its sample chip (1024-bit RSA).
// Source: https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03105/BSI_TR-03105-5_ReferenceDataSet_zip.zip
function bsiKey(): RsaKey {
  const jwk = createPrivateKey({ key: readFileSync(join(BSI, 'DG15_sk.pkcs8')), format: 'der', type: 'pkcs8' }).export({
    format: 'jwk',
  });
  const int = (s?: string) => BigInt(`0x${Buffer.from(s ?? '', 'base64url').toString('hex')}`);
  const n = int(jwk.n);
  return { n, e: int(jwk.e), d: int(jwk.d), p: int(jwk.p), q: int(jwk.q), bits: n.toString(2).length };
}
const bsiDg15 = new Uint8Array(readFileSync(join(BSI, 'Datagroup15.bin')));

describe('P1.9-16 the challenge is the first 8 bytes of presenceMsg', () => {
  const v = pyVector('presence', 'presenceMsg');
  const msg = presenceMsg(
    hexToBytes(v.inputs.dealSeal ?? ''),
    'B',
    hexToBytes(v.inputs.ledgerHash ?? ''),
    hexToBytes(v.inputs.nonce ?? ''),
  );

  it('is the golden prefix', () => {
    expect(bytesToHex(aaChallenge(msg))).toBe(v.output.slice(0, 16));
  });

  it('accepts only a 32-byte presenceMsg', () => {
    expect(() => aaChallenge(msg.subarray(0, 31))).toThrow(RangeError);
  });

  it('refuses a challenge of 7 or 9 bytes at input', () => {
    const p = makePassport({ pki, mrz: MRZ, seed });
    const signature = chipAnswerAA(p.aaKey, CH);
    for (const challenge of [CH.subarray(0, 7), concatBytes(CH, new Uint8Array(1))]) {
      expect(verifyActiveAuth({ dg15: p.dg15, dg14: p.dg14, challenge, signature })).toEqual(fail('CHALLENGE_LENGTH'));
    }
  });

  it('T-U-16n: a signature over any other 8 bytes fails CHIP_AUTH_INVALID', () => {
    const p = makePassport({ pki, mrz: MRZ, seed });
    const challenge = aaChallenge(msg);
    expect(
      verifyActiveAuth({ dg15: p.dg15, dg14: p.dg14, challenge, signature: chipAnswerAA(p.aaKey, challenge) }),
    ).toEqual({
      ok: true,
      alg: 'ecdsa',
    });
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 8, maxLength: 8 }), (other) => {
        fc.pre(bytesToHex(other) !== bytesToHex(challenge));
        const signature = chipAnswerAA(p.aaKey, other);
        expect(verifyActiveAuth({ dg15: p.dg15, dg14: p.dg14, challenge, signature })).toEqual(
          fail('CHIP_AUTH_INVALID'),
        );
      }),
      { numRuns: 20 },
    );
  });
});

describe('P1.9-06 ECDSA Active Authentication: plain r||s, hash from DG14', () => {
  const p = makePassport({ pki, mrz: MRZ, seed });
  const signature = chipAnswerAA(p.aaKey, CH);

  it('passes, and fails for another challenge or a changed signature byte', () => {
    expect(verifyActiveAuth({ dg15: p.dg15, dg14: p.dg14, challenge: CH, signature }).ok).toBe(true);
    expect(verifyActiveAuth({ dg15: p.dg15, dg14: p.dg14, challenge: flip(CH, 0), signature })).toEqual(
      fail('CHIP_AUTH_INVALID'),
    );
    for (const i of [0, 31, 32, 63]) {
      expect(verifyActiveAuth({ dg15: p.dg15, dg14: p.dg14, challenge: CH, signature: flip(signature, i) })).toEqual(
        fail('CHIP_AUTH_INVALID'),
      );
    }
  });

  it('accepts a high-S signature (chips do not normalize S; lowS: false)', () => {
    if (p.aaKey.kind !== 'ec') throw new Error('EC fixture expected');
    const s = p256.Signature.fromBytes(signature, 'compact');
    const high = new p256.Signature(s.r, p256.Point.CURVE().n - s.s).toBytes('compact');
    expect(bytesToHex(high)).not.toBe(bytesToHex(signature));
    expect(verifyActiveAuth({ dg15: p.dg15, dg14: p.dg14, challenge: CH, signature: high }).ok).toBe(true);
  });

  it('needs DG14 ActiveAuthenticationInfo for an EC key (Part 11 9.2.4)', () => {
    expect(verifyActiveAuth({ dg15: p.dg15, challenge: CH, signature })).toEqual(fail('DG14_AA_INFO_MISSING'));
    const bsiDg14 = new Uint8Array(readFileSync(join(BSI, 'Datagroup14.bin'))); // Chip Authentication only
    expect(verifyActiveAuth({ dg15: p.dg15, dg14: bsiDg14, challenge: CH, signature })).toEqual(
      fail('DG14_AA_INFO_MISSING'),
    );
  });

  it('refuses SHA-1 for ECDSA (Part 11 6.1.2.3)', () => {
    const aaInfo = (oid: string) =>
      tlv(
        [0x6e],
        new Uint8Array(
          new asn1js.Set({
            value: [
              new asn1js.Sequence({
                value: [
                  new asn1js.ObjectIdentifier({ value: '2.23.136.1.1.5' }),
                  new asn1js.Integer({ value: 1 }),
                  new asn1js.ObjectIdentifier({ value: oid }),
                ],
              }),
            ],
          }).toBER(),
        ),
      );
    expect(
      verifyActiveAuth({ dg15: p.dg15, dg14: aaInfo('0.4.0.127.0.7.1.1.4.1.1'), challenge: CH, signature }),
    ).toEqual(fail('AA_ALGORITHM_UNSUPPORTED'));
    expect(
      verifyActiveAuth({ dg15: p.dg15, dg14: aaInfo('0.4.0.127.0.7.1.1.4.1.3'), challenge: CH, signature }).ok,
    ).toBe(true);
  });

  it('accepts a DG15 key with explicit P-256 domain parameters (common on real chips)', () => {
    if (p.aaKey.kind !== 'ec') throw new Error('EC fixture expected');
    const c = p256.Point.CURVE();
    const g = p256.Point.BASE.toBytes(false);
    const int = (x: bigint) => new asn1js.Integer({ valueHex: hexToBytes(`00${x.toString(16).padStart(64, '0')}`) });
    const params = new asn1js.Sequence({
      value: [
        new asn1js.Integer({ value: 1 }),
        new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: '1.2.840.10045.1.1' }), int(c.p)] }),
        new asn1js.Sequence({
          value: [
            new asn1js.OctetString({ valueHex: hexToBytes(c.a.toString(16).padStart(64, '0')) }),
            new asn1js.OctetString({ valueHex: hexToBytes(c.b.toString(16).padStart(64, '0')) }),
          ],
        }),
        new asn1js.OctetString({ valueHex: g }),
        int(c.n),
        new asn1js.Integer({ value: 1 }),
      ],
    });
    const spki = new asn1js.Sequence({
      value: [
        new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: '1.2.840.10045.2.1' }), params] }),
        new asn1js.BitString({ valueHex: p256.getPublicKey(p.aaKey.secretKey, false) }),
      ],
    });
    const dg15 = tlv([0x6f], new Uint8Array(spki.toBER()));
    expect(verifyActiveAuth({ dg15, dg14: p.dg14, challenge: CH, signature }).ok).toBe(true);
    expect(verifyActiveAuth({ dg15, dg14: p.dg14, challenge: flip(CH, 3), signature })).toEqual(
      fail('CHIP_AUTH_INVALID'),
    );
  });
});

describe('P1.9-05 RSA Active Authentication, ISO/IEC 9796-2 scheme 1 with partial recovery', () => {
  it('ICAO 9303 Part 11 Appendix F: the worked example representative recovers with RND.IFD; one changed byte fails', () => {
    const m1 =
      '9D2784A67F8E7C659973EA1AEA25D95B6C8F91E5002F369F0FBDCE8A3CEC1991B543F1696546C5524CF23A5303CD6C98' +
      '599F40B79F377B5F3A1406B3B4D8F96784D23AA88DB7E1032A405E69325FA91A6E86F5C71AEA978264C4A207446DAD4E' +
      '7292E2DCDA3024B47DA8';
    const f = hexToBytes(`6A${m1}C063AA1E6D22FBD976AB0FE73D94D2D9C6D88127BC`);
    const m2 = hexToBytes('F173589974BF40C6');
    expect(f.length).toBe(128);
    expect(iso9796d2Recovers(f, m2)).toBe(true);
    expect(iso9796d2Recovers(f, flip(m2, 7))).toBe(false);
    for (const i of [0, 1, 60, 106, 107, 126, 127]) expect(iso9796d2Recovers(flip(f, i), m2)).toBe(false);
  });

  it('BSI TR-03105-5 sample key: SHA-1 (trailer BC) and SHA-256 (34CC) pass; one changed byte fails', () => {
    const key = bsiKey();
    expect(key.bits).toBe(1024);
    for (const hash of ['SHA-1', 'SHA-256'] as const) {
      const m1 = randomBytes(128 - 1 - (hash === 'SHA-1' ? 21 : 34));
      const signature = iso9796d2Sign(key, m1, CH, hash);
      expect(verifyActiveAuth({ dg15: bsiDg15, challenge: CH, signature })).toEqual({ ok: true, alg: 'rsa' });
      expect(verifyActiveAuth({ dg15: bsiDg15, challenge: flip(CH, 5), signature })).toEqual(fail('CHIP_AUTH_INVALID'));
      for (const i of [0, 64, 127]) {
        expect(verifyActiveAuth({ dg15: bsiDg15, challenge: CH, signature: flip(signature, i) })).toEqual(
          fail('CHIP_AUTH_INVALID'),
        );
      }
    }
  });

  it('accepts n - sigma as well as sigma (ISO/IEC 9796-2 recovery step)', () => {
    const key = bsiKey();
    const signature = iso9796d2Sign(key, randomBytes(106), CH, 'SHA-1');
    const alt = hexToBytes((key.n - BigInt(`0x${bytesToHex(signature)}`)).toString(16).padStart(256, '0'));
    expect(verifyActiveAuth({ dg15: bsiDg15, challenge: CH, signature: alt }).ok).toBe(true);
  });

  it('differential: a representative put through OpenSSL raw RSA with the BSI key verifies', () => {
    const dir = mkdtempSync(join(tmpdir(), 'legx-aa-'));
    const openssl = ['/opt/homebrew/opt/openssl@3/bin/openssl', '/usr/bin/openssl'].find((p) => {
      try {
        return execFileSync(p, ['version']).toString().startsWith('OpenSSL 3');
      } catch {
        return false;
      }
    });
    if (!openssl) return; // no OpenSSL 3: the BigInt signer above still covers the path
    const m1 = randomBytes(106);
    const f = concatBytes(new Uint8Array([0x6a]), m1, sha1(concatBytes(m1, CH)), new Uint8Array([0xbc]));
    writeFileSync(join(dir, 'f.bin'), f);
    execFileSync(openssl, [
      'pkeyutl',
      '-decrypt', // the raw private operation F^d mod n (no padding); -sign would treat F as a digest
      '-inkey',
      join(BSI, 'DG15_sk.pkcs8'),
      '-keyform',
      'DER',
      '-pkeyopt',
      'rsa_padding_mode:none',
      '-in',
      join(dir, 'f.bin'),
      '-out',
      join(dir, 's.bin'),
    ]);
    const signature = new Uint8Array(readFileSync(join(dir, 's.bin')));
    expect(verifyActiveAuth({ dg15: bsiDg15, challenge: CH, signature })).toEqual({ ok: true, alg: 'rsa' });
  });

  it('the 2048-bit SHA-256 fixture chip passes', () => {
    const p = makePassport({ pki, mrz: MRZ, seed, aa: 'rsa' });
    const signature = chipAnswerAA(p.aaKey, CH);
    expect(verifyActiveAuth({ dg15: p.dg15, challenge: CH, signature })).toEqual({ ok: true, alg: 'rsa' });
    expect(verifyActiveAuth({ dg15: p.dg15, challenge: flip(CH, 0), signature })).toEqual(fail('CHIP_AUTH_INVALID'));
  });

  it('refuses a representative with the wrong header, an unknown trailer or total recovery', () => {
    const m1 = randomBytes(106);
    const h = sha1(concatBytes(m1, CH));
    const rep = (head: number, trailer: number[]) =>
      concatBytes(new Uint8Array([head]), m1, h, new Uint8Array(trailer));
    expect(iso9796d2Recovers(rep(0x6a, [0xbc]), CH)).toBe(true);
    expect(iso9796d2Recovers(rep(0x4a, [0xbc]), CH)).toBe(false); // total recovery: M2 would be inside
    expect(iso9796d2Recovers(rep(0x2a, [0xbc]), CH)).toBe(false); // header bits not 01
    expect(iso9796d2Recovers(rep(0x6a, [0x33, 0xcc]), CH)).toBe(false); // ICAO: SHA-1 uses option 1 only
  });

  it('a shorter M1 is preceded by padding nibbles B and the border nibble A; anything else there fails', () => {
    const m1 = randomBytes(100);
    const h = sha1(concatBytes(m1, CH));
    const rep = (pad: number[]) => concatBytes(new Uint8Array(pad), m1, h, new Uint8Array([0xbc]));
    expect(iso9796d2Recovers(rep([0x6b, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xba]), CH)).toBe(true);
    expect(iso9796d2Recovers(rep([0x6b, 0xbb, 0xbb, 0x12, 0xbb, 0xbb, 0xba]), CH)).toBe(false);
  });
});

describe('hostile input never throws', () => {
  it('random DG15, DG14 and signatures give a failure code', () => {
    const p = makePassport({ pki, mrz: MRZ, seed });
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 300 }), fc.uint8Array({ maxLength: 300 }), (junk, sig) => {
        expect(verifyActiveAuth({ dg15: junk, challenge: CH, signature: sig }).ok).toBe(false);
        expect(verifyActiveAuth({ dg15: p.dg15, dg14: junk, challenge: CH, signature: sig }).ok).toBe(false);
        expect(verifyActiveAuth({ dg15: bsiDg15, challenge: CH, signature: sig }).ok).toBe(false);
      }),
      { numRuns: 200 },
    );
  });

  it('20,000 nested indefinite-length SEQUENCEs in DG15 or DG14 are refused (no stack overflow)', () => {
    const p = makePassport({ pki, mrz: MRZ, seed });
    const deep = new Uint8Array(40_000).map((_, i) => (i % 2 === 0 ? 0x30 : 0x80));
    const wrap = (tag: number) => concatBytes(new Uint8Array([tag, 0x82, deep.length >> 8, deep.length & 0xff]), deep);
    const signature = chipAnswerAA(p.aaKey, CH);
    expect(verifyActiveAuth({ dg15: wrap(0x6f), challenge: CH, signature })).toEqual(fail('DG15_MALFORMED'));
    expect(verifyActiveAuth({ dg15: p.dg15, dg14: wrap(0x6e), challenge: CH, signature })).toEqual(
      fail('DG14_AA_INFO_MISSING'),
    );
  });

  it('DG15 truncated at every byte or with a trailing byte is refused', () => {
    for (let i = 0; i < bsiDg15.length; i++) {
      expect(verifyActiveAuth({ dg15: bsiDg15.subarray(0, i), challenge: CH, signature: new Uint8Array(128) })).toEqual(
        fail('DG15_MALFORMED'),
      );
    }
    expect(
      verifyActiveAuth({
        dg15: concatBytes(bsiDg15, new Uint8Array(1)),
        challenge: CH,
        signature: new Uint8Array(128),
      }),
    ).toEqual(fail('DG15_MALFORMED'));
  });
});
