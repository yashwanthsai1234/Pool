// Task 1.9: passive authentication (ICAO 9303 Part 11, 5.1) and the chip checks the lawyer's console signs.
// T-U-16a to e, f (chip side), m and n; P1.9-03, P1.9-04; every fixture variant; the BSI TR-03105-5 reference SOD.
// Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p11_cons_en.pdf (5.1.1)
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { chipAnswerAA, makeBadVariants, makePassport, makeTestPki, type Passport, type PkiAlg } from '@legx/fixtures';
import { ecKeyFromSeed } from '@legx/fixtures/keys';
import { assemble } from '@legx/fixtures/passport';
import { reissue } from '@legx/fixtures/pki';
import { brainpoolP256r1 } from '@noble/curves/misc.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { presenceMsg } from '../../src/attest.ts';
import { passportCommitment } from '../../src/dealcore.ts';
import { aaChallenge } from '../../src/passport/activeAuth.ts';
import { chipChecks, passiveAuth, passportRecord } from '../../src/passport/passiveAuth.ts';
import { parseLds, parseSod } from '../../src/passport/sod.ts';
import { pyVector } from '../helpers/pyref.ts';

const RIPPLE_EPOCH = 946_684_800;
const ripple = (iso: string) => Date.parse(iso) / 1000 - RIPPLE_EPOCH;
/** A validated ledger close_time inside every fixture validity window. */
const AT = ripple('2027-06-01T12:00:00Z');
const MRZ = {
  documentNumber: 'L898902C3',
  surname: 'ERIKSSON',
  givenNames: 'ANNA MARIA',
  dateOfBirth: '740812',
  sex: 'F',
  dateOfExpiry: '340415',
} as const;
const seed = new Uint8Array(32).fill(9);
const fail = (code: string) => ({ ok: false, code });
const BSI = join(import.meta.dirname, 'data/bsi-tr03105-5');
const bsi = (f: string) => new Uint8Array(readFileSync(join(BSI, f)));

for (const alg of ['ecdsa-p256', 'rsa-pss'] as PkiAlg[]) {
  describe(`passiveAuth with the ${alg} PKI`, () => {
    const pki = makeTestPki({ seed, alg });
    const trustList = [pki.csca.cert];
    const good = makePassport({ pki, mrz: MRZ, seed });
    const v = makeBadVariants({ pki, mrz: MRZ, seed });
    const run = (p: Passport, extra: Partial<Parameters<typeof passiveAuth>[0]> = {}) =>
      passiveAuth({ dg1: p.dg1, sod: p.sod, dg14: p.dg14, dg15: p.dg15, trustList, atTime: AT, ...extra });

    it('T-U-16a: the good fixture passes and lists its data groups', async () => {
      const r = await run(good);
      expect(r).toEqual({ ok: true, listed: [1, 14, 15], dateOfExpiry: '340415' });
    });

    it('T-U-16b: a DS certificate from a rogue CSCA with the same name fails DS_NOT_CHAINED', async () => {
      expect(await run(v.wrongCsca.passport)).toEqual(fail('DS_NOT_CHAINED'));
      // ...and passes only if the rogue CSCA is trusted, so the chain check is the only failing step.
      expect((await run(v.wrongCsca.passport, { trustList: [v.wrongCsca.rogueCsca] })).ok).toBe(true);
      expect(await run(good, { trustList: [] })).toEqual(fail('DS_NOT_CHAINED'));
    });

    it('T-U-16c: a bad SOD signature fails SOD_SIGNATURE_INVALID', async () => {
      expect(await run(v.badSodSignature.passport)).toEqual(fail('SOD_SIGNATURE_INVALID'));
    });

    it('T-U-16d: a changed DG1 fails DG1_HASH_MISMATCH', async () => {
      expect(await run(v.changedDg1.passport)).toEqual(fail('DG1_HASH_MISMATCH'));
    });

    it('T-U-16e: an expired document fails DOCUMENT_EXPIRED by the given ledger time, not the clock', async () => {
      expect(await run(v.expiredDocument.passport)).toEqual(fail('DOCUMENT_EXPIRED'));
      // Valid through its date of expiry (UTC), refused one second later.
      const p = makePassport({ pki, mrz: { ...MRZ, dateOfExpiry: '270601' }, seed });
      expect((await run(p, { atTime: ripple('2027-06-01T23:59:59Z') })).ok).toBe(true);
      expect(await run(p, { atTime: ripple('2027-06-02T00:00:00Z') })).toEqual(fail('DOCUMENT_EXPIRED'));
    });

    it('every fixture variant gives exactly its expected reason', async () => {
      for (const variant of Object.values(v)) {
        const r = await run(variant.passport);
        if (variant.expect === 'accept') expect(r.ok, variant.name).toBe(true);
        else expect(r, variant.name).toEqual(fail(variant.reason));
      }
    });

    it('the eContentType and the signed contentType attribute must each be the LDS security object', async () => {
      const oid = '0606678108010101'; // 2.23.136.1.1.1; the SOD holds it twice: eContentType, then the attribute
      const hex = bytesToHex(good.sod);
      const first = hex.indexOf(oid);
      const second = hex.indexOf(oid, first + 1);
      expect(first).toBeGreaterThan(0);
      expect(second).toBeGreaterThan(first);
      for (const at of [first, second]) {
        const changed = hexToBytes(`${hex.slice(0, at)}0606678108010102${hex.slice(at + oid.length)}`);
        expect(await run({ ...good, sod: changed })).toEqual(fail('SOD_CONTENT_TYPE'));
      }
    });

    it('a CSCA or DS certificate outside its validity at the ledger time fails', async () => {
      expect(await run(good, { atTime: ripple('2045-01-01T00:00:00Z') })).toEqual(fail('DS_EXPIRED'));
      expect(await run(good, { atTime: ripple('2020-01-01T00:00:00Z') })).toEqual(fail('DS_EXPIRED'));
      // The same CSCA key and name, its certificate moved to 2005 to 2020: chained, but expired at the ledger time.
      const oldCsca = reissue(pki.csca.cert, { signer: pki.csca.key, notBefore: new Date('2005-01-01T00:00:00Z') });
      expect(await run(good, { trustList: [oldCsca] })).toEqual(fail('CSCA_EXPIRED'));
      expect((await run(good, { trustList: [oldCsca, pki.csca.cert] })).ok).toBe(true); // rollover: the valid one wins
    });

    it('a data group that the SOD does not list cannot be authenticated', async () => {
      const noAa = makePassport({ pki, mrz: MRZ, seed, aa: 'none' }); // a 1-hash SOD: invalid by itself
      expect(await run(noAa)).toEqual(fail('LDS_TOO_FEW_HASHES'));
      const other = makePassport({ pki, mrz: MRZ, seed: new Uint8Array(32).fill(1) });
      expect(await run(good, { dg15: other.dg15 })).toEqual(fail('DG15_HASH_MISMATCH'));
      expect(await run(good, { dg14: concatBytes(good.dg14 ?? new Uint8Array(), new Uint8Array(1)) })).toEqual(
        fail('DG14_HASH_MISMATCH'),
      );
    });
  });
}

describe('P1.9-03 and P1.9-04: valid but unusual signatures', () => {
  const pki = makeTestPki({ seed });
  const v = makeBadVariants({ pki, mrz: MRZ, seed });
  const run = (p: { dg1: Uint8Array; sod: Uint8Array }) =>
    passiveAuth({ dg1: p.dg1, sod: p.sod, trustList: [pki.csca.cert], atTime: AT });

  it('P1.9-03: a high-S ECDSA SOD signature passes', async () => {
    expect(v.highS?.passport).toBeDefined();
    expect((await run(v.highS?.passport ?? v.brainpoolDs.passport)).ok).toBe(true);
  });

  it('P1.9-04: a brainpoolP256r1 Document Signer passes through the noble fallback', async () => {
    expect((await run(v.brainpoolDs.passport)).ok).toBe(true);
  });

  it('the noble fallback accepts high S (lowS: false) and rejects a changed signature', async () => {
    const bpKey = ecKeyFromSeed(seed, 'variant/brainpool-ds', 'brainpoolP256r1');
    const ds = { cert: reissue(pki.ds.cert, { signer: pki.csca.key, key: bpKey }), key: bpKey };
    const n = brainpoolP256r1.Point.CURVE().n;
    const highS = (der: Uint8Array) => {
      const s = brainpoolP256r1.Signature.fromBytes(der, 'der');
      return s.s > n / 2n ? der : new brainpoolP256r1.Signature(s.r, n - s.s).toBytes('der');
    };
    const base = { mrz: v.brainpoolDs.passport.mrz, ds };
    const p = assemble({ ...base, aaKey: makePassport({ pki, mrz: MRZ, seed }).aaKey, sod: { tweakSignature: highS } });
    expect((await run(p)).ok).toBe(true);
    const bad = assemble({
      ...base,
      aaKey: p.aaKey,
      sod: { tweakSignature: (d) => highS(d).map((b, i, a) => (i === a.length - 1 ? b ^ 1 : b)) },
    });
    expect(await run(bad)).toEqual(fail('SOD_SIGNATURE_INVALID'));
  });
});

describe('the BSI TR-03105-5 reference EF.SOD (real-world encoding: RSA-PSS DS, NULL digest parameters)', () => {
  const sod = bsi('EF_SOD.bin');

  it('parses, and its LDS hashes equal SHA-256 of the reference DG1 and DG14', () => {
    const parsed = parseSod(sod);
    expect(parsed?.eContentType).toBe('2.23.136.1.1.1');
    const lds = parsed && parseLds(parsed.eContent);
    if (!lds || lds === 'few') throw new Error('LDS expected');
    expect([...lds.hashes.keys()].sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 14]);
    expect(bytesToHex(lds.hashes.get(1) ?? new Uint8Array())).toBe(bytesToHex(sha256(bsi('Datagroup1.bin'))));
    expect(bytesToHex(lds.hashes.get(14) ?? new Uint8Array())).toBe(bytesToHex(sha256(bsi('Datagroup14.bin'))));
  });

  it('its RSA-PSS SOD signature verifies, and the chain fails without its CSCA (not in the data set)', async () => {
    const at = ripple('2014-01-01T00:00:00Z');
    expect(await passiveAuth({ dg1: bsi('Datagroup1.bin'), sod, trustList: [], atTime: at })).toEqual(
      fail('DS_NOT_CHAINED'),
    );
    const flipped = sod.slice();
    flipped[sod.length - 1] = (flipped[sod.length - 1] ?? 0) ^ 1; // the last byte of the signature
    expect(await passiveAuth({ dg1: bsi('Datagroup1.bin'), sod: flipped, trustList: [], atTime: at })).toEqual(
      fail('SOD_SIGNATURE_INVALID'),
    );
  });
});

describe('hostile input never throws', () => {
  const pki = makeTestPki({ seed });
  const good = makePassport({ pki, mrz: MRZ, seed });
  const run = (dg1: Uint8Array, sod: Uint8Array, trustList = [pki.csca.cert]) =>
    passiveAuth({ dg1, sod, trustList, atTime: AT });

  it('random bytes as SOD, DG1 or trust anchor give a failure code', async () => {
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ maxLength: 400 }), async (junk) => {
        expect((await run(good.dg1, junk)).ok).toBe(false);
        expect((await run(junk, good.sod)).ok).toBe(false);
        expect(await run(good.dg1, good.sod, [junk])).toEqual(fail('DS_NOT_CHAINED'));
      }),
      { numRuns: 100 },
    );
  });

  it('a SOD of 20,000 nested indefinite-length SEQUENCEs is SOD_MALFORMED (no stack overflow)', async () => {
    const deep = new Uint8Array(40_000).map((_, i) => (i % 2 === 0 ? 0x30 : 0x80));
    const sod = concatBytes(new Uint8Array([0x77, 0x82, deep.length >> 8, deep.length & 0xff]), deep);
    expect(await run(good.dg1, sod)).toEqual(fail('SOD_MALFORMED'));
  });

  it('the SOD truncated at every 16th byte, or with a trailing byte, is SOD_MALFORMED', async () => {
    for (let i = 0; i < good.sod.length; i += 16)
      expect(await run(good.dg1, good.sod.subarray(0, i))).toEqual(fail('SOD_MALFORMED'));
    expect(await run(good.dg1, concatBytes(good.sod, new Uint8Array(1)))).toEqual(fail('SOD_MALFORMED'));
  });

  it('a signed DG1 that is not a TD3 MRZ is DG1_MALFORMED', async () => {
    for (const mrz of ['?'.repeat(88), good.mrz.slice(0, 87), `${good.mrz}<`]) {
      const p = assemble({ mrz, ds: pki.ds, aaKey: good.aaKey });
      expect(await run(p.dg1, p.sod), mrz).toEqual(fail('DG1_MALFORMED'));
    }
  });
});

describe('chipChecks: what the lawyer console signs for the nfc-chip method', () => {
  const pki = makeTestPki({ seed });
  const good = makePassport({ pki, mrz: MRZ, seed });
  const salt = new Uint8Array(32).fill(0x5a);
  const commitment = passportCommitment(passportRecord(good.dg1, good.sod), salt);
  const msg = presenceMsg(new Uint8Array(32).fill(1), 'A', new Uint8Array(32).fill(2), new Uint8Array(32).fill(3));
  const base = {
    dg1: good.dg1,
    sod: good.sod,
    dg14: good.dg14,
    dg15: good.dg15,
    trustList: [pki.csca.cert],
    atTime: AT,
    salt,
    commitment,
    presenceMsg: msg,
  };
  const aaSignature = chipAnswerAA(good.aaKey, aaChallenge(msg));
  const allTrue = {
    sod_signature_valid: true,
    ds_cert_chains_to_csca: true,
    dg1_hash_in_sod: true,
    document_not_expired: true,
    commitment_opens: true,
  };

  it('passportRecord and the chip commitment match the Python reference', () => {
    const vec = pyVector('identity', 'chip');
    const rec = passportRecord(hexToBytes(vec.inputs.dg1 ?? ''), hexToBytes(vec.inputs.sod ?? ''));
    expect(bytesToHex(passportCommitment(rec, hexToBytes(vec.inputs.salt ?? '')))).toBe(vec.output);
  });

  it('a good chip with an AA answer over the presenceMsg challenge gives every check true and AA', async () => {
    expect(await chipChecks({ ...base, aaSignature })).toEqual({
      ok: true,
      checks: { ...allTrue, chip_authentication: 'AA', chip_auth_available: true },
    });
  });

  it('T-U-16f: a commitment that does not open fails COMMITMENT_MISMATCH', async () => {
    expect(await chipChecks({ ...base, aaSignature, salt: new Uint8Array(32) })).toEqual(fail('COMMITMENT_MISMATCH'));
    expect(await chipChecks({ ...base, aaSignature, commitment: new Uint8Array(32) })).toEqual(
      fail('COMMITMENT_MISMATCH'),
    );
    expect(await chipChecks({ ...base, aaSignature, salt: new Uint8Array(31) })).toEqual(fail('COMMITMENT_MISMATCH'));
  });

  it('T-U-16m: a chip with DG15 but no chip authentication fails CHIP_AUTH_REQUIRED', async () => {
    expect(await chipChecks(base)).toEqual(fail('CHIP_AUTH_REQUIRED'));
  });

  it('T-U-16n: an AA answer over a different challenge fails CHIP_AUTH_INVALID', async () => {
    const other = chipAnswerAA(good.aaKey, msg.slice(8, 16));
    expect(await chipChecks({ ...base, aaSignature: other })).toEqual(fail('CHIP_AUTH_INVALID'));
  });

  it('a relayed chip: a valid AA answer from a chip whose DG15 is not the one in the SOD fails', async () => {
    const clone = makePassport({ pki, mrz: MRZ, seed: new Uint8Array(32).fill(3) });
    const sig = chipAnswerAA(clone.aaKey, aaChallenge(msg));
    expect(await chipChecks({ ...base, dg15: clone.dg15, aaSignature: sig })).toEqual(fail('DG15_HASH_MISMATCH'));
    expect(await chipChecks({ ...base, dg15: undefined, aaSignature: sig })).toEqual(fail('DG15_MISSING'));
  });

  it('Chip Authentication run by the native reader counts only when the chip has DG14', async () => {
    expect(await chipChecks({ ...base, caPassed: true })).toEqual({
      ok: true,
      checks: { ...allTrue, chip_authentication: 'CA', chip_auth_available: true },
    });
    expect(await chipChecks({ ...base, caPassed: true, aaSignature: aaSignature.map((b) => b ^ 1) })).toEqual(
      fail('CHIP_AUTH_INVALID'),
    );
    const rsa = makePassport({ pki, mrz: MRZ, seed, aa: 'rsa' }); // DG15 only, no DG14
    const rsaBase = {
      ...base,
      dg1: rsa.dg1,
      sod: rsa.sod,
      dg14: undefined,
      dg15: rsa.dg15,
      commitment: passportCommitment(passportRecord(rsa.dg1, rsa.sod), salt),
    };
    expect(await chipChecks({ ...rsaBase, caPassed: true })).toEqual(fail('CHIP_AUTH_REQUIRED'));
    const rsaSig = chipAnswerAA(rsa.aaKey, aaChallenge(msg));
    expect(await chipChecks({ ...rsaBase, aaSignature: rsaSig })).toEqual({
      ok: true,
      checks: { ...allTrue, chip_authentication: 'AA', chip_auth_available: true },
    });
  });

  it('a failed passive authentication is reported before anything else', async () => {
    const v = makeBadVariants({ pki, mrz: MRZ, seed });
    expect(await chipChecks({ ...base, aaSignature, sod: v.badSodSignature.passport.sod })).toEqual(
      fail('SOD_SIGNATURE_INVALID'),
    );
  });
});
