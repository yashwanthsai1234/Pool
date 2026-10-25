// Task 4.6: the chip-link protocol against the simulated sender. P4.6-01 to 03, fuzz, clone chip, eavesdropper.
import { presenceMsg } from '@legx/core/attest';
import { passportCommitment } from '@legx/core/dealcore';
import { passportRecord } from '@legx/core/passport/passiveAuth';
import { makePassport, makeTestPki } from '@legx/fixtures';
import { bytesToHex } from '@noble/hashes/utils.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { createSession, decodeChipData, encodeChipData, parseQr, receiveChip, simSend } from '../src/index.ts';

const RIPPLE_EPOCH = 946_684_800;
const AT = Date.parse('2027-06-01T12:00:00Z') / 1000 - RIPPLE_EPOCH;
const MRZ = {
  documentNumber: 'L898902C3',
  surname: 'ERIKSSON',
  givenNames: 'ANNA MARIA',
  dateOfBirth: '740812',
  sex: 'F',
  dateOfExpiry: '340415',
} as const;
const seed = new Uint8Array(32).fill(9);
const pki = makeTestPki({ seed });
const good = makePassport({ pki, mrz: MRZ, seed });
const other = makePassport({ pki, mrz: { ...MRZ, documentNumber: 'X12345678' }, seed: new Uint8Array(32).fill(3) });
const salt = new Uint8Array(32).fill(0x5a);
const msg = presenceMsg(new Uint8Array(32).fill(1), 'A', new Uint8Array(32).fill(2), new Uint8Array(32).fill(3));
const ctx = {
  trustList: [pki.csca.cert],
  atTime: AT,
  salt,
  commitment: passportCommitment(passportRecord(good.dg1, good.sod), salt),
  presenceMsg: msg,
};
const fail = (code: string) => ({ ok: false, code });

describe('P4.6-01 the transfer format', () => {
  it('round-trips DG1, SOD, DG14, DG15 and the AA answer', () => {
    const d = {
      dg1: good.dg1,
      sod: good.sod,
      dg14: good.dg14,
      dg15: good.dg15,
      aaSignature: new Uint8Array(64).fill(7),
    };
    expect(decodeChipData(encodeChipData(d))).toEqual({ ok: true, data: d });
  });
  it('property: any subset with DG1 and SOD round-trips', () => {
    const b = fc.uint8Array({ maxLength: 300 });
    fc.assert(
      fc.property(
        b,
        b,
        fc.option(b, { nil: undefined }),
        fc.option(b, { nil: undefined }),
        fc.option(b, { nil: undefined }),
        (dg1, sod, dg14, dg15, aaSignature) => {
          const d = { dg1, sod, dg14, dg15, aaSignature };
          expect(decodeChipData(encodeChipData(d))).toEqual({ ok: true, data: d });
        },
      ),
    );
  });
  it('refuses magic, version, order, repeats, unknown tags, truncation, trailing bytes and missing fields', () => {
    const ok = encodeChipData({ dg1: Uint8Array.of(1), sod: Uint8Array.of(2) });
    const code = (b: Uint8Array) => (decodeChipData(b) as { code?: string }).code;
    expect(code(Uint8Array.of(1, 2))).toBe('WIRE_TRUNCATED');
    expect(code(Uint8Array.of(0, 0, 0, 0, 1))).toBe('WIRE_MAGIC');
    expect(code(Uint8Array.from([...ok.slice(0, 4), 2, ...ok.slice(5)]))).toBe('WIRE_VERSION');
    expect(code(ok.slice(0, ok.length - 1))).toBe('WIRE_TRUNCATED');
    expect(code(Uint8Array.from([...ok, 9]))).toBe('WIRE_TRUNCATED');
    expect(code(Uint8Array.from([...ok, 9, 0, 0, 0, 0]))).toBe('WIRE_TAG');
    expect(code(Uint8Array.from([...ok, 2, 0, 0, 0, 0]))).toBe('WIRE_TAG');
    expect(code(Uint8Array.from([...ok.slice(0, 5), 2, 0, 0, 0, 1, 2]))).toBe('WIRE_MISSING');
    expect(code(Uint8Array.from([...ok.slice(0, 5), 1, 0xff, 0xff, 0xff, 0xff]))).toBe('WIRE_TOO_LARGE');
  });
  it('fuzz: the decoder never throws on arbitrary bytes or on mutated valid messages', () => {
    const valid = encodeChipData({ dg1: good.dg1, sod: good.sod, dg15: good.dg15, aaSignature: new Uint8Array(64) });
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 400 }), (b) => void decodeChipData(b)),
      { numRuns: 3000 },
    );
    fc.assert(
      fc.property(fc.nat(valid.length - 1), fc.nat(255), fc.nat(valid.length), (i, v, cut) => {
        const m = valid.slice(0, cut);
        if (i < m.length) m[i] = v;
        const r = decodeChipData(m);
        if (r.ok) expect(r.data.dg1.length).toBeGreaterThan(-1);
      }),
      { numRuns: 3000 },
    );
  });
});

describe('P4.6-02 the channel', () => {
  it('the QR carries a one-time key, the session and the challenge; the console opens it once', async () => {
    const s = await createSession(msg);
    const q = parseQr(s.qr);
    expect(q && bytesToHex(q.challenge)).toBe(bytesToHex(msg.slice(0, 8)));
    const sealed = await simSend(s.qr, { passport: good, aaKey: good.aaKey });
    expect((await receiveChip(s, sealed, ctx)).ok).toBe(true);
    expect(await receiveChip(s, sealed, ctx)).toEqual(fail('SESSION_USED'));
  });
  it('a third party on the network sees only ciphertext, and cannot open it', async () => {
    const s = await createSession(msg);
    const sealed = await simSend(s.qr, { passport: good, aaKey: good.aaKey });
    const wire = Buffer.concat([sealed.enc, sealed.ct]);
    for (const part of [good.dg1, good.sod, good.dg15 as Uint8Array]) {
      expect(wire.includes(part.slice(0, 16))).toBe(false);
    }
    expect(wire.includes(Buffer.from('LGXC'))).toBe(false);
    const eve = await createSession(msg); // another key, same challenge
    expect(await receiveChip(eve, sealed, ctx)).toEqual(fail('OPEN_FAILED'));
  });
  it('a tampered ciphertext or a replay into another session fails and does not burn the session', async () => {
    const s = await createSession(msg);
    const sealed = await simSend(s.qr, { passport: good, aaKey: good.aaKey });
    const bad = { enc: sealed.enc, ct: sealed.ct.map((x, i) => (i === 5 ? x ^ 1 : x)) };
    expect(await receiveChip(s, bad, ctx)).toEqual(fail('OPEN_FAILED'));
    expect((await receiveChip(s, sealed, ctx)).ok).toBe(true);
    const s2 = await createSession(msg);
    expect(await receiveChip(s2, sealed, ctx)).toEqual(fail('OPEN_FAILED'));
  });
  it('parseQr refuses malformed input', () => {
    for (const x of ['', 'x:y', 'legxchip1:zz:zz:zz', 'legxchip1:00:00:AA:extra']) expect(parseQr(x)).toBeUndefined();
  });
});

describe('P4.6-03 the AA challenge is the first 8 bytes of presenceMsg', () => {
  it('the console verifies the answer and reports AA', async () => {
    const s = await createSession(msg);
    const r = await receiveChip(s, await simSend(s.qr, { passport: good, aaKey: good.aaKey }), ctx);
    expect(r).toEqual({
      ok: true,
      checks: expect.objectContaining({ chip_authentication: 'AA', commitment_opens: true }),
    });
  });
  it('an answer to a different presenceMsg is CHIP_AUTH_INVALID', async () => {
    const s = await createSession(msg);
    const stale = presenceMsg(new Uint8Array(32).fill(9), 'A', new Uint8Array(32).fill(2), new Uint8Array(32).fill(3));
    expect(bytesToHex(stale.slice(0, 8))).not.toBe(bytesToHex(msg.slice(0, 8)));
    const r = await receiveChip(s, await simSend(s.qr, { passport: good, aaKey: good.aaKey }), {
      ...ctx,
      presenceMsg: stale,
    });
    expect(r).toEqual(fail('CHIP_AUTH_INVALID'));
  });
});

describe('a card with copied passport data but no AA key', () => {
  it('answering with another key gives CHIP_AUTH_INVALID', async () => {
    const s = await createSession(msg);
    expect(await receiveChip(s, await simSend(s.qr, { passport: good, aaKey: other.aaKey }), ctx)).toEqual(
      fail('CHIP_AUTH_INVALID'),
    );
  });
  it('giving no answer at all gives CHIP_AUTH_REQUIRED (the SOD lists DG15)', async () => {
    const s = await createSession(msg);
    expect(await receiveChip(s, await simSend(s.qr, { passport: good }), ctx)).toEqual(fail('CHIP_AUTH_REQUIRED'));
  });
});

describe('P4.6-04 a real passport on a real phone', () => {
  it.todo('manual: passive authentication and Active or Chip Authentication pass (DESIGN M5 [CHECK])');
});
