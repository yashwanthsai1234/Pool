// T-U-29 (key directory, echo broadcast, complaints, test-signing) and P1.15-01 to 04, 21.
import { ed25519 } from '@noble/curves/ed25519.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { describe, expect, it, vi } from 'vitest';
import { deriveAddress } from 'xrpl';
import { tupleHash } from '../src/dealcore.ts';
import {
  aggregateChecked,
  enrollmentSigned,
  type FrostError,
  type FrostMsg,
  holderId,
  type KeyShare,
  SigningSession,
  type SlotPublic,
  scalarBytes,
  slotPolicy,
  u32,
} from '../src/frost.ts';
import {
  checkContext,
  type DkgContext,
  dkgCompletedRecord,
  dkgReceiveEcho,
  dkgReceiveRound1,
  dkgReceiveRound2,
  dkgStart,
  judgeComplaint,
  readRound1,
  testSignCheck,
  testSignMessage,
} from '../src/frostDkg.ts';
import {
  EnrollmentRegistry,
  enrollmentKeyHash,
  qrPin,
  serviceKeyListMessage,
  verifyQrPin,
  verifyServiceKeyList,
} from '../src/frostSetup.ts';
import {
  chunkRng,
  dkgKeys,
  enc,
  enroll,
  hex,
  noPinCheck,
  runDkg,
  scalarRngBytes,
  slotSetup,
  xwing,
} from './helpers/frost.ts';

// DKG and X-Wing are slow when the whole suite runs in parallel.
vi.setConfig({ testTimeout: 60_000 });

const code = async (f: () => unknown) => {
  try {
    await f();
  } catch (e) {
    return (e as FrostError).code;
  }
  return 'NO_THROW';
};
const r2Aad = (ctx: DkgContext, from: number, to: number) =>
  tupleHash('legx/frost-dkg-r2/v1', [ctx.sessionId, u32(from), u32(to)]);

describe('T-U-29a/b/c key directory', () => {
  it('T-U-29a a swapped or never-pinned key is refused KEY_NOT_PINNED before any DKG message', async () => {
    const { ctx, holders } = slotSetup('LA');
    const reg = new EnrollmentRegistry();
    for (const h of holders) {
      reg.pin(h.key);
      reg.markLogged(enrollmentKeyHash(h.key));
    }
    const deps = { signer: holders[0]!.signer, cipher: xwing, pinned: reg.check };
    expect(dkgStart(ctx, 1, deps).out).toHaveLength(1);
    const coordinatorKey = enroll('evil', 'firm-hsm');
    const swapped = {
      ...ctx,
      holders: ctx.holders.map((h, i) => (i === 1 ? { ...h, edPub: coordinatorKey.key.edPub } : h)),
    };
    expect(await code(() => dkgStart(swapped, 1, deps))).toBe('KEY_NOT_PINNED');
    const unknown = { ...ctx, holders: ctx.holders.map((h, i) => (i === 2 ? { ...h, holder: 'never-pinned' } : h)) };
    expect(await code(() => dkgStart(unknown, 1, deps))).toBe('KEY_NOT_PINNED');
  });

  it('T-U-29b QR pinning between two devices; signed service key lists anchored on the ledger', async () => {
    const phone = enroll('A/phone', 'phone');
    const key2 = enroll('A/second', 'second-authenticator');
    const qr = qrPin(phone.key, key2.key);
    expect(await code(() => verifyQrPin(qr, phone.key, key2.key, qr.sas))).toBe('NO_THROW');
    const mitm = enroll('A/phone', 'phone');
    expect(await code(() => verifyQrPin(qr, mitm.key, key2.key, qr.sas))).toBe('PIN_MISMATCH');
    expect(await code(() => verifyQrPin(qr, phone.key, mitm.key, qr.sas))).toBe('PIN_MISMATCH');
    expect(
      await code(() =>
        verifyQrPin({ ...qr, sas: '000000' === qr.sas ? '111111' : '000000' }, phone.key, key2.key, qr.sas),
      ),
    ).toBe('PIN_MISMATCH');
    expect(await code(() => verifyQrPin(qr, phone.key, key2.key, 'abcdef'))).toBe('PIN_MISMATCH');

    const opsSecret = ed25519.utils.randomSecretKey();
    const opsPub = new Uint8Array([0xed, ...ed25519.getPublicKey(opsSecret)]);
    const opsAccount = deriveAddress(hex(opsPub).toUpperCase());
    const hsm = enroll('firm/hsm', 'firm-hsm');
    const bytes = enc(
      JSON.stringify({ keys: [{ holder: 'firm/hsm', role: 'firm-hsm', ed25519: hex(hsm.key.edPub).toUpperCase() }] }),
    );
    const list = { bytes, signerPub: opsPub, sig: ed25519.sign(serviceKeyListMessage(bytes), opsSecret) };
    const anchor = { account: 'rServiceAccount', hash: sha256(bytes) };
    const expected = { serviceAccount: 'rServiceAccount', opsAccount };
    const keys = verifyServiceKeyList(list, anchor, expected);
    expect(hex(keys[0]!.edPub)).toBe(hex(hsm.key.edPub));
    expect(await code(() => verifyServiceKeyList(list, { ...anchor, hash: sha256(enc('other')) }, expected))).toBe(
      'PIN_MISMATCH',
    );
    expect(await code(() => verifyServiceKeyList(list, { ...anchor, account: 'rOther' }, expected))).toBe(
      'PIN_MISMATCH',
    );
    const otherSecret = ed25519.utils.randomSecretKey();
    const otherPub = new Uint8Array([0xed, ...ed25519.getPublicKey(otherSecret)]);
    const byOther = { bytes, signerPub: otherPub, sig: ed25519.sign(serviceKeyListMessage(bytes), otherSecret) };
    expect(await code(() => verifyServiceKeyList(byOther, anchor, expected))).toBe('LIST_SIGNER_WRONG');
    expect(await code(() => verifyServiceKeyList({ ...list, sig: new Uint8Array(64) }, anchor, expected))).toBe(
      'LIST_SIGNER_WRONG',
    );
    expect(await code(() => verifyServiceKeyList({ ...list, signerPub: new Uint8Array(32) }, anchor, expected))).toBe(
      'LIST_SIGNER_WRONG',
    );
    // A firm whose operations account has a secp256k1 master key (DESIGN 6.14) works too.
    const secpSk = secp256k1.utils.randomSecretKey();
    const secpPub = secp256k1.getPublicKey(secpSk);
    const secpSig = secp256k1.sign(sha512(serviceKeyListMessage(bytes)).subarray(0, 32), secpSk, {
      prehash: false,
      format: 'der',
    });
    const secpList = { bytes, signerPub: secpPub, sig: secpSig };
    const secpOps = deriveAddress(hex(secpPub).toUpperCase());
    expect(verifyServiceKeyList(secpList, anchor, { ...expected, opsAccount: secpOps })).toHaveLength(1);
    const junk = enc('not json');
    const junkList = { bytes: junk, signerPub: opsPub, sig: ed25519.sign(serviceKeyListMessage(junk), opsSecret) };
    expect(await code(() => verifyServiceKeyList(junkList, { ...anchor, hash: sha256(junk) }, expected))).toBe(
      'INPUT_INVALID',
    );
  });

  it('T-U-29c the registry is append-only and a key is usable only once logged', async () => {
    const reg = new EnrollmentRegistry();
    const a = enroll('A/phone', 'phone');
    reg.pin(a.key);
    reg.pin(a.key); // same key again: no-op
    expect(await code(() => reg.require(a.key))).toBe('KEY_NOT_LOGGED');
    reg.markLogged(enrollmentKeyHash(a.key));
    expect(await code(() => reg.require(a.key))).toBe('NO_THROW');
    expect(await code(() => reg.pin({ ...a.key, edPub: enroll('x', 'phone').key.edPub }))).toBe('KEY_CHANGED');
    expect(await code(() => reg.remove('A/phone', 'phone'))).toBe('REGISTRY_APPEND_ONLY');
  });
});

describe('T-U-29d echo broadcast', () => {
  it('a holder shown a different round-1 message makes every holder abort with TRANSCRIPT_MISMATCH', async () => {
    const { ctx, holders } = slotSetup('A');
    // Holder 1 equivocates: a second, validly signed round-1 message goes to holder 2 only.
    const alt = dkgStart(ctx, 1, { signer: holders[0]!.signer, cipher: xwing, pinned: noPinCheck }).out[0]!;
    const starts = holders.map((h, i) => dkgStart(ctx, i + 1, { signer: h.signer, cipher: xwing, pinned: noPinCheck }));
    const r1 = starts.flatMap((s) => s.out);
    const echoes = starts.map(
      (s) =>
        dkgReceiveRound1(
          s.state,
          r1.filter((m) => m.from !== s.state.me).map((m) => (m.from === 1 && s.state.me === 2 ? alt : m)),
        ).out[0]!,
    );
    for (const s of starts) {
      expect(
        await code(() =>
          dkgReceiveEcho(
            s.state,
            echoes.filter((e) => e.from !== s.state.me),
          ),
        ),
      ).toBe('TRANSCRIPT_MISMATCH');
    }
  });

  it('echo before round 1, and round 2 before round 1, are refused', async () => {
    const { ctx, holders } = slotSetup('A');
    const s = dkgStart(ctx, 1, { signer: holders[0]!.signer, cipher: xwing, pinned: noPinCheck });
    expect(await code(() => dkgReceiveEcho(s.state, []))).toBe('INPUT_INVALID');
    expect(await code(() => dkgReceiveRound2(s.state, []))).toBe('INPUT_INVALID');
  });
});

describe('T-U-29e complaints', () => {
  it('a bad share is named by a verifiable complaint; a false complaint names its author', async () => {
    const { ctx, holders } = slotSetup('A');
    // Holder 1 sends holder 2 a share that fails the Feldman check, encrypted and signed properly.
    const fresh = await runDkg(ctx, holders, {
      r2: async (m, round1) => {
        if (m.from !== 1 || m.to !== 2) return m;
        const kemPub2 = readRound1(
          ctx,
          1,
          round1.filter((x) => x.from !== 1),
        ).get(2)!.kemPub;
        const ct = await xwing.seal(kemPub2, r2Aad(ctx, 1, 2), scalarBytes(42n));
        return enrollmentSigned(holders[0]!.signer, { ...m, fields: [ct] });
      },
    });
    const res2 = fresh.results[1]!;
    expect(res2.key).toBeUndefined();
    expect(res2.out).toHaveLength(1);
    const complaint = res2.out[0]!;
    expect(complaint.kind).toBe('dkg-complaint');
    const verdict = await judgeComplaint(ctx, fresh.round1, complaint, xwing);
    expect(verdict.guilty).toBe(1);
    // A false complaint: holder 2 accuses honest holder 3, carrying 3's real ciphertext.
    const real = fresh.r2.find((m) => m.from === 3 && m.to === 2)!;
    const kemSecret = complaint.fields[3]!;
    const falseComplaint = enrollmentSigned(holders[1]!.signer, {
      session: ctx.sessionId,
      kind: 'dkg-complaint',
      from: 2,
      to: 0,
      fields: [u32(3), real.fields[0]!, real.sig, kemSecret],
    });
    expect((await judgeComplaint(ctx, fresh.round1, falseComplaint, xwing)).guilty).toBe(2);
    // Forged evidence (a ciphertext the accused never signed) and a wrong KEM key also name the complainer.
    const forged = enrollmentSigned(holders[1]!.signer, {
      ...falseComplaint,
      fields: [u32(3), real.fields[0]!, new Uint8Array(64), kemSecret],
    });
    expect((await judgeComplaint(ctx, fresh.round1, forged, xwing)).guilty).toBe(2);
    const wrongKem = enrollmentSigned(holders[1]!.signer, {
      ...falseComplaint,
      fields: [u32(3), real.fields[0]!, real.sig, xwing.keygen().secretKey],
    });
    expect((await judgeComplaint(ctx, fresh.round1, wrongKem, xwing)).guilty).toBe(2);
    const self = enrollmentSigned(holders[1]!.signer, {
      ...falseComplaint,
      fields: [u32(2), real.fields[0]!, real.sig, kemSecret],
    });
    expect((await judgeComplaint(ctx, fresh.round1, self, xwing)).reason).toBe('malformed complaint');
    // A share that is not even a valid scalar is a Feldman failure too.
    const junk = await runDkg(ctx, holders, {
      r2: async (m, round1) => {
        if (m.from !== 3 || m.to !== 1) return m;
        const kemPub1 = readRound1(
          ctx,
          3,
          round1.filter((x) => x.from !== 3),
        ).get(1)!.kemPub;
        const ct = await xwing.seal(kemPub1, r2Aad(ctx, 3, 1), new Uint8Array(32).fill(0xff));
        return enrollmentSigned(holders[2]!.signer, { ...m, fields: [ct] });
      },
    });
    expect((await judgeComplaint(ctx, junk.round1, junk.results[0]!.out[0]!, xwing)).guilty).toBe(3);
    // Honest holders 1 and 3 got valid keys from everyone.
    expect(fresh.results[0]!.key).toBeDefined();
  });
});

async function testSigs(ctx: DkgContext, pub: SlotPublic, shares: KeyShare[]) {
  return PAIRS.map((pair) => {
    const msg = testSignMessage(ctx, pub, pair);
    const s = pair.map((i) => SigningSession.open(shares[i - 1]!, pub, msg));
    const list = s.map((x) => x.commitment);
    const sigShares = Object.fromEntries(
      pair.map((i, k) => [holderId(i), s[k]!.signShare(msg, list, testSignCheck(ctx, pub, i))]),
    );
    return { pair, sig: aggregateChecked(pub, list, msg, sigShares) };
  });
}
const PAIRS: [number, number][] = [
  [1, 2],
  [1, 3],
  [2, 3],
];

describe('T-U-29f test-signing and the frost.dkg.completed record', () => {
  it('with all three pairs good the record holds the transcript hash, all signatures, verifying shares and test signatures', async () => {
    const { ctx, run, keys, pub } = await dkgKeys('LB');
    const tests = await testSigs(
      ctx,
      pub,
      keys.map((k) => k.secret),
    );
    const rec = dkgCompletedRecord({ ctx, pub, round1: run.round1, echoes: run.echoes, testSignatures: tests });
    expect(rec.kind).toBe('frost.dkg.completed');
    expect(hex(rec.transcriptHash)).toBe(hex(run.echoes[0]!.fields[0]!));
    expect(rec.transcriptSigs).toHaveLength(3);
    expect(rec.verifyingShares.map(hex)).toEqual([1, 2, 3].map((i) => hex(pub.verifyingShares[holderId(i)]!)));
    expect(rec.testSignatures).toHaveLength(3);
    expect(hex(rec.slotPolicy)).toBe(hex(slotPolicy('LB', ['console', 'firm-hsm', 'partner'])));
    // Signing anything else with the test checker is refused.
    const s = SigningSession.open(keys[0]!.secret, pub, enc('other'));
    const t = SigningSession.open(keys[1]!.secret, pub, enc('other'));
    expect(
      await code(() => s.signShare(enc('other'), [s.commitment, t.commitment], () => ({ ok: false, reason: 'x' }))),
    ).toBe('MESSAGE_REFUSED');
  });

  it('one broken pair, a missing echo, or a different transcript: SLOT_SETUP_FAILED and no record', async () => {
    const { ctx, run, keys, pub } = await dkgKeys('LB');
    const tests = await testSigs(
      ctx,
      pub,
      keys.map((k) => k.secret),
    );
    const base = { ctx, pub, round1: run.round1, echoes: run.echoes, testSignatures: tests };
    const broken = tests.map((t) => (t.pair[1] === 3 && t.pair[0] === 2 ? { ...t, sig: tests[0]!.sig } : t));
    expect(await code(() => dkgCompletedRecord({ ...base, testSignatures: broken }))).toBe('SLOT_SETUP_FAILED');
    expect(await code(() => dkgCompletedRecord({ ...base, testSignatures: tests.slice(0, 2) }))).toBe(
      'SLOT_SETUP_FAILED',
    );
    expect(await code(() => dkgCompletedRecord({ ...base, echoes: run.echoes.slice(0, 2) }))).toBe('SLOT_SETUP_FAILED');
    expect(await code(() => dkgCompletedRecord({ ...base, round1: run.round1.slice(0, 2) }))).toBe('SLOT_SETUP_FAILED');
    const otherHash = enrollmentSigned(
      { sign: () => new Uint8Array(64) },
      { ...run.echoes[0]!, fields: [randomBytes(32)] },
    );
    expect(await code(() => dkgCompletedRecord({ ...base, echoes: [otherHash, ...run.echoes.slice(1)] }))).toBe(
      'SLOT_SETUP_FAILED',
    );
    const other = await dkgKeys('LB');
    expect(await code(() => dkgCompletedRecord({ ...base, pub: other.pub }))).toBe('SLOT_SETUP_FAILED');
    const vsSwap = {
      ...pub,
      verifyingShares: { ...pub.verifyingShares, [holderId(1)]: pub.verifyingShares[holderId(2)]! },
    };
    expect(await code(() => dkgCompletedRecord({ ...base, pub: vsSwap }))).toBe('SLOT_SETUP_FAILED');
    // A holder with a broken share cannot make a valid test signature at all.
    const brokenShare = { ...keys[2]!.secret, signingShare: scalarBytes(7n) };
    expect(await code(() => testSigs(ctx, pub, [keys[0]!.secret, keys[1]!.secret, brokenShare]))).toBe('SHARE_INVALID');
  });
});

describe('P1.15-01 to 04, 21 transport and setup', () => {
  it('P1.15-01 round-2 shares travel only as X-Wing ciphertexts; a plain package is refused', async () => {
    const { ctx, holders } = slotSetup('A');
    const run = await runDkg(ctx, holders);
    const recording = JSON.stringify([...run.round1, ...run.echoes, ...run.r2].map((m) => m.fields.map(hex)));
    for (const k of run.results) expect(recording).not.toContain(hex(k.key!.secret.signingShare));
    // No round-2 share (any sub-share) appears in plain text: every round-2 field is a 1,168-byte ciphertext.
    for (const m of run.r2) expect(m.fields[0]!.length).toBe(1168);
    const fresh = slotSetup('A');
    const plain = await runDkg(fresh.ctx, fresh.holders, {
      r2: (m) =>
        m.from === 3 && m.to === 1
          ? enrollmentSigned(fresh.holders[2]!.signer, { ...m, fields: [scalarBytes(5n)] })
          : m,
    });
    expect(plain.results[0]!.key).toBeUndefined();
    expect(plain.results[0]!.out[0]!.kind).toBe('dkg-complaint');
  });

  it('P1.15-02 a round-2 package for another recipient, or replayed into another session, is refused', async () => {
    const { ctx, holders } = slotSetup('A');
    const starts = holders.map((h, i) => dkgStart(ctx, i + 1, { signer: h.signer, cipher: xwing, pinned: noPinCheck }));
    const r1 = starts.flatMap((s) => s.out);
    const echoes = starts.map(
      (s) =>
        dkgReceiveRound1(
          s.state,
          r1.filter((m) => m.from !== s.state.me),
        ).out[0]!,
    );
    const r2: FrostMsg[] = [];
    for (const s of starts)
      r2.push(
        ...(
          await dkgReceiveEcho(
            s.state,
            echoes.filter((e) => e.from !== s.state.me),
          )
        ).out,
      );
    const to1 = r2.filter((m) => m.to === 1);
    const misrouted = r2.find((m) => m.from === 2 && m.to === 3)!;
    expect(await code(() => dkgReceiveRound2(starts[0]!.state, [misrouted, to1[1]!]))).toBe('WRONG_RECIPIENT');
    expect(await code(() => dkgReceiveRound2(starts[0]!.state, [{ ...misrouted, to: 1 }, to1[1]!]))).toBe(
      'ENROLLMENT_SIG_INVALID',
    );
    const other = { ...to1[0]!, session: randomBytes(32) };
    expect(await code(() => dkgReceiveRound2(starts[0]!.state, [other, to1[1]!]))).toBe('ENROLLMENT_SIG_INVALID');
    const replay = enrollmentSigned(holders[1]!.signer, { ...to1[0]!, session: randomBytes(32) });
    expect(await code(() => dkgReceiveRound2(starts[0]!.state, [replay, to1[1]!]))).toBe('SESSION_MISMATCH');
  });

  it('P1.15-03 a wrong proof of knowledge aborts the DKG and names the participant', async () => {
    const { ctx, holders } = slotSetup('A');
    const starts = holders.map((h, i) => dkgStart(ctx, i + 1, { signer: h.signer, cipher: xwing, pinned: noPinCheck }));
    const m3 = starts[2]!.out[0]!;
    const pok = m3.fields[2]!.slice();
    pok[40] = (pok[40] as number) ^ 1;
    const badPok = enrollmentSigned(holders[2]!.signer, {
      ...m3,
      fields: [m3.fields[0]!, m3.fields[1]!, pok, m3.fields[3]!],
    });
    let err: FrostError | undefined;
    try {
      dkgReceiveRound1(starts[0]!.state, [starts[1]!.out[0]!, badPok]);
    } catch (e) {
      err = e as FrostError;
    }
    expect([err?.code, err?.culprit]).toEqual(['POK_INVALID', 3]);
    const shortFields = enrollmentSigned(holders[2]!.signer, { ...m3, fields: m3.fields.slice(0, 3) });
    expect(await code(() => dkgReceiveRound1(starts[0]!.state, [starts[1]!.out[0]!, shortFields]))).toBe(
      'INPUT_INVALID',
    );
    const badPoint = enrollmentSigned(holders[2]!.signer, {
      ...m3,
      fields: [new Uint8Array(32), ...m3.fields.slice(1)],
    });
    expect(await code(() => dkgReceiveRound1(starts[0]!.state, [starts[1]!.out[0]!, badPoint]))).toBe('INPUT_INVALID');
  });

  it('P1.15-04 two runs give different group keys; an injected deterministic source repeats its result', async () => {
    const a = await dkgKeys('A');
    const b = await dkgKeys('A');
    expect(hex(a.pub.commitments[0]!)).not.toBe(hex(b.pub.commitments[0]!));
    const { ctx, holders } = slotSetup('A');
    const det = () => chunkRng([scalarRngBytes(11n), scalarRngBytes(12n), scalarRngBytes(13n)]);
    const one = dkgStart(ctx, 1, { signer: holders[0]!.signer, cipher: xwing, pinned: noPinCheck, rng: det() });
    const two = dkgStart(ctx, 1, { signer: holders[0]!.signer, cipher: xwing, pinned: noPinCheck, rng: det() });
    expect(one.out[0]!.fields.slice(0, 3).map(hex)).toEqual(two.out[0]!.fields.slice(0, 3).map(hex));
  });

  it('P1.15-21 two holders on one device are refused SAME_DEVICE_SHARES unless the slot is in single-device mode', async () => {
    const { ctx } = slotSetup('A');
    const same = {
      ...ctx,
      holders: ctx.holders.map((h, i) => (i === 1 ? { ...h, deviceId: ctx.holders[0]!.deviceId } : h)),
    };
    expect(await code(() => checkContext(same))).toBe('SAME_DEVICE_SHARES');
    const single = {
      ...same,
      holders: same.holders.map((h, i) => (i === 1 ? { ...h, role: 'passkey-same-device' as const } : h)),
    };
    expect(await code(() => checkContext(single))).toBe('NO_THROW');
    const shuffled = { ...ctx, holders: [ctx.holders[1]!, ctx.holders[0]!, ctx.holders[2]!] };
    expect(await code(() => checkContext(shuffled))).toBe('ROLE_INVALID');
    expect(await code(() => checkContext({ ...ctx, sessionId: new Uint8Array(16) }))).toBe('INPUT_INVALID');
    const dupKey = {
      ...ctx,
      holders: ctx.holders.map((h, i) => (i === 2 ? { ...h, edPub: ctx.holders[0]!.edPub } : h)),
    };
    expect(await code(() => checkContext(dupKey))).toBe('INPUT_INVALID');
    expect(
      await code(() =>
        dkgStart(ctx, 4, { signer: { sign: () => new Uint8Array(64) }, cipher: xwing, pinned: noPinCheck }),
      ),
    ).toBe('INPUT_INVALID');
  });
});
