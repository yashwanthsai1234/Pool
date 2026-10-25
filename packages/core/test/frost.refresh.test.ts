// T-U-23 (refresh with Feldman checks), T-U-30a/b (repair), P1.15-14 to 16, 18 to 20.
import { ed25519_FROST } from '@noble/curves/ed25519.js';
import { describe, expect, it, vi } from 'vitest';
import { tupleHash } from '../src/dealcore.ts';
import {
  enrollmentSigned,
  Fn,
  type FrostError,
  type FrostMsg,
  holderId,
  type KeyShare,
  mulBase,
  Point,
  parsePoint,
  parseScalar,
  type SlotPublic,
  scalarBytes,
  slotPolicy,
  slotPubkey,
  u32,
  verifyEd25519Strict,
  vssEval,
} from '../src/frost.ts';
import {
  deletionStatement,
  type RefreshContext,
  type RefreshState,
  refreshedEvent,
  refreshReceiveCommits,
  refreshReceiveShares,
  refreshStart,
} from '../src/frostRefresh.ts';
import { checkDelta, repairDelta, repairFinish, repairSigma } from '../src/frostRepair.ts';
import { rotationPlan } from '../src/frostRules.ts';
import {
  chunkRng,
  dkgKeys,
  type Enrolled,
  enc,
  enroll,
  frostSign,
  hex,
  refreshCtx,
  refreshSlot,
  repairShare,
  scalarRngBytes,
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

const pairsOf = (ids: number[]) => ids.flatMap((a, i) => ids.slice(i + 1).map((b) => [a, b]));

describe('T-U-23 refresh', () => {
  it('T-U-23a the group key is unchanged and every pair still signs, with every sub-share Feldman-checked', async () => {
    const s = await dkgKeys('A');
    const ctx = refreshCtx(s);
    const { results } = await refreshSlot(s, ctx);
    const pub = results[0]!.pub;
    for (const r of results) expect(hex(slotPubkey(r.pub))).toBe(hex(slotPubkey(s.pub)));
    for (const r of results) expect(r.pub.verifyingShares).toEqual(pub.verifyingShares);
    for (const [a, b] of pairsOf([1, 2, 3])) {
      const sig = frostSign(pub, [results[a! - 1]!.share, results[b! - 1]!.share], enc('after refresh'));
      expect(verifyEd25519Strict(sig, enc('after refresh'), slotPubkey(pub))).toBe(true);
    }
  });

  it('T-U-23b one old share and one refreshed share do not combine', async () => {
    const s = await dkgKeys('A');
    const { results } = await refreshSlot(s, refreshCtx(s));
    const msg = enc('mix');
    const oldShare = s.keys[0]!.secret;
    const newShare = results[1]!.share;
    // Through our wrapper: the old share does not match the new verifying share.
    expect(await code(() => frostSign(results[0]!.pub, [oldShare, newShare], msg))).toBe('SHARE_INVALID');
    // Raw noble with the old public data and nonces: the aggregate fails.
    const g = [oldShare, newShare].map((k) => ed25519_FROST.commit(k));
    const list = g.map((x) => x.commitments);
    const shares = Object.fromEntries(
      [oldShare, newShare].map((k, i) => [k.identifier, ed25519_FROST.signShare(k, s.pub, g[i]!.nonces, list, msg)]),
    );
    expect(() => ed25519_FROST.aggregate(s.pub, list, msg, shares)).toThrow();
    // Old shares still combine with each other: refresh is hygiene, not revocation.
    expect(
      verifyEd25519Strict(frostSign(s.pub, [s.keys[0]!.secret, s.keys[1]!.secret], msg), msg, slotPubkey(s.pub)),
    ).toBe(true);
  });

  it('T-U-23c equals an independent transliteration of ZF refresh_dkg_shares on the same dealings', async () => {
    const s = await dkgKeys('A');
    const coeffs = [101n, 202n, 303n];
    const { results } = await refreshSlot(s, refreshCtx(s), { rngs: coeffs });
    // ZF: signing_share = old + sum_l f_l(i) with f_l(x) = c_l * x; verifying_share = old_vs + sum_l F_l(i).
    for (const i of [1, 2, 3]) {
      const old = parseScalar(s.keys[i - 1]!.secret.signingShare);
      const expected = coeffs.reduce((acc, c) => Fn.add(acc, Fn.mul(c, BigInt(i))), old);
      expect(hex(results[i - 1]!.share.signingShare)).toBe(hex(scalarBytes(expected)));
      const vs = parsePoint(s.pub.verifyingShares[holderId(i)]!).add(
        mulBase(
          Fn.mul(
            coeffs.reduce((a, b) => a + b, 0n),
            BigInt(i),
          ),
        ),
      );
      expect(hex(results[0]!.pub.verifyingShares[holderId(i)]!)).toBe(hex(vs.toBytes()));
    }
  });

  it('a refresh among the two remaining holders keeps the key and drops the third verifying share', async () => {
    const s = await dkgKeys('LA');
    const { results } = await refreshSlot(s, refreshCtx(s, [1, 3]));
    expect(Object.keys(results[0]!.pub.verifyingShares)).toEqual([holderId(1), holderId(3)]);
    const msg = enc('two');
    expect(
      verifyEd25519Strict(
        frostSign(results[0]!.pub, [results[0]!.share, results[1]!.share], msg),
        msg,
        slotPubkey(s.pub),
      ),
    ).toBe(true);
  });
});

describe('P1.15-14 to 20 refresh rules', () => {
  it('P1.15-14 slotPolicy and the slot key equal their sealed values; the verifying shares change', async () => {
    const s = await dkgKeys('LB');
    const roles = s.ctx.holders.map((h) => h.role);
    const sealedPolicy = hex(slotPolicy('LB', roles));
    const ctx = refreshCtx(s);
    const { results } = await refreshSlot(s, ctx);
    expect(hex(slotPolicy('LB', roles))).toBe(sealedPolicy);
    expect(hex(slotPubkey(results[0]!.pub))).toBe(hex(slotPubkey(s.pub)));
    const statements = results.map((_, i) => deletionStatement(s.holders[i]!.signer, ctx, i + 1, results[0]!.pub));
    const ev = refreshedEvent(ctx, results[0]!.pub, statements);
    expect(ev.oldVerifyingShares).toEqual(s.pub.verifyingShares);
    expect(ev.newVerifyingShares).toEqual(results[0]!.pub.verifyingShares);
    for (const id of Object.keys(s.pub.verifyingShares)) {
      expect(hex(ev.newVerifyingShares[id]!)).not.toBe(hex(ev.oldVerifyingShares[id]!));
    }
  });

  it('P1.15-18 frost.refreshed is COMPLETE only with deletion statements from every remaining holder', async () => {
    const s = await dkgKeys('A');
    const ctx = refreshCtx(s);
    const { results } = await refreshSlot(s, ctx);
    const pub = results[0]!.pub;
    const st = s.holders.map((h, i) => deletionStatement(h.signer, ctx, i + 1, pub));
    const some = refreshedEvent(ctx, pub, st.slice(0, 2));
    expect([some.status, some.missing]).toEqual(['INCOMPLETE', [3]]);
    const outsider: Enrolled = enroll('outsider', 'recovery-agent');
    const forged = refreshedEvent(ctx, pub, [...st.slice(0, 2), deletionStatement(outsider.signer, ctx, 3, pub)]);
    expect(forged.status).toBe('INCOMPLETE');
    const stale = refreshedEvent(ctx, pub, [...st.slice(0, 2), deletionStatement(s.holders[2]!.signer, ctx, 3, s.pub)]);
    expect(stale.status).toBe('INCOMPLETE');
    expect(refreshedEvent(ctx, pub, st).status).toBe('COMPLETE');
    const otherKey = (await dkgKeys('A')).pub;
    expect(await code(() => refreshedEvent(ctx, otherKey, st))).toBe('REFRESH_INVALID');
  });

  it('P1.15-15 a threshold change or a non-zero constant term is refused', async () => {
    const s = await dkgKeys('A');
    const ctx = refreshCtx(s);
    const starts = [1, 2, 3].map((p) =>
      refreshStart(ctx, p, s.keys[p - 1]!.secret, { signer: s.holders[p - 1]!.signer, cipher: xwing }),
    );
    const m2 = starts[1]!.out[0]!;
    const resign = (fields: Uint8Array[]) => enrollmentSigned(s.holders[1]!.signer, { ...m2, fields });
    const threshold3 = resign([m2.fields[0]!, m2.fields[1]!, mulBase(5n).toBytes(), m2.fields[2]!]);
    expect(await code(() => refreshReceiveCommits(starts[0]!.state, [threshold3, starts[2]!.out[0]!]))).toBe(
      'REFRESH_INVALID',
    );
    const nonZero = resign([mulBase(9n).toBytes(), m2.fields[1]!, m2.fields[2]!]);
    expect(await code(() => refreshReceiveCommits(starts[0]!.state, [nonZero, starts[2]!.out[0]!]))).toBe(
      'REFRESH_INVALID',
    );
    const badPoint = resign([m2.fields[0]!, new Uint8Array(32), m2.fields[2]!]);
    expect(await code(() => refreshReceiveCommits(starts[0]!.state, [badPoint, starts[2]!.out[0]!]))).toBe(
      'REFRESH_INVALID',
    );
  });

  it('P1.15-16 a refresh message from an unauthenticated sender is refused', async () => {
    const s = await dkgKeys('A');
    const ctx = refreshCtx(s);
    const starts = [1, 2, 3].map((p) =>
      refreshStart(ctx, p, s.keys[p - 1]!.secret, { signer: s.holders[p - 1]!.signer, cipher: xwing }),
    );
    const intruder = enroll('intruder', 'recovery-agent');
    const fake = enrollmentSigned(intruder.signer, { ...starts[2]!.out[0]! });
    expect(await code(() => refreshReceiveCommits(starts[0]!.state, [starts[1]!.out[0]!, fake]))).toBe(
      'ENROLLMENT_SIG_INVALID',
    );
    // A sender outside the refresh participants is refused too.
    const ctx2 = refreshCtx(s, [1, 2]);
    const st = refreshStart(ctx2, 1, s.keys[0]!.secret, { signer: s.holders[0]!.signer, cipher: xwing });
    const from3 = enrollmentSigned(s.holders[2]!.signer, { ...starts[2]!.out[0]!, session: ctx2.sessionId });
    expect(await code(() => refreshReceiveCommits(st.state, [from3]))).toBe('INPUT_INVALID');
  });

  it("P1.15-19 a sub-share that fails its dealer's Feldman commitments names the dealer; no share is replaced", async () => {
    const s = await dkgKeys('A');
    const ctx = refreshCtx(s);
    const aad = (from: number, to: number) => tupleHash('legx/frost-refresh/v1', [ctx.sessionId, u32(from), u32(to)]);
    let err: FrostError | undefined;
    try {
      await refreshSlot(s, ctx, {
        tamper: async (m, states) => {
          if (m.from !== 2 || m.to !== 1) return m;
          const kemPub = states[1]!.dealings.get(1)!.kemPub;
          const ct = await xwing.seal(kemPub, aad(2, 1), scalarBytes(77n));
          return enrollmentSigned(s.holders[1]!.signer, { ...m, fields: [ct] });
        },
      });
    } catch (e) {
      err = e as FrostError;
    }
    expect([err?.code, err?.culprit]).toEqual(['SUBSHARE_INVALID', 2]);
    let err2: FrostError | undefined;
    try {
      await refreshSlot(s, ctx, {
        tamper: (m) =>
          m.from === 3 && m.to === 2 ? enrollmentSigned(s.holders[2]!.signer, { ...m, fields: [scalarBytes(1n)] }) : m,
      });
    } catch (e) {
      err2 = e as FrostError;
    }
    expect([err2?.code, err2?.culprit]).toEqual(['SUBSHARE_INVALID', 3]);
    // The old shares are untouched and still sign.
    expect(
      verifyEd25519Strict(
        frostSign(s.pub, [s.keys[0]!.secret, s.keys[1]!.secret], enc('x')),
        enc('x'),
        slotPubkey(s.pub),
      ),
    ).toBe(true);
  });

  it('P1.15-20 rotation plans; a refresh of a slot flagged stolen is ROTATION_REQUIRED', async () => {
    expect(rotationPlan('A', 'stolen')).toEqual(['new-dkg', 'signer-list-set-4-of-4', 'new-seal']);
    expect(rotationPlan('LB', 'stolen')).toEqual([
      'new-dkg',
      'signer-list-set-4-of-4',
      'new-seal',
      'new-contract-signatures',
      'new-nft',
    ]);
    expect(rotationPlan('B', 'lost')).toEqual(['repair', 'refresh']);
    const s = await dkgKeys('A');
    const ctx = { ...refreshCtx(s), stolen: true };
    expect(
      await code(() => refreshStart(ctx, 1, s.keys[0]!.secret, { signer: s.holders[0]!.signer, cipher: xwing })),
    ).toBe('ROTATION_REQUIRED');
  });

  it('refuses bad participants and a share that does not match', async () => {
    const s = await dkgKeys('A');
    const deps = { signer: s.holders[0]!.signer, cipher: xwing };
    const k = s.keys[0]!.secret;
    expect(await code(() => refreshStart(refreshCtx(s, [1]), 1, k, deps))).toBe('INPUT_INVALID');
    expect(await code(() => refreshStart(refreshCtx(s, [1, 1, 2]), 1, k, deps))).toBe('INPUT_INVALID');
    expect(await code(() => refreshStart(refreshCtx(s, [2, 3]), 1, k, deps))).toBe('INPUT_INVALID');
    expect(await code(() => refreshStart(refreshCtx(s, [1, 4]), 1, k, deps))).toBe('INPUT_INVALID');
    expect(await code(() => refreshStart(refreshCtx(s), 2, k, deps))).toBe('INPUT_INVALID');
    expect(await code(() => refreshStart(refreshCtx(s), 1, { ...k, signingShare: scalarBytes(3n) }, deps))).toBe(
      'SHARE_INVALID',
    );
  });
});

describe('T-U-30 repair', () => {
  it('T-U-30a two holders rebuild a share for a new device without the old share; it signs with any other holder', async () => {
    const s = await dkgKeys('A');
    const shares = s.keys.map((k) => k.secret);
    const lost = { ...shares[1]!, signingShare: new Uint8Array(32) }; // the old share is never an input
    const repaired = repairFinish(s.pub, 2, repairShare(s.pub, [1, 3], [shares[0]!, lost, shares[2]!], 2));
    expect(hex(repaired.signingShare)).toBe(hex(shares[1]!.signingShare));
    for (const other of [shares[0]!, shares[2]!]) {
      const sig = frostSign(s.pub, [repaired, other], enc('repaired'));
      expect(verifyEd25519Strict(sig, enc('repaired'), slotPubkey(s.pub))).toBe(true);
    }
  });

  it('T-U-30b a wrong repair contribution is detected and its helper named; no share is installed', async () => {
    const s = await dkgKeys('A');
    const shares = s.keys.map((k) => k.secret);
    const good = repairShare(s.pub, [1, 3], shares, 2);
    const named = async (c: typeof good) => {
      try {
        repairFinish(s.pub, 2, c);
      } catch (e) {
        return [(e as FrostError).code, (e as FrostError).culprit];
      }
      return ['NO_THROW'];
    };
    // Helper 3 sends a wrong sigma.
    expect(await named([good[0]!, { ...good[1]!, sigma: scalarBytes(5n) }])).toEqual([
      'REPAIR_CONTRIBUTION_INVALID',
      3,
    ]);
    // Helper 1 deals deltas that do not add up to its Lagrange-weighted share (consistent with its own commitments).
    const fake = new Map([...good[0]!.commitments].map(([k, v]) => [k, k === 1 ? mulBase(3n).toBytes() : v]));
    expect(await named([{ ...good[0]!, commitments: fake }, good[1]!])).toEqual(['REPAIR_CONTRIBUTION_INVALID', 1]);
    expect(await named([{ ...good[0]!, commitments: new Map([[1, good[0]!.commitments.get(1)!]]) }, good[1]!])).toEqual(
      ['REPAIR_CONTRIBUTION_INVALID', 1],
    );
    // A delta that does not match its sender's commitment is caught by the receiving helper.
    const d = repairDelta(s.pub, [1, 3], shares[0]!, 2);
    expect(await code(() => checkDelta(3, 1, scalarBytes(8n), d.commitments))).toBe('REPAIR_CONTRIBUTION_INVALID');
    expect(await code(() => checkDelta(2, 1, d.deltas.get(3)!, d.commitments))).toBe('REPAIR_CONTRIBUTION_INVALID');
    // A share for the wrong participant is never installed.
    const for3 = repairShare(s.pub, [1, 2], shares, 3);
    expect(
      await code(() =>
        repairFinish(
          {
            ...s.pub,
            verifyingShares: { ...s.pub.verifyingShares, [holderId(3)]: s.pub.verifyingShares[holderId(1)]! },
          },
          3,
          for3,
        ),
      ),
    ).toBe('REPAIR_FAILED');
  });

  it('refuses bad helper sets', async () => {
    const s = await dkgKeys('A');
    const k = s.keys[0]!.secret;
    expect(await code(() => repairDelta(s.pub, [1], k, 2))).toBe('INPUT_INVALID');
    expect(await code(() => repairDelta(s.pub, [1, 1], k, 2))).toBe('INPUT_INVALID');
    expect(await code(() => repairDelta(s.pub, [1, 2], k, 2))).toBe('INPUT_INVALID');
    expect(await code(() => repairDelta(s.pub, [1, 5], k, 2))).toBe('INPUT_INVALID');
    expect(await code(() => repairDelta(s.pub, [2, 3], k, 1))).toBe('INPUT_INVALID');
    expect(await code(() => repairDelta(s.pub, [1, 3], k, 0))).toBe('INPUT_INVALID');
  });

  it('a helper delta set always sums to zeta * share (repair identity, any participant)', () => {
    const dealt = ed25519_FROST.trustedDealer({ min: 2, max: 3 });
    const d = repairDelta(dealt.public, [2, 3], dealt.secretShares[holderId(2)]!, 1);
    const sum = [...d.deltas.values()].reduce((a, x) => Fn.add(a, parseScalar(x, true)), 0n);
    const zeta = Fn.div(Fn.create(1n - 3n), Fn.create(2n - 3n));
    expect(sum).toBe(Fn.mul(zeta, parseScalar(dealt.secretShares[holderId(2)]!.signingShare)));
    expect(vssEval([Point.BASE], 1n).equals(Point.BASE)).toBe(true);
  });
});
