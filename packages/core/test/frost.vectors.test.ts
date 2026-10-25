// T-U-21: RFC 9591 Appendix E.1 and the ZF frost-ed25519 3.0.0 vectors through our wrapper; T-U-30c: repair vectors.
import { readFileSync } from 'node:fs';
import { ed25519_FROST } from '@noble/curves/ed25519.js';
import { describe, expect, it, vi } from 'vitest';
import { tupleHash } from '../src/dealcore.ts';
import {
  aggregateChecked,
  type Commitment,
  enrollmentSigned,
  Fn,
  holderId,
  mulBase,
  parseScalar,
  SigningSession,
  type SlotPublic,
  scalarBytes,
  u32,
} from '../src/frost.ts';
import { dkgReceiveEcho, dkgReceiveRound1, dkgReceiveRound2, dkgStart } from '../src/frostDkg.ts';
import { repairDelta, repairSigma } from '../src/frostRepair.ts';
import { allow, chunkRng, enroll, hex, noPinCheck, ROLES, scalarRngBytes, unhex, xwing } from './helpers/frost.ts';

// DKG and X-Wing are slow when the whole suite runs in parallel.
vi.setConfig({ testTimeout: 60_000 });

const dir = new URL('../../../tools/frost-ref/vectors/', import.meta.url);
const json = (f: string) => JSON.parse(readFileSync(new URL(f, dir), 'utf8'));

/** Reads "key: hex" entries from RFC 9591 Appendix E.1, joining wrapped lines. */
function rfcE1(): Record<string, string> {
  const txt = readFileSync(new URL('rfc9591.txt', dir), 'utf8');
  const start = txt.lastIndexOf('E.1.  FROST(Ed25519, SHA-512)');
  const body = txt.slice(start, txt.indexOf('E.2.  FROST(', start));
  const out: Record<string, string> = {};
  let key = '';
  for (const raw of body.split('\n')) {
    const line = raw.trim();
    const m = /^([A-Za-z0-9_ [\]]+): ([0-9a-f,]+)$/.exec(line);
    if (m) {
      key = m[1] as string;
      out[key] = m[2] as string;
    } else if (key && /^[0-9a-f]+$/.test(line)) out[key] += line;
    else key = '';
  }
  return out;
}

type SignVector = {
  ids: number[];
  groupKey: string;
  shares: Record<number, string>;
  msg: string;
  rand: Record<number, [string, string]>;
  commitments: Record<number, [string, string]>;
  sigShares: Record<number, string>;
  sig: string;
  max: number;
};

function fromRfc(): SignVector {
  const v = rfcE1();
  const p = (i: number, k: string) => v[`P${i} ${k}`] as string;
  const ids = (v.participant_list as string).split(',').map(Number);
  return {
    ids,
    groupKey: v.group_public_key as string,
    shares: Object.fromEntries([1, 2, 3].map((i) => [i, p(i, 'participant_share')])),
    msg: v.message as string,
    rand: Object.fromEntries(ids.map((i) => [i, [p(i, 'hiding_nonce_randomness'), p(i, 'binding_nonce_randomness')]])),
    commitments: Object.fromEntries(
      ids.map((i) => [i, [p(i, 'hiding_nonce_commitment'), p(i, 'binding_nonce_commitment')]]),
    ),
    sigShares: Object.fromEntries(ids.map((i) => [i, p(i, 'sig_share')])),
    sig: v.sig as string,
    max: 3,
  };
}

function fromZf(file: string): SignVector {
  const v = json(file);
  const r1 = v.round_one_outputs.outputs as Record<string, string | number>[];
  const r2 = v.round_two_outputs.outputs as Record<string, string | number>[];
  const ids = v.inputs.participant_list as number[];
  // The big-identifier file keeps the share list of participants 1.., and the signers are 129, 256, 257:
  // their shares come from the polynomial, so derive them from the secret and coefficient.
  const a0 = parseScalar(unhex(v.inputs.group_secret_key));
  const a1 = parseScalar(unhex(v.inputs.share_polynomial_coefficients[0]));
  const share = (i: number) => hex(scalarBytes(Fn.add(a0, Fn.mul(a1, BigInt(i)))));
  return {
    ids,
    groupKey: v.inputs.verifying_key_key,
    shares: Object.fromEntries(ids.map((i) => [i, share(i)])),
    msg: v.inputs.message,
    rand: Object.fromEntries(r1.map((o) => [o.identifier, [o.hiding_nonce_randomness, o.binding_nonce_randomness]])),
    commitments: Object.fromEntries(
      r1.map((o) => [o.identifier, [o.hiding_nonce_commitment, o.binding_nonce_commitment]]),
    ),
    sigShares: Object.fromEntries(r2.map((o) => [o.identifier, o.sig_share])),
    sig: v.final_output.sig,
    max: Number(v.config.MAX_PARTICIPANTS),
  };
}

function runSignVector(v: SignVector) {
  const pub: SlotPublic = {
    signers: { min: 2, max: v.max },
    commitments: [unhex(v.groupKey)],
    verifyingShares: Object.fromEntries(
      Object.entries(v.shares).map(([i, s]) => [holderId(Number(i)), mulBase(parseScalar(unhex(s))).toBytes()]),
    ),
  };
  const msg = unhex(v.msg);
  const sessions = v.ids.map((i) => {
    const [h, b] = v.rand[i] as [string, string];
    const share = { identifier: holderId(i), signingShare: unhex(v.shares[i] as string) };
    return SigningSession.open(share, pub, msg, chunkRng([unhex(h), unhex(b)]));
  });
  const list: Commitment[] = sessions.map((s) => s.commitment);
  v.ids.forEach((i, k) => {
    expect(hex(list[k]!.hiding)).toBe(v.commitments[i]![0]);
    expect(hex(list[k]!.binding)).toBe(v.commitments[i]![1]);
  });
  const shares = Object.fromEntries(v.ids.map((i, k) => [holderId(i), sessions[k]!.signShare(msg, list, allow)]));
  for (const i of v.ids) expect(hex(shares[holderId(i)]!)).toBe(v.sigShares[i]);
  expect(hex(aggregateChecked(pub, list, msg, shares))).toBe(v.sig);
}

describe('T-U-21 FROST vectors', () => {
  it('T-U-21a RFC 9591 Appendix E.1: shares, commitments, signature shares and signature', () => {
    const v = fromRfc();
    // The key shares follow from the group secret and coefficient (RFC 9591 Appendix C).
    const e1 = rfcE1();
    const a0 = parseScalar(unhex(e1.group_secret_key as string));
    const a1 = parseScalar(unhex(e1['share_polynomial_coefficients[1]'] as string));
    for (const i of [1, 2, 3]) expect(hex(scalarBytes(Fn.add(a0, Fn.mul(a1, BigInt(i)))))).toBe(v.shares[i]);
    expect(hex(mulBase(a0).toBytes())).toBe(v.groupKey);
    runSignVector(v);
  });

  it('T-U-21b ZF vectors.json (participants 1 and 3)', () => runSignVector(fromZf('zf-vectors.json')));
  it('T-U-21b ZF vectors-big-identifier.json (participants 129, 256, 257 of 257)', () =>
    runSignVector(fromZf('zf-vectors-big-identifier.json')));

  it('T-U-21c ZF vectors_dkg.json through our DKG round functions (injected randomness for holder 1)', async () => {
    const v = json('zf-vectors_dkg.json').inputs;
    const holders = ROLES.client.map((r) => enroll(`A/${r}`, r));
    const ctx = { sessionId: new Uint8Array(32).fill(9), slot: 'A' as const, holders: holders.map((h) => h.key) };
    const kems = [1, 2, 3].map(() => xwing.keygen());
    let k = 0;
    const cipher = { ...xwing, keygen: () => kems[k++]! };
    // Holder 1 is ours: its polynomial (a0, a1) comes from the vector; the proof-of-knowledge nonce is ours.
    const rng = chunkRng([
      scalarRngBytes(parseScalar(unhex(v['1'].signing_key))),
      scalarRngBytes(parseScalar(unhex(v['1'].coefficient))),
      scalarRngBytes(12345n),
    ]);
    const me = dkgStart(ctx, 1, { signer: holders[0]!.signer, cipher, pinned: noPinCheck, rng });
    expect(me.out[0]!.fields.slice(0, 2).map(hex)).toEqual(v['1'].vss_commitments);
    // Holders 2 and 3 replay the vector's round-1 packages (including their proofs of knowledge).
    const r1 = [2, 3].map((i) =>
      enrollmentSigned(holders[i - 1]!.signer, {
        session: ctx.sessionId,
        kind: 'dkg-r1',
        from: i,
        to: 0,
        fields: [...v[i].vss_commitments.map(unhex), unhex(v[i].proof_of_knowledge), kems[i - 1]!.publicKey],
      }),
    );
    const echo = dkgReceiveRound1(me.state, r1).out[0]!;
    const echoes = [2, 3].map((i) =>
      enrollmentSigned(holders[i - 1]!.signer, { ...echo, from: i, fields: echo.fields }),
    );
    const sent = await dkgReceiveEcho(me.state, echoes);
    // Our shares to 2 and 3 equal what the vector says they received from 1.
    for (const m of sent.out) {
      const pt = await xwing.open(kems[m.to - 1]!.secretKey, aadFor(ctx.sessionId, 1, m.to), m.fields[0]!);
      expect(hex(pt)).toBe(v[m.to].signing_shares['1']);
    }
    const r2 = await Promise.all(
      [2, 3].map(async (i) => {
        const ct = await xwing.seal(kems[0]!.publicKey, aadFor(ctx.sessionId, i, 1), unhex(v['1'].signing_shares[i]));
        return enrollmentSigned(holders[i - 1]!.signer, {
          session: ctx.sessionId,
          kind: 'dkg-r2',
          from: i,
          to: 1,
          fields: [ct],
        });
      }),
    );
    const { key } = await dkgReceiveRound2(me.state, r2);
    expect(hex(key!.secret.signingShare)).toBe(v['1'].signing_share);
    expect(hex(key!.public.commitments[0]!)).toBe(v.verifying_key);
    for (const i of [1, 2, 3]) expect(hex(key!.public.verifyingShares[holderId(i)]!)).toBe(v[i].verifying_share);
  });
});

const aadFor = (session: Uint8Array, from: number, to: number) =>
  tupleHash('legx/frost-dkg-r2/v1', [session, u32(from), u32(to)]);

describe('T-U-30c ZF repair-share.json', () => {
  const v = json('zf-repair-share.json');
  it('part 2: a helper sums the deltas it received', () => {
    const s = v.scalar_generation;
    const sigma = repairSigma([s.random_scalar_1, s.random_scalar_2, s.random_scalar_3].map(unhex));
    expect(hex(sigma)).toBe(s.random_scalar_sum);
  });
  it('part 3: the new holder sums the sigmas', () => {
    const s = v.sigma_generation;
    const share = repairSigma([s.sigma_1, s.sigma_2, s.sigma_3, s.sigma_4].map(unhex));
    expect(hex(share)).toBe(s.sigma_sum);
  });
  it('part 1: the deltas of one helper sum to its Lagrange-weighted share (ZF check_repair_share_part1)', () => {
    const dealt = ed25519_FROST.trustedDealer({ min: 3, max: 5 });
    const helpers = [1, 4, 5];
    const share = dealt.secretShares[holderId(4)]!;
    const { deltas } = repairDelta(dealt.public, helpers, share, 2);
    const sum = [...deltas.values()].reduce((a, d) => Fn.add(a, parseScalar(d, true)), 0n);
    // lambda_4 evaluated at x = 2 over {1, 4, 5}: (2-1)(2-5) / ((4-1)(4-5))
    const lambda = Fn.div(Fn.mul(Fn.create(1n), Fn.create(-3n)), Fn.mul(3n, Fn.create(-1n)));
    expect(sum).toBe(Fn.mul(lambda, parseScalar(share.signingShare)));
  });
});
