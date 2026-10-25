// Share repair (DESIGN 6.4 "Refresh and repair"): t helpers rebuild a lost share for a new device without the
// old share and without ever reconstructing the group secret. This is ZF frost-core's `repairable` module
// (Laing and Stinson's enrollment repairable threshold scheme) on noble primitives, with one addition so the
// new holder can name a cheating helper: each helper publishes commitments D_ij = delta_ij * G to its deltas.
//   helper i:  deltas delta_ij (j in helpers) with sum_j delta_ij = zeta_i * s_i, zeta_i = Lagrange at x = r
//   helper j:  checks delta_ij * G == D_ij, sends sigma_j = sum_i delta_ij to the new holder
//   new holder: checks sum_j D_ij == zeta_i * Y_i and sigma_j * G == sum_i D_ij, then s_r = sum_j sigma_j,
//               and s_r * G must equal its verifying share Y_r.
// The deltas and sigmas are secret and travel encrypted and enrollment-signed (the relay, task 3.9).
// Written by us and unaudited (DESIGN 6.4 "Risks"); ZF added `repairable` after its NCC audit.
// Source: https://github.com/ZcashFoundation/frost/blob/frost-ed25519/v3.0.0/frost-core/src/keys/repairable.rs
// Source: https://eprint.iacr.org/2017/1155 (Laing and Stinson, "A survey and refinement of repairable threshold schemes")
import { ed25519_FROST } from '@noble/curves/ed25519.js';
import {
  Fn,
  FrostError,
  holderId,
  idScalar,
  type KeyShare,
  mulBase,
  Point,
  parsePoint,
  parseScalar,
  type Rng,
  type SlotPublic,
  scalarBytes,
} from './frost.ts';

/** zeta_i: the Lagrange coefficient of helper i over the helper set, evaluated at the participant's x. */
function zeta(helpers: readonly number[], i: number, x: number): bigint {
  let num = 1n;
  let den = 1n;
  for (const j of helpers) {
    if (j === i) continue;
    num = Fn.mul(num, Fn.create(BigInt(x - j)));
    den = Fn.mul(den, Fn.create(BigInt(i - j)));
  }
  return Fn.div(num, den);
}

function checkHelpers(pub: SlotPublic, helpers: readonly number[], participant: number): void {
  const set = new Set(helpers);
  if (set.size !== helpers.length || helpers.length < pub.signers.min || set.has(participant) || participant < 1) {
    throw new FrostError('INPUT_INVALID', 'helpers');
  }
  if (!helpers.every((h) => holderId(h) in pub.verifyingShares))
    throw new FrostError('INPUT_INVALID', 'unknown helper');
}

/** Step 1 (helper): split zeta_i * s_i into one delta per helper, and commit to each delta. */
export function repairDelta(
  pub: SlotPublic,
  helpers: readonly number[],
  share: KeyShare,
  participant: number,
  rng?: Rng,
): { deltas: Map<number, Uint8Array>; commitments: Map<number, Uint8Array> } {
  const me = Number(idScalar(share.identifier));
  checkHelpers(pub, helpers, participant);
  if (!helpers.includes(me)) throw new FrostError('INPUT_INVALID', 'not a helper');
  const sorted = [...helpers].sort((a, b) => a - b);
  const random = sorted.slice(0, -1).map(() => Fn.fromBytes(ed25519_FROST.utils.randomScalar(rng)));
  const last = Fn.sub(
    Fn.mul(zeta(sorted, me, participant), parseScalar(share.signingShare)),
    random.reduce((a, b) => Fn.add(a, b), 0n),
  );
  const values = [...random, last];
  const deltas = new Map(sorted.map((h, k) => [h, scalarBytes(values[k] as bigint)]));
  const commitments = new Map(sorted.map((h, k) => [h, mulBase(values[k] as bigint).toBytes()]));
  return { deltas, commitments };
}

/** Step 2 (helper `me`): check a received delta against its sender's published commitment. */
export function checkDelta(
  me: number,
  from: number,
  delta: Uint8Array,
  commitments: ReadonlyMap<number, Uint8Array>,
): void {
  const d = commitments.get(me);
  if (!d || !mulBase(parseScalar(delta, true)).equals(parsePoint(d, true))) {
    throw new FrostError('REPAIR_CONTRIBUTION_INVALID', `helper ${from}`, from);
  }
}

/** Steps 2 and 3: a sum of scalars (sigma_j from deltas; the new share from sigmas). */
export const repairSigma = (values: readonly Uint8Array[]): Uint8Array =>
  scalarBytes(values.reduce((acc, v) => Fn.add(acc, parseScalar(v, true)), 0n));

/**
 * Step 3 (new holder): check every helper's commitments and sigma, then install the share only if it matches
 * the participant's verifying share. Names the helper whose contribution is wrong.
 */
export function repairFinish(
  pub: SlotPublic,
  participant: number,
  contributions: readonly { from: number; sigma: Uint8Array; commitments: ReadonlyMap<number, Uint8Array> }[],
): KeyShare {
  const helpers = contributions.map((c) => c.from);
  checkHelpers(pub, helpers, participant);
  for (const { from, commitments } of contributions) {
    const parts = helpers.map((j) => commitments.get(j));
    const yi = parsePoint(pub.verifyingShares[holderId(from)] as Uint8Array);
    if (
      commitments.size !== helpers.length ||
      parts.some((p) => !p) ||
      !parts
        .reduce((acc, p) => acc.add(parsePoint(p as Uint8Array, true)), Point.ZERO)
        .equals(yi.multiplyUnsafe(zeta(helpers, from, participant)))
    ) {
      throw new FrostError('REPAIR_CONTRIBUTION_INVALID', `helper ${from}`, from);
    }
  }
  for (const { from: j, sigma } of contributions) {
    const expected = contributions.reduce(
      (acc, c) => acc.add(parsePoint(c.commitments.get(j) as Uint8Array, true)),
      Point.ZERO,
    );
    if (!mulBase(parseScalar(sigma, true)).equals(expected)) {
      throw new FrostError('REPAIR_CONTRIBUTION_INVALID', `helper ${j}`, j);
    }
  }
  const share = repairSigma(contributions.map((c) => c.sigma));
  const target = pub.verifyingShares[holderId(participant)];
  if (!target || !mulBase(parseScalar(share)).equals(parsePoint(target))) throw new FrostError('REPAIR_FAILED');
  return { identifier: holderId(participant), signingShare: share };
}
