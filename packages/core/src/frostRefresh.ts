// Share refresh (DESIGN 6.4 "Refresh and repair"): every participant deals a random polynomial with a zero
// constant term, sends each other participant its sub-share (X-Wing HPKE, enrollment-signed), and every
// receiver checks each sub-share against the dealer's Feldman commitments before adding it to its share.
// The group key, and so the ledger, the seal and slotPolicy, stay the same; the verifying shares change.
//
// A REFRESH IS HYGIENE, NOT REVOCATION. Old shares still combine with each other, and nobody can prove a
// deletion. A refresh counts as done only when every remaining holder has signed a deletion statement
// (`refreshedEvent`). A share known to be stolen needs rotation on the ledger (`rotationPlan`), not a refresh.
//
// This follows ZF frost-core 3.0.0 `keys/refresh.rs` (refresh_dkg_part1/part2/shares), which cannot change
// the threshold and leaves sender authentication to the caller (its part 2 skips the proof-of-knowledge
// check, so we authenticate every message with the sender's enrollment key). Written by us, unaudited.
// Source: https://github.com/ZcashFoundation/frost/blob/frost-ed25519/v3.0.0/frost-core/src/keys/refresh.rs
// Source: https://frost.zfnd.org/tutorial/refreshing-shares.html
// Source: https://doi.org/10.1007/3-540-44750-4_27 (Herzberg, Jarecki, Krawczyk, Yung: proactive secret sharing)
// Source: https://doi.org/10.1109/SFCS.1987.4 (Feldman VSS)
import { ed25519_FROST } from '@noble/curves/ed25519.js';
import { equalBytes } from '@noble/curves/utils.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { tupleHash } from './dealcore.ts';
import {
  type EnrollmentSigner,
  enrollmentSigned,
  Fn,
  FrostError,
  type FrostMsg,
  holderId,
  idScalar,
  type KeyShare,
  mulBase,
  onePerHolder,
  openEnrollmentMessage,
  Point,
  parsePoint,
  parseScalar,
  type Rng,
  type SlotPublic,
  scalarBytes,
  u32,
  vssEval,
} from './frost.ts';
import type { DkgContext, ShareCipher } from './frostDkg.ts';

/** `participants` are the remaining holders (at least the threshold); `stolen` marks a slot that needs rotation. */
export type RefreshContext = DkgContext & { pub: SlotPublic; participants: readonly number[]; stolen?: boolean };
type Dealing = { commitment: ReturnType<typeof parsePoint>[]; kemPub: Uint8Array };
export type RefreshState = {
  readonly ctx: RefreshContext;
  readonly me: number;
  readonly share: KeyShare;
  readonly signer: EnrollmentSigner;
  readonly cipher: ShareCipher;
  readonly coeffs: bigint[];
  readonly kemSecret: Uint8Array;
  readonly dealings: Map<number, Dealing>;
};

const IDENTITY = Point.ZERO.toBytes();
const aad = (ctx: RefreshContext, from: number, to: number): Uint8Array =>
  tupleHash('legx/frost-refresh/v1', [ctx.sessionId, u32(from), u32(to)]);
const evalPoly = (coeffs: readonly bigint[], x: bigint): bigint =>
  coeffs.reduceRight((acc, c) => Fn.add(Fn.mul(acc, x), c), 0n);

/** Step 1: deal a polynomial with f(0) = 0 and broadcast its commitments (the first is the identity). */
export function refreshStart(
  ctx: RefreshContext,
  me: number,
  share: KeyShare,
  deps: { signer: EnrollmentSigner; cipher: ShareCipher; rng?: Rng },
): { state: RefreshState; out: FrostMsg[] } {
  if (ctx.stolen) throw new FrostError('ROTATION_REQUIRED', 'a stolen share needs a new key on the ledger');
  const { pub, participants } = ctx;
  if (
    new Set(participants).size !== participants.length ||
    participants.length < pub.signers.min ||
    !participants.every((p) => holderId(p) in pub.verifyingShares) ||
    !participants.includes(me) ||
    share.identifier !== holderId(me)
  ) {
    throw new FrostError('INPUT_INVALID', 'participants');
  }
  if (
    !mulBase(parseScalar(share.signingShare)).equals(parsePoint(pub.verifyingShares[share.identifier] as Uint8Array))
  ) {
    throw new FrostError('SHARE_INVALID', 'share does not match its verifying share');
  }
  const coeffs = [0n];
  for (let k = 1; k < pub.signers.min; k++) coeffs.push(Fn.fromBytes(ed25519_FROST.utils.randomScalar(deps.rng)));
  const commitment = coeffs.map((c) => mulBase(c));
  const kem = deps.cipher.keygen();
  const state: RefreshState = {
    ctx,
    me,
    share,
    signer: deps.signer,
    cipher: deps.cipher,
    coeffs,
    kemSecret: kem.secretKey,
    dealings: new Map([[me, { commitment, kemPub: kem.publicKey }]]),
  };
  const out = enrollmentSigned(deps.signer, {
    session: ctx.sessionId,
    kind: 'refresh-commit',
    from: me,
    to: 0,
    fields: [...commitment.map((p) => p.toBytes()), kem.publicKey],
  });
  return { state, out: [out] };
}

/** Step 2: authenticate every dealing, refuse a threshold change or a non-zero constant term, then send sub-shares. */
export async function refreshReceiveCommits(
  state: RefreshState,
  msgs: readonly FrostMsg[],
): Promise<{ state: RefreshState; out: FrostMsg[] }> {
  const { ctx, me } = state;
  const t = ctx.pub.signers.min;
  const opened = msgs.map((m) => openEnrollmentMessage(ctx, m, 'refresh-commit', me));
  for (const m of onePerHolder(ctx, me, opened, ctx.participants)) {
    if (m.fields.length !== t + 1 || !equalBytes(m.fields[0] as Uint8Array, IDENTITY)) {
      throw new FrostError('REFRESH_INVALID', 'threshold change or non-zero constant term', m.from);
    }
    let commitment: Dealing['commitment'];
    try {
      commitment = [Point.ZERO, ...m.fields.slice(1, t).map((c) => parsePoint(c))];
    } catch {
      throw new FrostError('REFRESH_INVALID', 'commitment', m.from);
    }
    state.dealings.set(m.from, { commitment, kemPub: m.fields[t] as Uint8Array });
  }
  const out: FrostMsg[] = [];
  for (const j of ctx.participants) {
    if (j === me) continue;
    const sub = scalarBytes(evalPoly(state.coeffs, BigInt(j)));
    const ct = await state.cipher.seal((state.dealings.get(j) as Dealing).kemPub, aad(ctx, me, j), sub);
    out.push(
      enrollmentSigned(state.signer, { session: ctx.sessionId, kind: 'refresh-share', from: me, to: j, fields: [ct] }),
    );
  }
  return { state, out };
}

/**
 * Step 3: check every sub-share against its dealer's Feldman commitments (naming a bad dealer, and replacing
 * no share then), and return the new share and the new public data. The group key does not change.
 */
export async function refreshReceiveShares(
  state: RefreshState,
  msgs: readonly FrostMsg[],
): Promise<{ share: KeyShare; pub: SlotPublic }> {
  const { ctx, me } = state;
  const x = idScalar(holderId(me));
  let sum = evalPoly(state.coeffs, x);
  const opened = msgs.map((m) => openEnrollmentMessage(ctx, m, 'refresh-share', me));
  for (const m of onePerHolder(ctx, me, opened, ctx.participants)) {
    const dealing = state.dealings.get(m.from) as Dealing;
    let sub: bigint;
    try {
      sub = parseScalar(
        await state.cipher.open(state.kemSecret, aad(ctx, m.from, me), m.fields[0] as Uint8Array),
        true,
      );
    } catch {
      throw new FrostError('SUBSHARE_INVALID', `dealer ${m.from}`, m.from);
    }
    if (!mulBase(sub).equals(vssEval(dealing.commitment, x)))
      throw new FrostError('SUBSHARE_INVALID', `dealer ${m.from}`, m.from);
    sum = Fn.add(sum, sub);
  }
  state.coeffs.fill(0n);
  const dealings = [...state.dealings.values()];
  const commitments = ctx.pub.commitments.map((c, k) =>
    dealings.reduce((acc, d) => acc.add(d.commitment[k] as ReturnType<typeof parsePoint>), parsePoint(c)).toBytes(),
  );
  const verifyingShares = Object.fromEntries(
    ctx.participants.map((p) => {
      const id = holderId(p);
      const delta = dealings.reduce((acc, d) => acc.add(vssEval(d.commitment, idScalar(id))), Point.ZERO);
      return [
        id,
        parsePoint(ctx.pub.verifyingShares[id] as Uint8Array)
          .add(delta)
          .toBytes(),
      ];
    }),
  );
  // The new share matches its new verifying share: the old one did (refreshStart) and every sub-share passed Feldman.
  return {
    share: { identifier: holderId(me), signingShare: scalarBytes(Fn.add(parseScalar(state.share.signingShare), sum)) },
    pub: { signers: { ...ctx.pub.signers }, commitments, verifyingShares },
  };
}

/** Hash of a verifying-share set (sorted by identifier), as named in deletion statements. */
function verifyingSharesHash(pub: SlotPublic): Uint8Array {
  const ids = Object.keys(pub.verifyingShares).sort((a, b) => (idScalar(a) < idScalar(b) ? -1 : 1));
  return tupleHash(
    'legx/frost-verifying-shares/v1',
    ids.flatMap((id) => [utf8ToBytes(id), pub.verifyingShares[id] as Uint8Array]),
  );
}

/** A holder's signed statement that it deleted its old share after the refresh from `oldPub` to `newPub`. */
export const deletionStatement = (
  signer: EnrollmentSigner,
  ctx: RefreshContext,
  me: number,
  newPub: SlotPublic,
): FrostMsg =>
  enrollmentSigned(signer, {
    session: ctx.sessionId,
    kind: 'refresh-deleted',
    from: me,
    to: 0,
    fields: [verifyingSharesHash(ctx.pub), verifyingSharesHash(newPub)],
  });

export type FrostRefreshed = {
  kind: 'frost.refreshed';
  status: 'COMPLETE' | 'INCOMPLETE';
  missing: number[];
  oldVerifyingShares: Record<string, Uint8Array>;
  newVerifyingShares: Record<string, Uint8Array>;
  statements: FrostMsg[];
};

/**
 * The `frost.refreshed` event. COMPLETE only when every remaining holder signed a deletion statement with its
 * pinned enrollment key over these exact old and new verifying shares; a statement by any other key is ignored.
 */
export function refreshedEvent(
  ctx: RefreshContext,
  newPub: SlotPublic,
  statements: readonly FrostMsg[],
): FrostRefreshed {
  if (!equalBytes(newPub.commitments[0] as Uint8Array, ctx.pub.commitments[0] as Uint8Array)) {
    throw new FrostError('REFRESH_INVALID', 'group key changed');
  }
  const oldHash = verifyingSharesHash(ctx.pub);
  const newHash = verifyingSharesHash(newPub);
  const valid = statements.filter((s) => {
    try {
      openEnrollmentMessage(ctx, s, 'refresh-deleted', 0);
    } catch {
      return false;
    }
    return equalBytes(s.fields[0] as Uint8Array, oldHash) && equalBytes(s.fields[1] as Uint8Array, newHash);
  });
  const signed = new Set(valid.map((s) => s.from));
  const missing = ctx.participants.filter((p) => !signed.has(p));
  return {
    kind: 'frost.refreshed',
    status: missing.length === 0 ? 'COMPLETE' : 'INCOMPLETE',
    missing,
    oldVerifyingShares: ctx.pub.verifyingShares,
    newVerifyingShares: newPub.verifyingShares,
    statements: valid,
  };
}
