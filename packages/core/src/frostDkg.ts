// Distributed key generation for one slot (DESIGN 6.4 "Key generation rules"), as pure round functions:
// (state, incoming messages) -> (state, outgoing messages). The relay (task 3.9) and the browser
// (task 4.7) only move messages.
//
// Protocol: Pedersen DKG with Schnorr proofs of knowledge as in FROST (Komlo and Goldberg, figure 1),
// over noble's DKG.round1/2/3, plus what noble leaves to the caller:
//  - every message is signed by the sender's pinned enrollment key (DESIGN 6.3);
//  - round 1 is an echo broadcast: every holder signs the hash of the full round-1 transcript and aborts
//    if any other holder saw a different one (a broadcast channel is required for DKG security);
//  - round-2 shares travel as X-Wing HPKE ciphertexts to a per-session KEM key each holder publishes
//    in its signed round-1 message;
//  - a holder whose share fails the Feldman check publishes a signed complaint that carries the
//    ciphertext and reveals its per-session KEM secret, so anyone can decrypt and see who cheated
//    (cf. the complaint phase of GJKR's DKG);
//  - before the slot enters the seal, all three pairs test-sign a fixed message.
// Source: https://eprint.iacr.org/2020/852 (FROST, section 5.1 and figure 1)
// Source: https://frost.zfnd.org/tutorial/dkg.html (broadcast channel; authenticated, confidential round 2)
// Source: https://doi.org/10.1007/s00145-006-0347-3 (Gennaro, Jarecki, Krawczyk, Rabin: complaints)
// Source: https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/
import { ed25519_FROST } from '@noble/curves/ed25519.js';
import { equalBytes } from '@noble/curves/utils.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { tupleHash } from './dealcore.ts';
import {
  type CheckResult,
  type Commitment,
  canonicalRoles,
  type Directory,
  type EnrollmentSigner,
  enrollmentSigned,
  Fn,
  FrostError,
  type FrostMsg,
  frostMsgBytes,
  type HolderKey,
  holderId,
  idScalar,
  isSingleDeviceMode,
  type KeyShare,
  mulBase,
  onePerHolder,
  openEnrollmentMessage,
  parsePoint,
  parseScalar,
  type Rng,
  type SlotName,
  type SlotPublic,
  scalarBytes,
  slotPolicy,
  slotPubkey,
  THRESHOLD,
  u32,
  verifyEd25519Strict,
  vssEval,
} from './frost.ts';

/** HPKE for share transport (X-Wing, DESIGN 6.13). Task 1.16 supplies the real one; `suite` is stored with each package. */
export type ShareCipher = {
  suite: string;
  keygen(): { publicKey: Uint8Array; secretKey: Uint8Array };
  publicKeyOf(secretKey: Uint8Array): Uint8Array;
  seal(publicKey: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
  open(secretKey: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
};
/** Checks that every holder's enrollment key is the pinned one (frostSetup's registry implements it). */
export type PinCheck = (dir: Directory) => void;

export type DkgContext = Directory & { slot: SlotName };
export type DkgDeps = { signer: EnrollmentSigner; cipher: ShareCipher; pinned: PinCheck; rng?: Rng };
type Round1 = { commitment: Uint8Array[]; pok: Uint8Array; kemPub: Uint8Array };
type NobleSecret = ReturnType<typeof ed25519_FROST.DKG.round1>['secret'];
export type DkgState = {
  readonly ctx: DkgContext;
  readonly me: number;
  readonly cipher: ShareCipher;
  readonly signer: EnrollmentSigner;
  readonly secret: NobleSecret;
  readonly kemSecret: Uint8Array;
  readonly round1: Map<number, Round1>;
  transcript?: Uint8Array;
};
export type DkgKey = { public: SlotPublic; secret: KeyShare };

/**
 * noble refuses to advance one DKG secret twice ("round2 package used in round3"); a replayed message on a state
 * that already advanced gets a typed FrostError, never a plain Error (I-25).
 */
function noble<T>(step: () => T): T {
  try {
    return step();
  } catch (e) {
    throw new FrostError('INPUT_INVALID', `DKG step refused: ${(e as Error).message}`);
  }
}

/** Who the slot's holders are, in canonical role order; distinct devices unless single-device mode (P1.15-21). */
export function checkContext(ctx: DkgContext): void {
  const roles = ctx.holders.map((h) => h.role);
  if (canonicalRoles(ctx.slot, roles).join(',') !== roles.join(',')) {
    throw new FrostError('ROLE_INVALID', 'holders not in canonical role order');
  }
  if (ctx.sessionId.length !== 32) throw new FrostError('INPUT_INVALID', 'session id');
  if (new Set(ctx.holders.map((h) => h.deviceId)).size !== roles.length && !isSingleDeviceMode(roles)) {
    throw new FrostError('SAME_DEVICE_SHARES');
  }
  if (new Set(ctx.holders.map((h) => h.edPub.join())).size !== roles.length) {
    throw new FrostError('INPUT_INVALID', 'duplicate enrollment key');
  }
}

const r2Aad = (ctx: DkgContext, from: number, to: number): Uint8Array =>
  tupleHash('legx/frost-dkg-r2/v1', [ctx.sessionId, u32(from), u32(to)]);

/** Round 1: commit to a fresh random polynomial and prove knowledge of its constant term. */
export function dkgStart(ctx: DkgContext, me: number, deps: DkgDeps): { state: DkgState; out: FrostMsg[] } {
  checkContext(ctx);
  deps.pinned(ctx);
  if (!ctx.holders[me - 1]) throw new FrostError('INPUT_INVALID', 'me');
  const r1 = ed25519_FROST.DKG.round1(holderId(me), THRESHOLD, undefined, deps.rng);
  const kem = deps.cipher.keygen();
  const own: Round1 = { commitment: r1.public.commitment, pok: r1.public.proofOfKnowledge, kemPub: kem.publicKey };
  const state: DkgState = {
    ctx,
    me,
    cipher: deps.cipher,
    signer: deps.signer,
    secret: r1.secret,
    kemSecret: kem.secretKey,
    round1: new Map([[me, own]]),
  };
  const out = enrollmentSigned(deps.signer, {
    session: ctx.sessionId,
    kind: 'dkg-r1',
    from: me,
    to: 0,
    fields: [...own.commitment, own.pok, own.kemPub],
  });
  return { state, out: [out] };
}

/** FROST proof of knowledge check: R == mu*G - c*phi with c = H_dkg(id || phi || R).
 * Source: https://github.com/ZcashFoundation/frost/blob/frost-ed25519/v3.0.0/frost-core/src/keys/dkg.rs */
function checkPok(from: number, r1: Round1): void {
  try {
    const phi = parsePoint(r1.commitment[0] as Uint8Array);
    const R = parsePoint(r1.pok.subarray(0, 32));
    const mu = parseScalar(r1.pok.subarray(32), true);
    const pre = concatBytes(
      utf8ToBytes('FROST-ED25519-SHA512-v1dkg'),
      scalarBytes(idScalar(holderId(from))),
      r1.commitment[0] as Uint8Array,
      r1.pok.subarray(0, 32),
    );
    const c = Fn.create(bytesToNumberLE(sha512(pre)));
    if (r1.pok.length !== 64 || !R.equals(mulBase(mu).subtract(phi.multiplyUnsafe(c)))) throw new Error('pok');
  } catch {
    throw new FrostError('POK_INVALID', `holder ${from}`, from);
  }
}

function bytesToNumberLE(b: Uint8Array): bigint {
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i] as number);
  return n;
}

function parseRound1(m: FrostMsg): Round1 {
  if (m.fields.length !== THRESHOLD.min + 2) throw new FrostError('INPUT_INVALID', 'round 1 fields', m.from);
  const commitment = m.fields.slice(0, THRESHOLD.min);
  try {
    for (const c of commitment) parsePoint(c);
  } catch {
    throw new FrostError('INPUT_INVALID', 'round 1 commitment', m.from);
  }
  return { commitment, pok: m.fields[THRESHOLD.min] as Uint8Array, kemPub: m.fields[THRESHOLD.min + 1] as Uint8Array };
}

/** The hash every holder signs after round 1: session, slot policy, and each holder's key and round-1 message. */
export function transcriptHash(ctx: DkgContext, round1: ReadonlyMap<number, Round1>): Uint8Array {
  const parts: Uint8Array[] = [
    ctx.sessionId,
    slotPolicy(
      ctx.slot,
      ctx.holders.map((h) => h.role),
    ),
  ];
  ctx.holders.forEach((h, i) => {
    const r = round1.get(i + 1) as Round1;
    parts.push(h.edPub, ...r.commitment, r.pok, r.kemPub);
  });
  return tupleHash('legx/frost-dkg-transcript/v1', parts);
}

/** Authenticates and checks all round-1 messages (naming a bad proof of knowledge) and returns them by holder. */
export function readRound1(ctx: DkgContext, me: number, msgs: readonly FrostMsg[]): Map<number, Round1> {
  const out = new Map<number, Round1>();
  for (const m of onePerHolder(
    ctx,
    me,
    msgs.map((x) => openEnrollmentMessage(ctx, x, 'dkg-r1', me)),
  )) {
    const r1 = parseRound1(m);
    checkPok(m.from, r1);
    out.set(m.from, r1);
  }
  return out;
}

/** After round 1: check every message, then sign the transcript hash (the echo). */
export function dkgReceiveRound1(state: DkgState, msgs: readonly FrostMsg[]): { state: DkgState; out: FrostMsg[] } {
  for (const [from, r1] of readRound1(state.ctx, state.me, msgs)) state.round1.set(from, r1);
  state.transcript = transcriptHash(state.ctx, state.round1);
  const echo = enrollmentSigned(state.signer, {
    session: state.ctx.sessionId,
    kind: 'dkg-echo',
    from: state.me,
    to: 0,
    fields: [state.transcript],
  });
  return { state, out: [echo] };
}

/** After the echo: every other holder must have signed the same transcript hash; then send encrypted round-2 shares. */
export async function dkgReceiveEcho(
  state: DkgState,
  echoes: readonly FrostMsg[],
): Promise<{ state: DkgState; out: FrostMsg[] }> {
  const { ctx, me } = state;
  const transcript = state.transcript;
  if (!transcript) throw new FrostError('INPUT_INVALID', 'round 1 not done');
  for (const e of onePerHolder(
    ctx,
    me,
    echoes.map((x) => openEnrollmentMessage(ctx, x, 'dkg-echo', me)),
  )) {
    if (e.fields.length !== 1 || !equalBytes(e.fields[0] as Uint8Array, transcript)) {
      throw new FrostError('TRANSCRIPT_MISMATCH', `holder ${e.from}`, e.from);
    }
  }
  const others = [...state.round1].filter(([i]) => i !== me).map(([i, r]) => nobleRound1(i, r));
  const shares = noble(() => ed25519_FROST.DKG.round2(state.secret, others));
  const out: FrostMsg[] = [];
  for (const [i] of state.round1) {
    if (i === me) continue;
    const share = (shares[holderId(i)] as { signingShare: Uint8Array }).signingShare;
    const kemPub = (state.round1.get(i) as Round1).kemPub;
    const ct = await state.cipher.seal(kemPub, r2Aad(ctx, me, i), share);
    out.push(enrollmentSigned(state.signer, { session: ctx.sessionId, kind: 'dkg-r2', from: me, to: i, fields: [ct] }));
  }
  return { state, out };
}

const nobleRound1 = (i: number, r: Round1) => ({
  identifier: holderId(i),
  commitment: r.commitment,
  proofOfKnowledge: r.pok,
});

/** Feldman check of a sub-share f_from(me) against the sender's commitments. */
function shareMatches(r1: Round1, me: number, share: Uint8Array): boolean {
  try {
    const s = parseScalar(share, true);
    return mulBase(s).equals(
      vssEval(
        r1.commitment.map((c) => parsePoint(c)),
        idScalar(holderId(me)),
      ),
    );
  } catch {
    return false;
  }
}

async function tryOpen(
  cipher: ShareCipher,
  sk: Uint8Array,
  aad: Uint8Array,
  ct: Uint8Array,
): Promise<Uint8Array | undefined> {
  try {
    return await cipher.open(sk, aad, ct);
  } catch {
    return undefined;
  }
}

/**
 * Round 3: decrypt and Feldman-check each share. A bad share produces a signed complaint (and no key);
 * otherwise noble's round 3 returns the key share and the slot's public data.
 */
export async function dkgReceiveRound2(
  state: DkgState,
  msgs: readonly FrostMsg[],
): Promise<{ state: DkgState; out: FrostMsg[]; key?: DkgKey }> {
  const { ctx, me } = state;
  if (!state.transcript) throw new FrostError('INPUT_INVALID', 'round 1 not done');
  const received = onePerHolder(
    ctx,
    me,
    msgs.map((x) => openEnrollmentMessage(ctx, x, 'dkg-r2', me)),
  );
  const complaints: FrostMsg[] = [];
  const shares: { identifier: string; signingShare: Uint8Array }[] = [];
  for (const m of received) {
    const ct = m.fields.length === 1 ? (m.fields[0] as Uint8Array) : new Uint8Array();
    const share = await tryOpen(state.cipher, state.kemSecret, r2Aad(ctx, m.from, me), ct);
    if (share && shareMatches(state.round1.get(m.from) as Round1, me, share)) {
      shares.push({ identifier: holderId(m.from), signingShare: share });
      continue;
    }
    complaints.push(
      enrollmentSigned(state.signer, {
        session: ctx.sessionId,
        kind: 'dkg-complaint',
        from: me,
        to: 0,
        fields: [u32(m.from), ct, m.sig, state.kemSecret],
      }),
    );
  }
  if (complaints.length > 0) return { state, out: complaints };
  const others = [...state.round1].filter(([i]) => i !== me).map(([i, r]) => nobleRound1(i, r));
  const key = noble(() => ed25519_FROST.DKG.round3(state.secret, others, shares));
  return { state, out: [], key };
}

/**
 * Anyone can judge a complaint: it names the accused if the accused's signed ciphertext decrypts (with the
 * revealed per-session KEM key) to a share that fails the Feldman check, and names the complainer otherwise.
 * `round1` is the full, echoed set of round-1 messages.
 */
export async function judgeComplaint(
  ctx: DkgContext,
  round1Msgs: readonly FrostMsg[],
  complaint: FrostMsg,
  cipher: ShareCipher,
): Promise<{ guilty: number; reason: string }> {
  const c = openEnrollmentMessage(ctx, complaint, 'dkg-complaint', 0);
  const r1 = new Map(round1Msgs.map((m) => [m.from, parseRound1(openEnrollmentMessage(ctx, m, 'dkg-r1', 0))]));
  const malformed = { guilty: c.from, reason: 'malformed complaint' };
  // The length checks come first: a short field list or index must name the complainer, not throw (I-23).
  if (c.fields.length !== 4 || c.fields[0]?.length !== 4) return malformed;
  const [accusedB, ct, accusedSig, kemSecret] = c.fields as [Uint8Array, Uint8Array, Uint8Array, Uint8Array];
  const accused = new DataView(accusedB.buffer, accusedB.byteOffset).getUint32(0);
  const accusedR1 = r1.get(accused);
  const complainerR1 = r1.get(c.from);
  if (accused === c.from || !accusedR1 || !complainerR1) return malformed;
  const r2 = { session: ctx.sessionId, kind: 'dkg-r2' as const, from: accused, to: c.from, fields: [ct] };
  const accusedKey = (ctx.holders[accused - 1] as Directory['holders'][number]).edPub;
  if (!verifyEd25519Strict(accusedSig, frostMsgBytes(r2), accusedKey)) {
    return { guilty: c.from, reason: 'ciphertext not signed by the accused' };
  }
  let revealed: Uint8Array | undefined;
  try {
    revealed = cipher.publicKeyOf(kemSecret);
  } catch {
    revealed = undefined; // a KEM key of the wrong length
  }
  if (!revealed || !equalBytes(revealed, complainerR1.kemPub)) {
    return { guilty: c.from, reason: 'revealed KEM key does not match round 1' };
  }
  const share = await tryOpen(cipher, kemSecret, r2Aad(ctx, accused, c.from), ct);
  if (share && shareMatches(accusedR1, c.from, share)) return { guilty: c.from, reason: 'false complaint' };
  return { guilty: accused, reason: 'share fails the Feldman check' };
}

// ---------- test-signing and the frost.dkg.completed record ----------

/**
 * The fixed message a pair signs before the seal (DESIGN 6.4 rule 4); the pair is inside the message, and so are the
 * holders' Ed25519 enrollment keys in role order. The slot key's test signatures then bind those keys, so the gate
 * can refuse an enrollment key that did not take part in this DKG (I-S-G2, I-E2; OD-21).
 */
export const testSignMessage = (
  ctx: Pick<DkgContext, 'sessionId' | 'slot'> & { readonly holders: readonly Pick<HolderKey, 'edPub'>[] },
  pub: SlotPublic,
  pair: readonly [number, number],
): Uint8Array =>
  tupleHash('legx/frost-test-sign/v1', [
    ctx.sessionId,
    utf8ToBytes(ctx.slot),
    slotPubkey(pub),
    u32(pair[0]),
    u32(pair[1]),
    ...ctx.holders.map((h) => h.edPub),
  ]);

/**
 * The checkMessage a holder uses for test-signing: only a test message for a pair that includes it, signed
 * with exactly that pair's commitments, so each test signature shows that both of its holders' shares work.
 */
export const testSignCheck =
  (ctx: DkgContext, pub: SlotPublic, me: number) =>
  (msg: Uint8Array, list: readonly Commitment[]): CheckResult => {
    const ids = list.map((c) => Number(idScalar(c.identifier))).sort((a, b) => a - b);
    const pair = ids as [number, number];
    const ok = ids.length === 2 && ids.includes(me) && equalBytes(msg, testSignMessage(ctx, pub, pair));
    return ok ? { ok: true } : { ok: false, reason: "not this pair's test message" };
  };

export type DkgCompleted = {
  kind: 'frost.dkg.completed';
  slot: SlotName;
  slotPolicy: Uint8Array;
  slotPub: Uint8Array;
  transcriptHash: Uint8Array;
  transcriptSigs: Uint8Array[];
  verifyingShares: Uint8Array[];
  testSignatures: { pair: [number, number]; sig: Uint8Array }[];
};

const PAIRS: [number, number][] = [
  [1, 2],
  [1, 3],
  [2, 3],
];

/**
 * Builds the `frost.dkg.completed` record only if every holder signed one transcript hash, the slot's public
 * data follows from that transcript, and all three pairs' test signatures verify strictly; else SLOT_SETUP_FAILED.
 */
export function dkgCompletedRecord(input: {
  ctx: DkgContext;
  pub: SlotPublic;
  round1: readonly FrostMsg[];
  echoes: readonly FrostMsg[];
  testSignatures: readonly { pair: [number, number]; sig: Uint8Array }[];
}): DkgCompleted {
  const { ctx, pub } = input;
  try {
    const r1 = new Map<number, Round1>();
    for (const m of input.round1) r1.set(m.from, parseRound1(openEnrollmentMessage(ctx, m, 'dkg-r1', 0)));
    for (const [from, r] of r1) checkPok(from, r);
    if (r1.size !== ctx.holders.length) throw new Error('round 1 incomplete');
    const transcript = transcriptHash(ctx, r1);
    const echoes = input.echoes.map((m) => openEnrollmentMessage(ctx, m, 'dkg-echo', 0));
    const signers = new Set(echoes.map((e) => e.from));
    if (signers.size !== ctx.holders.length || echoes.length !== signers.size) throw new Error('echo signatures');
    if (!echoes.every((e) => equalBytes(e.fields[0] as Uint8Array, transcript))) throw new Error('echo hash');
    // The group commitment is the sum of every holder's commitment; verifying shares follow from it.
    const merged = [0, 1].map((k) =>
      [...r1.values()].map((r) => parsePoint(r.commitment[k] as Uint8Array)).reduce((a, b) => a.add(b)),
    );
    if (!merged.every((p, k) => equalBytes(p.toBytes(), pub.commitments[k] as Uint8Array)))
      throw new Error('group key');
    const vs = ctx.holders.map((_, i) => vssEval(merged, BigInt(i + 1)).toBytes());
    if (!vs.every((v, i) => equalBytes(v, pub.verifyingShares[holderId(i + 1)] as Uint8Array))) {
      throw new Error('verifying shares');
    }
    const slotPub = slotPubkey(pub);
    const tests = PAIRS.map(([a, b]) => {
      const t = input.testSignatures.find((x) => x.pair[0] === a && x.pair[1] === b);
      if (!t || !verifyEd25519Strict(t.sig, testSignMessage(ctx, pub, [a, b]), slotPub)) {
        throw new Error(`test signature ${a}+${b}`);
      }
      return { pair: [a, b] as [number, number], sig: t.sig };
    });
    return {
      kind: 'frost.dkg.completed',
      slot: ctx.slot,
      slotPolicy: slotPolicy(
        ctx.slot,
        ctx.holders.map((h) => h.role),
      ),
      slotPub,
      transcriptHash: transcript,
      transcriptSigs: ctx.holders.map((_, i) => (echoes.find((e) => e.from === i + 1) as FrostMsg).sig),
      verifyingShares: vs,
      testSignatures: tests,
    };
  } catch (e) {
    throw new FrostError('SLOT_SETUP_FAILED', (e as Error).message);
  }
}
