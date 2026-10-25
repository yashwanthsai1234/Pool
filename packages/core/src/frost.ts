// FROST(Ed25519, SHA-512) slot keys (DESIGN 6.3, 6.4): a thin, strict layer over noble's ed25519_FROST.
// Every slot is a 2-of-3 group key; the ledger sees an ordinary Ed25519 key (0xED || 32 bytes).
// noble's FROST has no independent audit (DESIGN 6.4 "Risks"), so every check we can do sits in
// front of and behind each noble call.
// Source: https://www.rfc-editor.org/rfc/rfc9591
// Source: https://github.com/paulmillr/noble-curves/blob/2.4.0/src/abstract/frost.ts
import { ed25519, ed25519_FROST } from '@noble/curves/ed25519.js';
import { equalBytes } from '@noble/curves/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { deriveAddress } from 'xrpl';
import { tupleHash } from './dealcore.ts';
import { verifyXrplKeySig } from './verify.ts';

export type FrostCode =
  | 'NONCE_USED'
  | 'SESSION_MISMATCH'
  | 'MESSAGE_REFUSED'
  | 'SHARE_INVALID'
  | 'AGGREGATE_INVALID'
  | 'BELOW_THRESHOLD'
  | 'ENROLLMENT_SIG_INVALID'
  | 'WRONG_RECIPIENT'
  | 'NOT_SERIALIZABLE'
  | 'ROLE_INVALID'
  | 'SAME_DEVICE_SHARES'
  | 'INPUT_INVALID'
  | 'KEY_NOT_PINNED'
  | 'KEY_CHANGED'
  | 'KEY_NOT_LOGGED'
  | 'REGISTRY_APPEND_ONLY'
  | 'PIN_MISMATCH'
  | 'LIST_SIGNER_WRONG'
  | 'TRANSCRIPT_MISMATCH'
  | 'POK_INVALID'
  | 'COMPLAINT'
  | 'SLOT_SETUP_FAILED'
  | 'REFRESH_INVALID'
  | 'SUBSHARE_INVALID'
  | 'ROTATION_REQUIRED'
  | 'REPAIR_CONTRIBUTION_INVALID'
  | 'REPAIR_FAILED';

/** Typed error. `culprit` names the holder index (1, 2 or 3) that caused it, when one can be named. */
export class FrostError extends Error {
  readonly code: FrostCode;
  readonly culprit: number | undefined;
  constructor(code: FrostCode, detail = '', culprit?: number) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'FrostError';
    this.code = code;
    this.culprit = culprit;
  }
}

export type KeyShare = { identifier: string; signingShare: Uint8Array };
export type SlotPublic = {
  signers: { min: number; max: number };
  commitments: Uint8Array[];
  verifyingShares: Record<string, Uint8Array>;
};
export type Commitment = { identifier: string; hiding: Uint8Array; binding: Uint8Array };
export type Rng = (bytesLength?: number) => Uint8Array;
export type CheckResult = { ok: true } | { ok: false; reason: string };

export const THRESHOLD = { min: 2, max: 3 } as const;
const Point = ed25519.Point;
const Fn = Point.Fn;
type EdPoint = InstanceType<typeof Point>;

// ---------- encoding helpers (DESIGN 6, "Encoding rules") ----------

export const u32 = (n: number): Uint8Array => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
};

/** Holder index (1-based, in the slot's canonical role order) to the FROST identifier. */
export const holderId = (index: number): string => ed25519_FROST.Identifier.fromNumber(index);

/** FROST identifier (noble: 32-byte little-endian scalar, hex) to a bigint. */
export const idScalar = (id: string): bigint => Fn.fromBytes(hexBytes(id));

function hexBytes(hex: string): Uint8Array {
  if (!/^([0-9a-f]{2})*$/.test(hex)) throw new FrostError('INPUT_INVALID', 'hex');
  return Uint8Array.from(hex.match(/../g) ?? [], (h) => Number.parseInt(h, 16));
}

/** Parse a 32-byte Edwards point; refuses the identity (unless allowed) and points outside the prime-order subgroup. */
export function parsePoint(b: Uint8Array, allowIdentity = false): EdPoint {
  if (!(b instanceof Uint8Array) || b.length !== 32) throw new FrostError('INPUT_INVALID', 'point length');
  let p: EdPoint;
  try {
    p = Point.fromBytes(b);
  } catch {
    throw new FrostError('INPUT_INVALID', 'point encoding');
  }
  if (p.is0() ? !allowIdentity : !p.isTorsionFree()) throw new FrostError('INPUT_INVALID', 'point');
  return p;
}

/** Parse a canonical 32-byte little-endian scalar below the group order (zero allowed only when asked). */
export function parseScalar(b: Uint8Array, allowZero = false): bigint {
  if (!(b instanceof Uint8Array) || b.length !== 32) throw new FrostError('INPUT_INVALID', 'scalar length');
  let s: bigint;
  try {
    s = Fn.fromBytes(b);
  } catch {
    throw new FrostError('INPUT_INVALID', 'scalar range');
  }
  if (s === 0n && !allowZero) throw new FrostError('INPUT_INVALID', 'zero scalar');
  return s;
}

export const scalarBytes = (s: bigint): Uint8Array => Fn.toBytes(Fn.create(s));
export const mulBase = (s: bigint): EdPoint => Point.BASE.multiplyUnsafe(Fn.create(s));
export { Fn, Point };

/** Feldman VSS: the commitment to f(x), sum_k C_k * x^k.
 * Source: Feldman 1987, "A practical scheme for non-interactive verifiable secret sharing", https://doi.org/10.1109/SFCS.1987.4 */
export function vssEval(commitments: readonly EdPoint[], x: bigint): EdPoint {
  let acc = Point.ZERO;
  let pow = 1n;
  for (const c of commitments) {
    acc = acc.add(c.multiplyUnsafe(pow));
    pow = Fn.mul(pow, x);
  }
  return acc;
}

// ---------- roles and slotPolicy (DESIGN 6.4, encoding rules) ----------

export type SlotName = 'A' | 'B' | 'LA' | 'LB';
const CLIENT_ROLES = ['phone', 'second-authenticator', 'recovery-agent'] as const;
const CLIENT_SINGLE_DEVICE_ROLES = ['phone', 'passkey-same-device', 'recovery-agent'] as const;
const LAWYER_ROLES = ['console', 'firm-hsm', 'partner'] as const;
export type Role =
  | (typeof CLIENT_ROLES)[number]
  | (typeof CLIENT_SINGLE_DEVICE_ROLES)[number]
  | (typeof LAWYER_ROLES)[number];

const isClientSlot = (slot: SlotName): boolean => slot === 'A' || slot === 'B';

/** The canonical role order for a slot. A shuffled list is put in order; duplicates and unknown roles are refused. */
export function canonicalRoles(slot: SlotName, roles: readonly string[]): Role[] {
  const options: readonly (readonly Role[])[] = isClientSlot(slot)
    ? [CLIENT_ROLES, CLIENT_SINGLE_DEVICE_ROLES]
    : slot === 'LA' || slot === 'LB'
      ? [LAWYER_ROLES]
      : [];
  const set = new Set(roles);
  const order = options.find((o) => o.every((r) => set.has(r)));
  if (!order || set.size !== roles.length || roles.length !== order.length) {
    throw new FrostError('ROLE_INVALID', roles.join(','));
  }
  return [...order];
}

/** True when the client's share 2 is a passkey on the same phone (DESIGN 6.4 "single-device mode"); screens must label it. */
export const isSingleDeviceMode = (roles: readonly string[]): boolean => roles.includes('passkey-same-device');

/** slotPolicy = tupleHash("legx/slot-policy/v1", [utf8(slot), u32(2), u32(3), utf8(roles joined by ",")]).
 * Only the threshold and holder roles, never verifying shares, so a refresh leaves the seal unchanged (DESIGN 6.4). */
export function slotPolicy(slot: SlotName, roles: readonly string[]): Uint8Array {
  const ordered = canonicalRoles(slot, roles);
  return tupleHash('legx/slot-policy/v1', [
    utf8ToBytes(slot),
    u32(THRESHOLD.min),
    u32(THRESHOLD.max),
    utf8ToBytes(ordered.join(',')),
  ]);
}

// ---------- group key ----------

/** The slot's XRPL public key: 0xED || the 32-byte group key (`public.commitments[0]`). */
export function slotPubkey(pub: SlotPublic): Uint8Array {
  const gk = pub.commitments[0];
  if (!gk) throw new FrostError('INPUT_INVALID', 'no group key');
  parsePoint(gk);
  return concatBytes(new Uint8Array([0xed]), gk);
}

/** The slot's classic address, through xrpl.js. */
export const slotAddress = (pub: SlotPublic): string => deriveAddress(bytesToHex(slotPubkey(pub)).toUpperCase());

/** Strict RFC 8032 verification of an Ed25519 signature under a 0xED-prefixed key, through task 1.4's
 * `verifyXrplKeySig` (zip215: false, DESIGN 6.8). Slot and enrollment keys are Ed25519 only. */
export const verifyEd25519Strict = (sig: Uint8Array, msg: Uint8Array, pub33: Uint8Array): boolean =>
  pub33.length === 33 && pub33[0] === 0xed && verifyXrplKeySig(bytesToHex(pub33), msg, bytesToHex(sig));

/** True when the available holders reach the threshold (P1.15-17). */
export const canSign = (pub: SlotPublic, available: readonly string[]): boolean =>
  new Set(available.filter((id) => id in pub.verifyingShares)).size >= pub.signers.min;

// ---------- signing ----------

function commitmentsHash(list: readonly Commitment[]): Uint8Array {
  const sorted = [...list].sort((a, b) => (idScalar(a.identifier) < idScalar(b.identifier) ? -1 : 1));
  return tupleHash(
    'legx/frost-commitments/v1',
    sorted.flatMap((c) => [hexBytes(c.identifier), c.hiding, c.binding]),
  );
}

function checkCommitmentList(pub: SlotPublic, list: readonly Commitment[]): void {
  const ids = new Set(list.map((c) => c.identifier));
  if (ids.size !== list.length) throw new FrostError('INPUT_INVALID', 'duplicate participant');
  if (list.length < pub.signers.min) throw new FrostError('BELOW_THRESHOLD', `${list.length} of ${pub.signers.min}`);
  for (const c of list) {
    if (!(c.identifier in pub.verifyingShares)) throw new FrostError('INPUT_INVALID', 'unknown participant');
    parsePoint(c.hiding);
    parsePoint(c.binding);
  }
}

/**
 * One signing session for one message. Nonces live only in a private field, are used once, and are
 * zeroed right after use (RFC 9591 sections 5.1, 5.2 and 7.3). There is no serializer and no way to
 * rebuild a session, so a "tab reload" cannot replay nonces. Only this class produces signature shares.
 */
export class SigningSession {
  #share: KeyShare;
  #pub: SlotPublic;
  #nonces: { hiding: Uint8Array; binding: Uint8Array } | undefined;
  readonly #commitment: Commitment;
  readonly #msgHash: Uint8Array;
  #listHash: Uint8Array | undefined;

  private constructor(share: KeyShare, pub: SlotPublic, msg: Uint8Array, rng: Rng | undefined) {
    const vs = pub.verifyingShares[share.identifier];
    if (!vs || !mulBase(parseScalar(share.signingShare)).equals(parsePoint(vs))) {
      throw new FrostError('SHARE_INVALID', 'share does not match its verifying share');
    }
    const { nonces, commitments } = ed25519_FROST.commit(share, rng);
    this.#share = share;
    this.#pub = pub;
    this.#nonces = nonces;
    this.#commitment = commitments;
    this.#msgHash = sha256(msg);
  }

  /** Round 1. `rng` is only for test vectors (RFC 9591 hiding/binding nonce randomness). */
  static open(share: KeyShare, pub: SlotPublic, msg: Uint8Array, rng?: Rng): SigningSession {
    return new SigningSession(share, pub, msg, rng);
  }

  get commitment(): Commitment {
    return this.#commitment;
  }

  /**
   * Round 2. The signer (never the coordinator) supplies `checkMessage`, which decodes the exact bytes
   * and compares them with the seal (DESIGN 6.4 signing rules, RFC 9591 section 7.7).
   * Source: https://www.rfc-editor.org/rfc/rfc9591#section-5.2
   */
  signShare(
    msg: Uint8Array,
    list: readonly Commitment[],
    checkMessage: (m: Uint8Array, list: readonly Commitment[]) => CheckResult,
  ): Uint8Array {
    const listHash = commitmentsHash(list);
    if (!equalBytes(sha256(msg), this.#msgHash)) throw new FrostError('SESSION_MISMATCH', 'message');
    if (this.#listHash && !equalBytes(listHash, this.#listHash)) throw new FrostError('SESSION_MISMATCH', 'list');
    const nonces = this.#nonces;
    if (!nonces) throw new FrostError('NONCE_USED', 'signing nonces already used');
    const own = list.find((c) => c.identifier === this.#share.identifier);
    if (
      !own ||
      !equalBytes(own.hiding, this.#commitment.hiding) ||
      !equalBytes(own.binding, this.#commitment.binding)
    ) {
      throw new FrostError('SESSION_MISMATCH', 'own commitment');
    }
    checkCommitmentList(this.#pub, list);
    const verdict = checkMessage(msg, list);
    if (!verdict.ok) throw new FrostError('MESSAGE_REFUSED', verdict.reason);
    this.#nonces = undefined; // drop first: even a throw below cannot reuse them
    this.#listHash = listHash;
    try {
      return ed25519_FROST.signShare(this.#share, this.#pub, nonces, [...list], msg);
    } finally {
      nonces.hiding.fill(0);
      nonces.binding.fill(0);
    }
  }

  toJSON(): never {
    throw new FrostError('NOT_SERIALIZABLE');
  }
}

/** Returns the identifiers whose signature share fails `verifyShare` (identifiable abort, RFC 9591 section 5.4). */
export function verifyShares(
  pub: SlotPublic,
  list: readonly Commitment[],
  msg: Uint8Array,
  shares: Readonly<Record<string, Uint8Array>>,
): string[] {
  return Object.entries(shares)
    .filter(([id, share]) => {
      try {
        return !ed25519_FROST.verifyShare(pub, [...list], msg, id, share);
      } catch {
        return true;
      }
    })
    .map(([id]) => id);
}

/**
 * Aggregate: check every share first (naming any cheater, and never calling `aggregate` then),
 * aggregate, then verify the result strictly before returning it (DESIGN 6.4 "signing").
 * Source: https://www.rfc-editor.org/rfc/rfc9591#section-5.3
 */
export function aggregateChecked(
  pub: SlotPublic,
  list: readonly Commitment[],
  msg: Uint8Array,
  shares: Readonly<Record<string, Uint8Array>>,
): Uint8Array {
  checkCommitmentList(pub, list);
  const ids = Object.keys(shares);
  if (ids.length !== list.length || !list.every((c) => c.identifier in shares)) {
    throw new FrostError('INPUT_INVALID', 'shares do not match commitments');
  }
  const cheaters = verifyShares(pub, list, msg, shares);
  if (cheaters[0] !== undefined)
    throw new FrostError('SHARE_INVALID', cheaters.join(','), Number(idScalar(cheaters[0])));
  let sig: Uint8Array;
  try {
    sig = ed25519_FROST.aggregate(pub, [...list], msg, shares);
  } catch {
    throw new FrostError('AGGREGATE_INVALID', 'aggregate');
  }
  if (!verifyEd25519Strict(sig, msg, slotPubkey(pub))) throw new FrostError('AGGREGATE_INVALID', 'strict verify');
  return sig;
}

// ---------- enrollment-signed messages (DESIGN 6.3) ----------

/** One holder in a slot ceremony: its role, its pinned enrollment key (33 bytes, 0xED prefix) and its device id. */
export type HolderKey = { holder: string; role: Role; edPub: Uint8Array; deviceId: string };
export type Directory = { sessionId: Uint8Array; holders: readonly HolderKey[] };
export type MsgKind =
  | 'dkg-r1'
  | 'dkg-echo'
  | 'dkg-r2'
  | 'dkg-complaint'
  | 'refresh-commit'
  | 'refresh-share'
  | 'refresh-deleted';
export type FrostMsg = {
  session: Uint8Array;
  kind: MsgKind;
  from: number;
  to: number; // 0 = broadcast
  fields: Uint8Array[];
  sig: Uint8Array;
};
/** Signs with the holder's enrollment key. Ed25519 now; task 1.16 adds the ML-DSA-65 half. */
export type EnrollmentSigner = { sign(msg: Uint8Array): Uint8Array };

/** The exact bytes an enrollment key signs: session id, kind, sender and recipient are all inside. */
export const frostMsgBytes = (m: Omit<FrostMsg, 'sig'>): Uint8Array =>
  tupleHash('legx/frost-msg/v1', [m.session, utf8ToBytes(m.kind), u32(m.from), u32(m.to), ...m.fields]);

export function enrollmentSigned(signer: EnrollmentSigner, m: Omit<FrostMsg, 'sig'>): FrostMsg {
  return { ...m, sig: signer.sign(frostMsgBytes(m)) };
}

/**
 * Authenticate a message against the pinned directory before any use of its content (P1.15-02, T-U-22e).
 * `me` is the receiving holder index; a direct message for another holder is refused.
 */
export function openEnrollmentMessage(dir: Directory, m: FrostMsg, kind: MsgKind, me: number): FrostMsg {
  const sender = dir.holders[m.from - 1];
  if (!sender || !Number.isInteger(m.from) || !verifyEd25519Strict(m.sig, frostMsgBytes(m), sender.edPub)) {
    throw new FrostError('ENROLLMENT_SIG_INVALID', `from ${m.from}`, m.from);
  }
  if (!equalBytes(m.session, dir.sessionId)) throw new FrostError('SESSION_MISMATCH', 'session id', m.from);
  if (m.kind !== kind) throw new FrostError('INPUT_INVALID', `expected ${kind}`, m.from);
  if (m.to !== 0 && m.to !== me) throw new FrostError('WRONG_RECIPIENT', `to ${m.to}`, m.from);
  return m;
}

/** Keeps one message per other holder; a missing or duplicate sender is refused. */
export function onePerHolder(
  dir: Directory,
  me: number,
  msgs: readonly FrostMsg[],
  members?: readonly number[],
): FrostMsg[] {
  const expected = (members ?? dir.holders.map((_, i) => i + 1)).filter((i) => i !== me);
  const byFrom = new Map(msgs.map((m) => [m.from, m]));
  if (byFrom.size !== msgs.length || msgs.length !== expected.length || !expected.every((i) => byFrom.has(i))) {
    throw new FrostError('INPUT_INVALID', 'need exactly one message from each other holder');
  }
  return expected.map((i) => byFrom.get(i) as FrostMsg);
}
