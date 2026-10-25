// Pure rules every share holder applies before it signs (DESIGN 6.4 "Signing rules" and "Recovery rules"):
// approvals, the message allow-list, the server nonce ledger, the recovery state machine and rotation plans.
// A holder never signs on its own say-so, and never signs bytes it has not decoded and compared with the seal.
// Source: https://www.rfc-editor.org/rfc/rfc9591#section-7.7 (signers should validate the message)
import { p256 } from '@noble/curves/nist.js';
import { equalBytes } from '@noble/curves/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { base64, base64urlnopad } from '@scure/base';
import { deriveAddress, encodeForMultiSigning, encodeForSigning, type Transaction } from 'xrpl';
import { tupleHash } from './dealcore.ts';
import {
  type CheckResult,
  type Commitment,
  FrostError,
  type Role,
  type SlotName,
  verifyEd25519Strict,
} from './frost.ts';
import { verifyXrplKeySig } from './verify.ts';

// ---------- approvals (WebAuthn assertion by the human owner of the slot) ----------

/** A WebAuthn assertion over the message hash (the challenge is the 32-byte hash). ES256 credentials. */
export type Approval = { authenticatorData: Uint8Array; clientDataJSON: Uint8Array; signature: Uint8Array };
/** `origins`: the exact origins expected; by default any `https://` origin whose host is the RP ID or under it. */
export type ApproverKey = { p256Pub: Uint8Array; rpId: string; origins?: readonly string[] };
export type ApprovalCode =
  | 'APPROVAL_MISSING'
  | 'APPROVAL_SIG_INVALID'
  | 'APPROVAL_HASH_MISMATCH'
  | 'APPROVAL_NOT_UV'
  | 'APPROVAL_ORIGIN';

/**
 * WebAuthn L3 7.2 step 13: C.origin is an origin the RP expects. Without a list, an https origin (default port) whose
 * host is the RP ID or a subdomain of it, as the RP ID rules allow; for the RP ID `localhost` (development and the
 * browser tests), also http on any port, since browsers treat localhost as a secure context.
 * Source: https://www.w3.org/TR/webauthn-3/#rp-id ; https://www.w3.org/TR/secure-contexts/#localhost
 */
function originExpected(origin: unknown, key: ApproverKey): boolean {
  if (typeof origin !== 'string') return false;
  if (key.origins) return key.origins.includes(origin);
  if (key.rpId === 'localhost' && /^https?:\/\/localhost(:[0-9]{1,5})?$/.test(origin)) return true;
  const m = /^https:\/\/([a-z0-9.-]+)$/.exec(origin);
  return !!m && (m[1] === key.rpId || (m[1] as string).endsWith(`.${key.rpId}`));
}

const b64url = (b: Uint8Array): string => base64urlnopad.encode(b);
// DSSE payloads are standard base64; padding is restored so unpadded input still decodes, as Buffer did.
const fromB64 = (s: string): Uint8Array => base64.decode(s.padEnd(Math.ceil(s.length / 4) * 4, '='));

/**
 * The firm HSM (and the client's second authenticator) sign only with a user-verified approval over the same
 * message hash. Checks follow WebAuthn Level 3 section 7.2: type, challenge, origin, crossOrigin, rpIdHash, UP and UV flags, and
 * the signature over authenticatorData || SHA-256(clientDataJSON).
 * Source: https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion
 */
export function approvalCheck(
  approval: Approval | undefined,
  msgHash: Uint8Array,
  key: ApproverKey,
): { ok: true } | { ok: false; code: ApprovalCode } {
  if (!approval) return { ok: false, code: 'APPROVAL_MISSING' };
  const { authenticatorData: ad, clientDataJSON, signature } = approval;
  // noble returns false (it does not throw) for a malformed signature or key.
  const data = new Uint8Array([...ad, ...sha256(clientDataJSON)]);
  const signed = p256.verify(signature, data, key.p256Pub, { format: 'der', lowS: false });
  if (!signed || ad.length < 37 || !equalBytes(ad.subarray(0, 32), sha256(utf8ToBytes(key.rpId)))) {
    return { ok: false, code: 'APPROVAL_SIG_INVALID' };
  }
  let client: { type?: unknown; challenge?: unknown; origin?: unknown; crossOrigin?: unknown };
  try {
    client = JSON.parse(new TextDecoder().decode(clientDataJSON));
  } catch {
    return { ok: false, code: 'APPROVAL_SIG_INVALID' };
  }
  if (client.type !== 'webauthn.get' || client.challenge !== b64url(msgHash))
    return { ok: false, code: 'APPROVAL_HASH_MISMATCH' };
  // Steps 13 and 14 (I-S-F3): an expected origin, and never made inside a frame of another site.
  if (!originExpected(client.origin, key) || client.crossOrigin === true) return { ok: false, code: 'APPROVAL_ORIGIN' };
  const flags = ad[32] as number;
  if ((flags & 0x01) === 0 || (flags & 0x04) === 0) return { ok: false, code: 'APPROVAL_NOT_UV' };
  return { ok: true };
}

// ---------- the message allow-list ----------

export type Payout = { account: string; tag?: number };
/** The sealed public deal data a holder compares every request with. */
export type SealedDeal = {
  walletAddress: string;
  contractRoot: Uint8Array;
  dealSeal?: Uint8Array; // absent before the seal exists; seal-bound tags are refused then
  payoutA: Payout; // Alice: refund, and the AccountDelete destination
  payoutB: Payout;
  exitAmountDrops: string;
  maxFeeDrops: string;
  slotPubs: Record<SlotName, Uint8Array>; // 33-byte XRPL keys
};
export type SignRequest =
  | { kind: 'xrpl-multisign'; tx: Record<string, unknown> }
  | { kind: 'xrpl-single'; tx: Record<string, unknown> }
  | { kind: 'tagged'; tag: string; parts: Uint8Array[] }
  | { kind: 'gate-record'; envelope: Uint8Array };

const refused = (reason: string): CheckResult => ({ ok: false, reason });
const BASE_FIELDS = [
  'TransactionType',
  'Account',
  'Destination',
  'DestinationTag',
  'Fee',
  'Sequence',
  'TicketSequence',
  'LastLedgerSequence',
  'Flags',
  'SigningPubKey',
  'NetworkID',
];
const ALLOWED_TX: Record<string, string[]> = { Payment: [...BASE_FIELDS, 'Amount'], AccountDelete: BASE_FIELDS };
const TF_FULLY_CANONICAL_SIG = 0x80000000;
const UINT32_FIELDS = ['DestinationTag', 'Sequence', 'TicketSequence', 'LastLedgerSequence', 'NetworkID'];
const isUint32 = (v: unknown): boolean => Number.isInteger(v) && (v as number) >= 0 && (v as number) <= 0xffffffff;

const samePayout = (tx: Record<string, unknown>, p: Payout): boolean =>
  tx.Destination === p.account && tx.DestinationTag === p.tag;

/** Exits from the deal wallet only: a Payment of the agreed amount to a sealed payout, or AccountDelete to Alice. */
function checkMultisign(tx: Record<string, unknown>, msg: Uint8Array, deal: SealedDeal, slot: SlotName): CheckResult {
  const fields = ALLOWED_TX[tx.TransactionType as string];
  if (!fields) return refused('transaction type');
  if (Object.keys(tx).some((k) => !fields.includes(k))) return refused('unexpected field');
  if (tx.Account !== deal.walletAddress) return refused('another wallet');
  if (tx.SigningPubKey !== undefined && tx.SigningPubKey !== '') return refused('not a multisign');
  if (tx.Flags !== undefined && tx.Flags !== 0 && tx.Flags !== TF_FULLY_CANONICAL_SIG) return refused('flags');
  if (!UINT32_FIELDS.every((f) => tx[f] === undefined || isUint32(tx[f]))) return refused('integer field');
  if (typeof tx.Fee !== 'string' || !/^\d{1,16}$/.test(tx.Fee) || BigInt(tx.Fee) > BigInt(deal.maxFeeDrops))
    return refused('fee');
  if (tx.TransactionType === 'Payment') {
    if (!samePayout(tx, deal.payoutA) && !samePayout(tx, deal.payoutB)) return refused('destination');
    if (tx.Amount !== deal.exitAmountDrops) return refused('amount');
  } else if (!samePayout(tx, deal.payoutA)) return refused('destination');
  const signer = deriveAddress(bytesToHex(deal.slotPubs[slot]).toUpperCase());
  // xrpl.js may still throw on a value it cannot encode; that is a refusal too (before any nonce is used).
  const expected = encodeForMultiSigning(tx as unknown as Transaction, signer);
  return expected === bytesToHex(msg).toUpperCase() ? { ok: true } : refused('message is not this transaction');
}

const ACCEPT_FIELDS = [
  'TransactionType',
  'Account',
  'Issuer',
  'CredentialType',
  'Fee',
  'Sequence',
  'LastLedgerSequence',
  'SigningPubKey',
  'NetworkID',
];
/**
 * OD-33, step 5f: a client slot's own account (the address of its group key) accepts its party badge, single-signed:
 * `CredentialAccept` with `Issuer` = the sealed deal wallet and `CredentialType` = hex(`LEGX_PARTY_<side>`), the
 * slot key as `SigningPubKey`, a capped fee, and no other field (no flags, memos or tickets).
 * Source: https://xrpl.org/docs/references/protocol/transactions/types/credentialaccept ; DESIGN 7.3 step 5f
 */
function checkCredentialAccept(
  tx: Record<string, unknown>,
  msg: Uint8Array,
  deal: SealedDeal,
  slot: SlotName,
): CheckResult {
  if (slot !== 'A' && slot !== 'B') return refused('only a client slot accepts a party badge');
  if (tx.TransactionType !== 'CredentialAccept') return refused('transaction type');
  if (Object.keys(tx).some((k) => !ACCEPT_FIELDS.includes(k))) return refused('unexpected field');
  const pubHex = bytesToHex(deal.slotPubs[slot]).toUpperCase();
  if (tx.Account !== deriveAddress(pubHex) || tx.SigningPubKey !== pubHex) return refused('not this slot account');
  if (tx.Issuer !== deal.walletAddress) return refused('issuer');
  if (tx.CredentialType !== bytesToHex(utf8ToBytes(`LEGX_PARTY_${slot}`)).toUpperCase()) return refused('type');
  if (!UINT32_FIELDS.every((f) => tx[f] === undefined || isUint32(tx[f]))) return refused('integer field');
  if (typeof tx.Fee !== 'string' || !/^\d{1,16}$/.test(tx.Fee) || BigInt(tx.Fee) > BigInt(deal.maxFeeDrops))
    return refused('fee');
  try {
    const same = encodeForSigning(tx as unknown as Transaction) === bytesToHex(msg).toUpperCase();
    return same ? { ok: true } : refused('message is not this transaction');
  } catch {
    return refused('not encodable'); // before any nonce is used
  }
}

/** The tagged tupleHash messages a slot may sign, each with the parts that must match the seal (DESIGN 6.4). */
function checkTagged(tag: string, p: readonly Uint8Array[], deal: SealedDeal, slot: SlotName): boolean {
  const eq = (i: number, v: Uint8Array | undefined) => v !== undefined && p[i] !== undefined && equalBytes(p[i], v);
  const isSlot = (i: number) => eq(i, utf8ToBytes(slot));
  const lawyer = slot === 'LA' || slot === 'LB';
  switch (tag) {
    case 'legx/binding/v1': // 6.5 [contractRoot, C_side, slotPub, side]
      return p.length === 4 && eq(0, deal.contractRoot) && eq(2, deal.slotPubs[slot]) && isSlot(3);
    case 'legx/contract-sign/v1': // 6.12 [contractRoot, wallet, role]
      return (
        lawyer && p.length === 3 && eq(0, deal.contractRoot) && eq(1, utf8ToBytes(deal.walletAddress)) && isSlot(2)
      );
    case 'legx/passport-presence/v1': // 6.15 [dealSeal, side, ledger_hash, lawyerNonce]
      return !lawyer && p.length === 4 && eq(0, deal.dealSeal) && isSlot(1);
    case 'legx/pq-binding/v1': // 6.13 [dealSeal, slotPub, pqKeyHash]
      return p.length === 3 && eq(0, deal.dealSeal) && eq(1, deal.slotPubs[slot]);
    case 'legx/ops-binding/v1': // 6.14 [contractRoot, opsAccount, lawyerPub, LC, role]
      return lawyer && p.length === 5 && eq(0, deal.contractRoot) && eq(2, deal.slotPubs[slot]) && isSlot(4);
    default:
      return false;
  }
}

/** 6.17: lawyer slot B signs the SHA-256 of a `release.gate.passed` DSSE envelope for this deal. */
function checkGateRecord(envelope: Uint8Array, msg: Uint8Array, deal: SealedDeal, slot: SlotName): CheckResult {
  if (slot !== 'LB' || !equalBytes(sha256(envelope), msg)) return refused('gate record hash');
  try {
    const env = JSON.parse(new TextDecoder().decode(envelope)) as { payloadType: string; payload: string };
    const st = JSON.parse(new TextDecoder().decode(fromB64(env.payload)));
    const ok =
      env.payloadType === 'application/vnd.legx.event+json;v=1' &&
      st.predicate.kind === 'release.gate.passed' &&
      st.subject[0].digest.sha256 === bytesToHex(deal.contractRoot);
    return ok ? { ok: true } : refused('not a gate record for this deal');
  } catch {
    return refused('envelope');
  }
}

/** Decides whether `msg` is on the allow-list for this slot of this deal. */
export function messageAllowed(req: SignRequest, msg: Uint8Array, deal: SealedDeal, slot: SlotName): CheckResult {
  switch (req.kind) {
    case 'xrpl-multisign':
      return checkMultisign(req.tx, msg, deal, slot);
    case 'xrpl-single':
      return checkCredentialAccept(req.tx, msg, deal, slot);
    case 'tagged':
      return checkTagged(req.tag, req.parts, deal, slot) && equalBytes(tupleHash(req.tag, req.parts), msg)
        ? { ok: true }
        : refused(`tag ${req.tag}`);
    case 'gate-record':
      return checkGateRecord(req.envelope, msg, deal, slot);
  }
}

/** Holders that need the human's user-verified approval before they sign (DESIGN 6.4). */
const NEEDS_APPROVAL: readonly Role[] = ['firm-hsm', 'second-authenticator'];

/**
 * The co-signing decision the services use (firm HSM, recovery agent, second device): the message must be on
 * the allow-list, and an approval-guarded holder needs a user-verified approval over SHA-256(msg).
 * Pass the result as `checkMessage` to `SigningSession.signShare`, so a refusal never uses a nonce.
 */
export function cosign(input: {
  request: SignRequest;
  msg: Uint8Array;
  deal: SealedDeal;
  slot: SlotName;
  role: Role;
  approval?: Approval;
  approver?: ApproverKey;
}): CheckResult {
  const allowed = messageAllowed(input.request, input.msg, input.deal, input.slot);
  if (!allowed.ok || !NEEDS_APPROVAL.includes(input.role)) return allowed;
  if (!input.approver) return refused('APPROVAL_MISSING');
  const a = approvalCheck(input.approval, sha256(input.msg), input.approver);
  return a.ok ? a : refused(a.code);
}

// ---------- server nonce ledger ----------

/** Stable id of a round-1 commitment. */
export const commitmentId = (c: Commitment): string =>
  bytesToHex(tupleHash('legx/frost-commitment-id/v1', [hexToBytes(c.identifier), c.hiding, c.binding]));

/** Server holders mark a commitment used in one atomic step before releasing a share (Phase 3: Postgres). */
export type NonceLedger = { markUsed(commitmentId: string): Promise<boolean> };

export class MemoryNonceLedger implements NonceLedger {
  readonly #used = new Set<string>();
  async markUsed(id: string): Promise<boolean> {
    if (this.#used.has(id)) return false;
    this.#used.add(id);
    return true;
  }
}

/** Releases a signature share only if this call is the one that marked the commitment used. */
export async function releaseShare(ledger: NonceLedger, id: string, sign: () => Uint8Array): Promise<Uint8Array> {
  if (!(await ledger.markUsed(id))) throw new FrostError('NONCE_USED', `signing nonces already used (${id})`);
  return sign();
}

// ---------- recovery rules (DESIGN 6.4) ----------

export const RECOVERY_DELAY_MS = 72 * 3600 * 1000;
/** How old a zero-knowledge proof may be to count as fresh for recovery. */
export const PROOF_FRESH_MS = 10 * 60 * 1000;
export type RecoveryCode =
  | 'IDENTIFIER_MISMATCH'
  | 'FACE_MATCH_MISSING'
  | 'PROOF_STALE'
  | 'OPS_SIGNATURE_INVALID'
  | 'RECOVERY_DELAY'
  | 'CANCELLED'
  | 'CANCEL_TOO_LATE'
  | 'CANCEL_SIG_INVALID';
export class RecoveryError extends Error {
  readonly code: RecoveryCode;
  constructor(code: RecoveryCode) {
    super(code);
    this.name = 'RecoveryError';
    this.code = code;
  }
}
export type RecoveryRecord = { kind: string; at: number; slot: SlotName; detail: string };
export type RecoveryState = {
  /** UUIDv7, made by `recoveryStart`; the cancel statement names it, so it cancels this recovery only (I-S-F2). */
  recoveryId: string;
  slot: SlotName;
  status: 'pending' | 'cancelled' | 'authorized';
  startedAt: number;
  records: RecoveryRecord[];
};
export type RecoveryRequest =
  | {
      kind: 'client';
      slot: 'A' | 'B';
      at: number;
      proof: { identifier: string; provedAt: number };
      onboardingIdentifier: string;
      faceMatch: boolean;
    }
  | {
      kind: 'lawyer';
      slot: 'LA' | 'LB';
      at: number;
      /** What the operations account signed, as `lawyerRecoveryMessage` fields (I-S-F1). */
      dealId: string;
      newKeyId: string;
      ledgerIndex: number;
      sig: Uint8Array;
      opsPub: Uint8Array;
      opsAccount: string;
    };

/**
 * What the firm's operations account signs to start a lawyer recovery: bound to the deal, the slot, the new key and
 * a ledger index (the caller checks it is fresh), so no other signature by that key starts one (I-S-F1).
 * Source: DESIGN 6.4 "Recovery rules"; the tag is contracts `LAWYER_RECOVERY_TAG` (a test pins it; core does not load the API contract)
 */
export function lawyerRecoveryMessage(dealId: string, slot: string, newKeyId: string, ledgerIndex: number): Uint8Array {
  if (!Number.isInteger(ledgerIndex) || ledgerIndex < 0 || ledgerIndex > 0xffffffff)
    throw new RangeError('ledgerIndex');
  const u32 = new Uint8Array(4);
  new DataView(u32.buffer).setUint32(0, ledgerIndex);
  return tupleHash('legx/lawyer-recovery/v1', [utf8ToBytes(dealId), utf8ToBytes(slot), utf8ToBytes(newKeyId), u32]);
}

/** A UUIDv7 for `at` (Unix ms). Source: https://www.rfc-editor.org/rfc/rfc9562#section-5.7 */
function uuid7(at: number): string {
  const b = randomBytes(16);
  new DataView(b.buffer).setUint16(0, Math.floor(at / 2 ** 32) & 0xffff);
  new DataView(b.buffer).setUint32(2, at >>> 0);
  b[6] = 0x70 | ((b[6] as number) & 0x0f);
  b[8] = 0x80 | ((b[8] as number) & 0x3f);
  const h = bytesToHex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Starts a recovery: checks who asks, then produces notices for the old device and both lawyers. */
export function recoveryStart(req: RecoveryRequest): { state: RecoveryState; notices: string[] } {
  if (req.kind === 'client') {
    if (req.proof.identifier !== req.onboardingIdentifier) throw new RecoveryError('IDENTIFIER_MISMATCH');
    if (req.at - req.proof.provedAt > PROOF_FRESH_MS || req.proof.provedAt > req.at)
      throw new RecoveryError('PROOF_STALE');
    if (!req.faceMatch) throw new RecoveryError('FACE_MATCH_MISSING');
  } else {
    const pubHex = bytesToHex(req.opsPub).toUpperCase();
    const addr = req.opsPub.length === 33 ? deriveAddress(pubHex) : '';
    let msg: Uint8Array;
    try {
      msg = lawyerRecoveryMessage(req.dealId, req.slot, req.newKeyId, req.ledgerIndex);
    } catch {
      throw new RecoveryError('OPS_SIGNATURE_INVALID'); // no well-formed request to check the signature against
    }
    if (addr !== req.opsAccount || !verifyXrplKeySig(pubHex, msg, bytesToHex(req.sig))) {
      throw new RecoveryError('OPS_SIGNATURE_INVALID');
    }
  }
  const notices = ['old-device', 'lawyerA', 'lawyerB'];
  const record = {
    kind: 'frost.recovery.requested',
    at: req.at,
    slot: req.slot,
    detail: `${req.kind}; notified ${notices.join(',')}`,
  };
  const state: RecoveryState = {
    recoveryId: uuid7(req.at),
    slot: req.slot,
    status: 'pending',
    startedAt: req.at,
    records: [record],
  };
  return { state, notices };
}

/** The old device cancels during the delay with a statement signed by its pinned enrollment key. */
export function recoveryCancel(
  s: RecoveryState,
  at: number,
  cancel: { sig: Uint8Array; oldDevicePub: Uint8Array },
): RecoveryState {
  if (s.status !== 'pending') throw new RecoveryError('CANCELLED');
  if (at >= s.startedAt + RECOVERY_DELAY_MS) throw new RecoveryError('CANCEL_TOO_LATE');
  if (!verifyEd25519Strict(cancel.sig, recoveryCancelMessage(s), cancel.oldDevicePub))
    throw new RecoveryError('CANCEL_SIG_INVALID');
  return {
    ...s,
    status: 'cancelled',
    records: [...s.records, { kind: 'frost.recovery.cancelled', at, slot: s.slot, detail: 'old device' }],
  };
}

/** The cancel statement names the recovery (a UUIDv7, unique), so it cancels no other recovery (I-S-F2). */
export const recoveryCancelMessage = (s: RecoveryState): Uint8Array =>
  tupleHash('legx/recovery-cancel/v1', [
    utf8ToBytes(s.recoveryId),
    utf8ToBytes(s.slot),
    utf8ToBytes(String(s.startedAt)),
  ]);

/** Recovery signing may start only after the full 72-hour delay, and never after a cancel. */
export function recoveryAuthorize(s: RecoveryState, at: number): RecoveryState {
  if (s.status === 'cancelled') throw new RecoveryError('CANCELLED');
  if (at - s.startedAt < RECOVERY_DELAY_MS) throw new RecoveryError('RECOVERY_DELAY');
  return {
    ...s,
    status: 'authorized',
    records: [...s.records, { kind: 'frost.recovery.authorized', at, slot: s.slot, detail: '' }],
  };
}

/**
 * After an authorized recovery signs, the record names the two share holders that took part, by role, so the
 * evidence shows who signed (DESIGN 6.4 recovery rules; I-E6). The roles come from the aggregated commitments.
 */
export function recoverySigned(s: RecoveryState, at: number, holders: readonly [Role, Role]): RecoveryState {
  if (s.status !== 'authorized') throw new RecoveryError(s.status === 'cancelled' ? 'CANCELLED' : 'RECOVERY_DELAY');
  if (holders[0] === holders[1]) throw new FrostError('ROLE_INVALID', 'two distinct holders sign');
  const record = { kind: 'frost.recovery.signed', at, slot: s.slot, detail: `signed by ${holders.join(',')}` };
  return { ...s, records: [...s.records, record] };
}

// ---------- rotation (the only real revocation) ----------

export type RotationStep =
  | 'repair'
  | 'refresh'
  | 'new-dkg'
  | 'signer-list-set-4-of-4'
  | 'new-seal'
  | 'new-contract-signatures'
  | 'new-nft';

/** A lost share is repaired and refreshed; a stolen share needs a new slot key on the ledger (DESIGN 6.4). */
export function rotationPlan(slot: SlotName, reason: 'lost' | 'stolen'): RotationStep[] {
  if (reason === 'lost') return ['repair', 'refresh'];
  const plan: RotationStep[] = ['new-dkg', 'signer-list-set-4-of-4', 'new-seal'];
  return slot === 'LA' || slot === 'LB' ? [...plan, 'new-contract-signatures', 'new-nft'] : plan;
}
