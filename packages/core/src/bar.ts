// Bar records (DESIGN 6.16, 6.2). Pure checks: no network, no clock. Ledger times (Ripple epoch seconds) come in as
// arguments, from validated ledgers the caller trusts. Every failure is a result code, never a boolean.
// Source: DESIGN 6.2 (LC recipe), 6.16 (BarVerification, BarDealLink), 6.17 (BAR_*_OK), encoding rules at the start of 6.
import { ATTEST_PAYLOAD_TYPE, BarDealLink, BarVerification } from '@legx/contracts/records';
import { Jurisdiction } from '@legx/contracts/values';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { tupleHash } from './dealcore.ts';
import type { Envelope } from './evidence.ts';

/** The age limit is exactly 30 days of ledger time: 30 days passes, 30 days plus 1 second is stale (DESIGN D19). */
export const BAR_MAX_AGE_SECONDS = 30 * 24 * 60 * 60;

// contracts exports the schemas only, so the record types are read off them.
export type BarVerificationRecord = ReturnType<typeof BarVerification.parse>;
export type BarDealLinkRecord = ReturnType<typeof BarDealLink.parse>;

export type BarCode =
  | 'ENVELOPE_INVALID'
  | 'WRONG_SIGNER'
  | 'MALFORMED'
  | 'WRONG_DEAL'
  | 'ROLE_MISMATCH'
  | 'LAWYER_KEY_MISMATCH'
  | 'COMMITMENT_MISMATCH'
  | 'OPS_MISMATCH'
  | 'VERIFICATION_HASH_MISMATCH'
  | 'NOT_ACTIVE'
  | 'TIME_INVALID'
  | 'STALE'
  | 'BAR_NUMBER_MISMATCH';
export type BarResult<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly code: BarCode };

/** What a hybrid envelope verifier returns (task 1.16 `verifyHybrid` fits once bound to a registry and a time). */
export type EnvelopeVerifier = (
  env: Envelope,
) => { ok: true; payload: Uint8Array; keyIds: { ed25519: string; mlDsa65: string } } | { ok: false; code: string };
/** The verifier attestation key pair the caller trusts, and the function that checks envelopes. */
export interface BarTrust {
  readonly verify: EnvelopeVerifier;
  readonly verifierKeyIds: { readonly ed25519: string; readonly mlDsa65: string };
}

const fail = (code: BarCode) => ({ ok: false, code }) as const;
const sha256Hex = (b: Uint8Array) => bytesToHex(sha256(b));

/** Trim, then refuse anything outside A-Z, a-z, 0-9, `-`, then uppercase. Checked before uppercasing: `ı` upcases to `I`. */
export function normalizeBarNumber(raw: string): string {
  const t = raw.trim();
  if (!/^[A-Za-z0-9-]{1,32}$/.test(t)) throw new Error('bar number: only A-Z, 0-9 and - (1 to 32 characters)');
  return t.toUpperCase();
}

/** SHA-256 of the normalized bar number: the only form the platform stores (DESIGN 9). Design question DQ-1.10-1. */
export const barNumberSha256 = (barNumber: string): string => sha256Hex(utf8ToBytes(normalizeBarNumber(barNumber)));

/**
 * LC = tupleHash("legx/bar-commit/v1", [salt32, utf8(jurisdiction + ":" + barNumber)]). A jurisdiction that is not an
 * ISO 3166 code with an optional subdivision (so one with `:`) is refused, which keeps the string unambiguous.
 */
export function openBarCommitment(salt32: Uint8Array, jurisdiction: string, barNumber: string): Uint8Array {
  if (salt32.length !== 32) throw new Error('salt must be 32 bytes');
  if (!Jurisdiction.safeParse(jurisdiction).success) throw new Error('jurisdiction: ISO 3166 code, e.g. US or US-CA');
  return tupleHash('legx/bar-commit/v1', [salt32, utf8ToBytes(`${jurisdiction}:${normalizeBarNumber(barNumber)}`)]);
}

// Parses stored envelope bytes, checks the signature through the injected verifier, then the payload shape.
function open<T>(
  bytes: Uint8Array,
  trust: BarTrust,
  schema: { safeParse(x: unknown): { success: true; data: T } | { success: false } },
): BarResult<T> {
  let env: Envelope;
  try {
    env = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    return fail('ENVELOPE_INVALID');
  }
  if (env?.payloadType !== ATTEST_PAYLOAD_TYPE) return fail('ENVELOPE_INVALID');
  const r = trust.verify(env);
  if (!r.ok) return fail('ENVELOPE_INVALID');
  if (r.keyIds.ed25519 !== trust.verifierKeyIds.ed25519 || r.keyIds.mlDsa65 !== trust.verifierKeyIds.mlDsa65) {
    return fail('WRONG_SIGNER');
  }
  let json: unknown;
  try {
    json = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(r.payload));
  } catch {
    return fail('MALFORMED');
  }
  const p = schema.safeParse(json);
  return p.success ? { ok: true, value: p.data } : fail('MALFORMED');
}

export interface BarVerificationInput {
  readonly envelopeBytes: Uint8Array; // the exact stored DSSE bytes
  readonly trust: BarTrust;
  readonly opsAccount: string; // the sealed operations account
  /** close_time of the ledger in `checked_at_ledger`, looked up from validated history (Ripple epoch seconds). */
  readonly checkedAtCloseTime: number;
  /** close_time of the validated ledger the gate reads (Ripple epoch seconds). */
  readonly nowCloseTime: number;
}

/** Signed by the verifier, for this operations account, `active`, and at most 30 days old by ledger time. */
export function verifyBarVerification(i: BarVerificationInput): BarResult<BarVerificationRecord> {
  const r = open(i.envelopeBytes, i.trust, BarVerification);
  if (!r.ok) return r;
  const v = r.value;
  if (v.ops_account !== i.opsAccount) return fail('OPS_MISMATCH');
  if (v.status !== 'active') return fail('NOT_ACTIVE');
  const age = i.nowCloseTime - i.checkedAtCloseTime;
  if (!Number.isSafeInteger(i.nowCloseTime) || !Number.isSafeInteger(i.checkedAtCloseTime) || age < 0) {
    return fail('TIME_INVALID');
  }
  return age > BAR_MAX_AGE_SECONDS ? fail('STALE') : r;
}

/** The deal's sealed values the link must match (DESIGN 6.6). */
export interface SealedBarTerms {
  readonly dealId: string;
  readonly contractRoot: string; // hex
  readonly role: 'LA' | 'LB';
  readonly lawyerPub: string;
  readonly barCommitment: string; // hex of LC_role
  readonly opsAccount: string;
}
export interface BarDealLinkInput extends Omit<BarVerificationInput, 'envelopeBytes' | 'opsAccount'> {
  readonly linkBytes: Uint8Array;
  readonly verificationBytes: Uint8Array;
  readonly sealed: SealedBarTerms;
  /** Verifier side only: the salt and bar number the lawyer gave. The gate has no salt and omits this. */
  readonly opening?: { readonly salt32: Uint8Array; readonly barNumber: string };
}

/** The link matches this deal and the sealed values, names exactly this verification, and that one passes too. */
export function verifyBarDealLink(i: BarDealLinkInput): BarResult<BarDealLinkRecord> {
  const r = open(i.linkBytes, i.trust, BarDealLink);
  if (!r.ok) return r;
  const l = r.value;
  const s = i.sealed;
  if (l.deal_id !== s.dealId || l.contract_root !== s.contractRoot) return fail('WRONG_DEAL');
  if (l.role !== s.role) return fail('ROLE_MISMATCH');
  if (l.lawyer_pub !== s.lawyerPub) return fail('LAWYER_KEY_MISMATCH');
  if (l.bar_commitment !== s.barCommitment) return fail('COMMITMENT_MISMATCH');
  if (l.ops_account !== s.opsAccount) return fail('OPS_MISMATCH');
  if (l.verification_sha256 !== sha256Hex(i.verificationBytes)) return fail('VERIFICATION_HASH_MISMATCH');
  const v = verifyBarVerification({ ...i, envelopeBytes: i.verificationBytes, opsAccount: s.opsAccount });
  if (!v.ok) return v;
  if (i.opening) {
    const { salt32, barNumber } = i.opening;
    if (barNumberSha256(barNumber) !== v.value.bar_number_sha256) return fail('BAR_NUMBER_MISMATCH');
    const lc = bytesToHex(openBarCommitment(salt32, v.value.jurisdiction, barNumber));
    if (lc !== s.barCommitment) return fail('COMMITMENT_MISMATCH');
  }
  return r;
}
