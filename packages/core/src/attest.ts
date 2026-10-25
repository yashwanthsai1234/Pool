// Passport attestation at release (DESIGN 6.15, W4a) and the onboarding attestation (6.10, 6.17 ONBOARDING_OK).
// The release gate and the arbitrator's verifier run these pure checks. They never see or parse passport data
// (invariant I7): the client's own lawyer ran passive authentication (passport/passiveAuth.ts) or verified the
// zero-knowledge proof (task 1.17), and signed what was found; the gate trusts that signature for the checking part (D21).
import type { PublicDealData } from '@legx/contracts/deal';
import { ZK_DOMAIN } from '@legx/contracts/records';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { dealSeal, tupleHash } from './dealcore.ts';
import { ATTEST_PAYLOAD_TYPE, type Envelope } from './evidence.ts';
import { type HybridCode, type KeyRegistry, verifyHybrid } from './hybridEnvelope.ts';
import { verifyXrplKeySig } from './verify.ts';

export type Side = 'A' | 'B';
export type Method = 'zkpassport' | 'nfc-chip';
export type Profile = 'production' | 'demo';

/**
 * presenceMsg = tupleHash("legx/passport-presence/v1", [dealSeal, utf8(side), ledger_hash, lawyerNonce]): what the
 * client's slot key signs, and whose first 8 bytes are the Active Authentication challenge. Throws a RangeError
 * ('NONCE_LENGTH' for a nonce that is not 32 bytes) on wrong input lengths.
 * Source: DESIGN.md 6.15 and the encoding rules of section 6 (hashes, ledger hashes and nonces are 32 raw bytes)
 */
export function presenceMsg(
  dealSeal: Uint8Array,
  side: Side,
  ledgerHash: Uint8Array,
  lawyerNonce: Uint8Array,
): Uint8Array {
  if (lawyerNonce.length !== 32) throw new RangeError('NONCE_LENGTH');
  if (dealSeal.length !== 32 || ledgerHash.length !== 32)
    throw new RangeError('dealSeal and ledgerHash must be 32 bytes');
  if (side !== 'A' && side !== 'B') throw new RangeError('side must be A or B');
  return tupleHash('legx/passport-presence/v1', [dealSeal, utf8ToBytes(side), ledgerHash, lawyerNonce]);
}

/** The deal-scoped ZKPassport scope. Source: DESIGN 6.10 (`scope = "legx/v1/" || dealId`) */
export function zkScope(dealId: string): string {
  if (dealId === '') throw new Error('dealId must not be empty');
  return `legx/v1/${dealId}`;
}

/**
 * OD-29: distinct_tag = tupleHash("legx/id-distinct/v1", [utf8(dealId), X]), X = utf8(N_side) for zkpassport or
 * SHA-256(DG1) for nfc-chip. Equal tags on the two sides mean one person; the tag links only within one deal.
 * Source: DESIGN.md 6.17 IDS_DISTINCT; build/DECISIONS.md OD-29
 */
export const distinctTag = (dealId: string, x: Uint8Array): Uint8Array =>
  tupleHash('legx/id-distinct/v1', [utf8ToBytes(dealId), x]);

/**
 * The lawyer's nonce is single use (DESIGN 6.15). The lawyer console and the evidence service keep the set of used
 * nonces (lowercase hex; tasks 3.4 and 4.4); this is only the pure check.
 */
export function checkFreshNonce(
  nonce: Uint8Array,
  used: ReadonlySet<string>,
): { readonly ok: true } | { readonly ok: false; readonly code: 'NONCE_LENGTH' | 'NONCE_REUSED' } {
  if (nonce.length !== 32) return { ok: false, code: 'NONCE_LENGTH' };
  return used.has(bytesToHex(nonce)) ? { ok: false, code: 'NONCE_REUSED' } : { ok: true };
}

// ---------- configuration ----------

declare const CONFIG: unique symbol;
/** Built only by `attestConfig`, so a limit above 24 hours cannot reach the verifier. */
export type AttestConfig = { readonly maxAgeSeconds: number; readonly [CONFIG]: true };
const DEFAULT_MAX_AGE_SECONDS = 3600;
const MAX_AGE_LIMIT_SECONDS = 86_400;

/** Freshness by ledger time: 1 hour by default, at most 24 hours (DESIGN 6.15). Throws a RangeError otherwise. */
export function attestConfig({ maxAgeSeconds = DEFAULT_MAX_AGE_SECONDS } = {}): AttestConfig {
  if (!Number.isInteger(maxAgeSeconds) || maxAgeSeconds <= 0) throw new RangeError('FRESHNESS_LIMIT_INVALID');
  if (maxAgeSeconds > MAX_AGE_LIMIT_SECONDS) throw new RangeError('FRESHNESS_LIMIT_TOO_HIGH');
  return Object.freeze({ maxAgeSeconds }) as AttestConfig;
}
const DEFAULT_CONFIG = attestConfig();

// ---------- inputs and results ----------

export interface AttestDeal {
  readonly id: string;
  readonly data: PublicDealData;
}
export interface SealedKeys {
  /**
   * Each lawyer's enrollment key IDs (Ed25519 and ML-DSA-65), from the pinned key directory of that lawyer's slot
   * (DESIGN 6.3; the ML-DSA keys are bound into the seal by pqKeyHash_LA and pqKeyHash_LB, 6.13).
   */
  readonly lawyerKeyIds: Readonly<Record<Side, readonly string[]>>;
  readonly registry: KeyRegistry;
}
export interface LedgerRecord {
  /** Uppercase hex, as rippled returns it. */
  readonly hash: string;
  /** close_time, Ripple epoch seconds. */
  readonly closeTime: number;
}
interface CommonInput {
  /** The envelope exactly as stored (embedded byte for byte in `passport.verified` or `identity.onboarded`). */
  readonly envelope: Envelope;
  /** The side the gate is checking. */
  readonly side: Side;
  readonly deal: AttestDeal;
  readonly sealedKeys: SealedKeys;
  /** The current validated ledger close_time, Ripple epoch seconds. Never a local clock. */
  readonly now: number;
  /** Production (the default) refuses Sepolia roots, mock identifiers and dev mode (DESIGN 6.10). */
  readonly profile?: Profile;
}
export interface AttestationInput extends CommonInput {
  /** Validated ledger history by index; validated history does not change. */
  readonly ledgerLookup: (index: number) => LedgerRecord | undefined;
  readonly config?: AttestConfig;
  /** zkpassport: the proof bytes stored in the evidence log for this attestation. */
  readonly zkProof?: Uint8Array | undefined;
}
export type OnboardingInput = CommonInput;

export type AttestCode =
  | 'WRONG_PAYLOAD_TYPE'
  | `ENVELOPE_INVALID:${HybridCode}`
  | 'PAYLOAD_MALFORMED'
  | 'NONCE_LENGTH'
  | 'WRONG_SIGNER'
  | 'WRONG_SIDE'
  | 'DEAL_INVALID'
  | 'WRONG_DEAL'
  | 'COMMITMENT_MISMATCH'
  | 'METHOD_UNKNOWN'
  | 'METHOD_NOT_ALLOWED'
  | 'METHOD_MISMATCH'
  | 'CHECKS_SHAPE_WRONG'
  | 'PRESENCE_MISSING'
  | 'PRESENCE_INVALID'
  | 'ANCHOR_UNKNOWN'
  | 'ANCHOR_MISMATCH'
  | 'STALE'
  | `CHECK_FALSE:${string}`
  | TrustCode
  | 'PROOF_MISSING'
  | 'PROOF_HASH_MISMATCH'
  | ProofBindingCode
  | 'CHIP_AUTH_REQUIRED'
  | 'SLOT_PUB_MISMATCH'
  | 'DISTINCT_TAG_MISMATCH';
export type AttestResult =
  | { readonly ok: true; readonly method: Method }
  | { readonly ok: false; readonly code: AttestCode };

class Refused extends Error {
  readonly code: AttestCode;
  constructor(code: AttestCode) {
    super(code);
    this.code = code;
  }
}
const refuse = (code: AttestCode): never => {
  throw new Refused(code);
};
const run = (rules: () => Method): AttestResult => {
  try {
    return { ok: true, method: rules() };
  } catch (e) {
    if (e instanceof Refused) return { ok: false, code: e.code };
    return { ok: false, code: 'PAYLOAD_MALFORMED' }; // hostile input that slipped past a shape check: fail closed
  }
};

// ---------- small shape helpers ----------

type Obj = Record<string, unknown>;
const isObj = (x: unknown): x is Obj => typeof x === 'object' && x !== null && !Array.isArray(x);
const HEX32 = /^[0-9a-f]{64}$/;
const UHEX32 = /^[0-9A-F]{64}$/;
const isUint32 = (x: unknown, min: number) =>
  Number.isInteger(x) && (x as number) >= min && (x as number) <= 0xffffffff;
const UUID7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
/** Keys exactly `required` plus any of `optional`, nothing else. */
const hasKeys = (o: Obj, required: readonly string[], optional: readonly string[] = []) =>
  required.every((k) => Object.hasOwn(o, k)) &&
  Object.keys(o).every((k) => required.includes(k) || optional.includes(k));

// ---------- the shared rules ----------

/** Which methods each sealed identityPolicy allows (DESIGN 6.10, 6.15). */
const POLICY_ALLOWS: Readonly<Record<string, readonly Method[]>> = {
  zk: ['zkpassport'],
  'zk-or-chip': ['zkpassport', 'nfc-chip'],
  chip: ['nfc-chip'],
};

/**
 * The envelope rules both attestation kinds share: the attest payloadType; a valid hybrid envelope (Ed25519 and
 * ML-DSA-65, DESIGN 6.13) whose keys are valid at `now`; a JSON object payload. Returns the payload and key IDs.
 * Source: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md (v1.0.2)
 */
function openEnvelope(i: CommonInput): { p: Obj; keyIds: readonly string[] } {
  if (!isObj(i.envelope) || i.envelope.payloadType !== ATTEST_PAYLOAD_TYPE) refuse('WRONG_PAYLOAD_TYPE');
  const v = verifyHybrid(i.envelope, i.sealedKeys.registry, i.now);
  if (!v.ok) return refuse(`ENVELOPE_INVALID:${v.code}`);
  const p: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(v.payload));
  if (!isObj(p)) return refuse('PAYLOAD_MALFORMED');
  return { p, keyIds: [v.keyIds.ed25519, v.keyIds.mlDsa65] };
}

/** Right signer: side A by lawyer A, side B by lawyer B, both signatures (DESIGN 6.15; 10.1 "A lawyer attests the other side's client"). */
function signerRule(i: CommonInput, p: Obj, keyIds: readonly string[]) {
  const own = i.sealedKeys.lawyerKeyIds[i.side];
  if (p.checked_by_role !== `lawyer${i.side}` || !keyIds.every((k) => own.includes(k))) refuse('WRONG_SIGNER');
  if (p.side !== i.side) refuse('WRONG_SIDE');
}

/** Allowed method: allowed by the sealed identityPolicy, and equal to the sealed idMethod_side (DESIGN 6.15). */
function methodRule(i: CommonInput, method: unknown): Method {
  if (method !== 'zkpassport' && method !== 'nfc-chip') return refuse('METHOD_UNKNOWN');
  if (!POLICY_ALLOWS[i.deal.data.identityPolicy]?.includes(method)) refuse('METHOD_NOT_ALLOWED');
  if (method !== (i.side === 'A' ? i.deal.data.idMethodA : i.deal.data.idMethodB)) refuse('METHOD_MISMATCH');
  return method;
}

const sealedCommitment = (i: CommonInput) => (i.side === 'A' ? i.deal.data.commitmentA : i.deal.data.commitmentB);

/**
 * The checks object has the method's shape: only its keys, its required fields present, and every boolean field a
 * boolean or absent (an absent check counts as false, so it fails as CHECK_FALSE, P1.9-17).
 */
function checksShape(checks: unknown, shape: ChecksShape): Obj {
  const booleans = [...shape.booleans, ...(shape.optionalBooleans ?? [])];
  if (!isObj(checks) || !hasKeys(checks, shape.required, [...booleans, ...(shape.records ?? [])])) {
    return refuse('CHECKS_SHAPE_WRONG');
  }
  for (const k of booleans) if (k in checks && typeof checks[k] !== 'boolean') refuse('CHECKS_SHAPE_WRONG');
  return checks;
}
function allTrue(checks: Obj, names: readonly string[]) {
  for (const n of names) if (checks[n] !== true) refuse(`CHECK_FALSE:${n}`);
}

interface ChecksShape {
  /** Checks that must be true. */
  readonly booleans: readonly string[];
  /** Non-boolean fields that must be present; the method rules check their content. */
  readonly required: readonly string[];
  /** Checks that may be absent; if present, false fails like a required one. */
  readonly optionalBooleans?: readonly string[];
  /** The zero-knowledge record fields: checked as one record (ZK_RECORD_INCOMPLETE), so they may be absent here. */
  readonly records?: readonly string[];
}
const CHIP_SHAPE: ChecksShape = {
  booleans: [
    'sod_signature_valid',
    'ds_cert_chains_to_csca',
    'dg1_hash_in_sod',
    'document_not_expired',
    'commitment_opens',
  ],
  required: ['chip_authentication', 'chip_auth_available'],
  optionalBooleans: ['face_match'],
};
const ZK_RECORD_KEYS = ['proof_sha256', 'trust'];
const ZK_RELEASE_SHAPE: ChecksShape = {
  booleans: [
    'proof_verified',
    'identifier_matches',
    'bound_value_is_presence_msg',
    'document_not_expired',
    'face_match_passed',
  ],
  required: [],
  records: ZK_RECORD_KEYS,
};
const ZK_ONBOARDING_SHAPE: ChecksShape = {
  booleans: ['proof_verified', 'bound_value_matches', 'expiry_after_cancel_plus_30d', 'age_over_18'],
  required: ['scope', 'domain', 'unique_identifier'],
  records: ZK_RECORD_KEYS,
};

/**
 * The nfc-chip rules: every check true, a known chip_authentication value, and not "none" when the console found
 * DG14 or DG15 (`chip_auth_available`), so a cloned chip without its private key fails (OD-22, OD-23).
 * Source: DESIGN.md 6.15; ICAO Doc 9303 Part 11 sections 6.1 (AA) and 6.2 (CA)
 * https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
 */
function chipRules(checks: unknown) {
  const c = checksShape(checks, CHIP_SHAPE);
  if (!['AA', 'CA', 'none'].includes(c.chip_authentication as string)) refuse('CHECKS_SHAPE_WRONG');
  if (typeof c.chip_auth_available !== 'boolean') refuse('CHECKS_SHAPE_WRONG');
  allTrue(c, CHIP_SHAPE.booleans);
  if (c.chip_auth_available && c.chip_authentication === 'none') refuse('CHIP_AUTH_REQUIRED');
  if (c.face_match === false) refuse('CHECK_FALSE:face_match');
}

// ---------- the zero-knowledge trust record (DESIGN 6.10) ----------

export type TrustCode = 'ZK_RECORD_INCOMPLETE' | 'DEVMODE_REFUSED' | 'SEPOLIA_REFUSED' | 'MOCK_IDENTIFIER_REFUSED';
const SEPOLIA_CHAIN_ID = 11155111;
const ETH_HASH = /^0x[0-9a-f]{64}$/;
/** A string that matches, never a coerced value (I-24: `String(["0.21.1"])` would pass). */
const matches = (re: RegExp, x: unknown) => typeof x === 'string' && re.test(x);
const IDENTIFIER_TYPES = ['NON_SALTED', 'SALTED', 'NON_SALTED_MOCK', 'SALTED_MOCK', 'NONE'];
const TRUST_KEYS = [
  'chain_id',
  'block_number',
  'block_hash',
  'registry_address',
  'root',
  'circuit_manifest_version',
  'vkey_hashes',
  'identifier_type',
  'dev_mode',
];

/**
 * The trust record of a recorded ZKPassport verification: all nine fields present and well formed, and in the
 * production profile no Sepolia chain (11155111), no mock identifier type and no dev mode.
 * Source: DESIGN.md 6.10 and 6.15 (trust record); contracts `ZkTrustRecord`
 */
export function checkTrustRecord(trust: unknown, profile: Profile): { ok: true } | { ok: false; code: TrustCode } {
  const t = isObj(trust) ? trust : {};
  const complete =
    hasKeys(t, TRUST_KEYS) &&
    Number.isSafeInteger(t.chain_id) &&
    (t.chain_id as number) >= 1 &&
    Number.isSafeInteger(t.block_number) &&
    (t.block_number as number) >= 0 &&
    matches(ETH_HASH, t.block_hash) &&
    matches(/^0x[0-9a-f]{40}$/, t.registry_address) &&
    matches(ETH_HASH, t.root) &&
    matches(/^[0-9]+\.[0-9]+\.[0-9]+$/, t.circuit_manifest_version) &&
    Array.isArray(t.vkey_hashes) &&
    t.vkey_hashes.length >= 1 &&
    t.vkey_hashes.length <= 16 &&
    t.vkey_hashes.every((h) => matches(ETH_HASH, h)) &&
    IDENTIFIER_TYPES.includes(t.identifier_type as string) &&
    typeof t.dev_mode === 'boolean';
  if (!complete) return { ok: false, code: 'ZK_RECORD_INCOMPLETE' };
  if (profile === 'production') {
    if (t.dev_mode) return { ok: false, code: 'DEVMODE_REFUSED' };
    if (t.chain_id === SEPOLIA_CHAIN_ID) return { ok: false, code: 'SEPOLIA_REFUSED' };
    if (String(t.identifier_type).endsWith('_MOCK')) return { ok: false, code: 'MOCK_IDENTIFIER_REFUSED' };
  }
  return { ok: true };
}

/**
 * ZKPassport's scope hashes: the first 31 bytes of SHA-256 of the UTF-8 string, one BN254 field element.
 * Source: @zkpassport/utils 0.40.0-beta.2 `getScopeHash` / `getServiceScopeHash` (sha256(...).slice(0, 31)), checked
 * in build/tmp/F2/scope.mjs against the recorded set packages/zk/fixtures/sets/alice-deal2.json
 */
const scopeField = (s: string) => `00${bytesToHex(sha256(utf8ToBytes(s)).slice(0, 31))}`;

export type ProofBindingCode = 'PROOF_UNREADABLE' | 'PROOF_NOT_BOUND' | 'PROOF_WRONG_SCOPE';
/**
 * I-S-G3: the stored proof set is this deal's release proof for this presenceMsg. The set is the JSON list of public
 * proofs (zk `proofSetBytes`). Every disclosure proof (one with committed inputs) carries public inputs 2 and 3, the
 * service scope (domain) and subscope; each must be `legx.app` and `legx/v1/<dealId>`; exactly one `bind` proof
 * must commit `custom_data = hex(presenceMsg)`. The proofs themselves are verified by the lawyer and re-verified
 * offline (3.11); the gate only refuses a set made for another deal or another presence.
 * Source: DESIGN.md 6.10 (release `custom_data = hex(presenceMsg_side)`, `scope = "legx/v1/" || dealId`), 6.15;
 * @zkpassport/utils 0.40.0-beta.2 `getServiceScopeFromDisclosureProof` (publicInputs[2]) and
 * `getServiceSubScopeFromDisclosureProof` (publicInputs[3]); public inputs lead the proof hex, 32 bytes each.
 */
export function checkProofBinding(
  proofSet: Uint8Array,
  dealId: string,
  presence: Uint8Array,
): { readonly ok: true } | { readonly ok: false; readonly code: ProofBindingCode } {
  const fail = (code: ProofBindingCode) => ({ ok: false, code }) as const;
  let set: unknown;
  try {
    set = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(proofSet));
  } catch {
    return fail('PROOF_UNREADABLE');
  }
  if (!Array.isArray(set)) return fail('PROOF_UNREADABLE');
  const disclosures = set.filter((p): p is Obj => isObj(p) && isObj(p.committedInputs));
  const scope = scopeField(zkScope(dealId));
  const domain = scopeField(ZK_DOMAIN);
  for (const p of disclosures) {
    if (!matches(/^[0-9a-f]{256,}$/, p.proof)) return fail('PROOF_UNREADABLE');
    const input = (k: number) => String(p.proof).slice(64 * k, 64 * (k + 1));
    if (input(2) !== domain || input(3) !== scope) return fail('PROOF_WRONG_SCOPE');
  }
  const bound = disclosures.map((p) => (p.committedInputs as Obj).bind).filter((b) => b !== undefined);
  const data = bound.length === 1 && isObj(bound[0]) ? bound[0].data : undefined;
  return isObj(data) && data.custom_data === bytesToHex(presence) ? { ok: true } : fail('PROOF_NOT_BOUND');
}

/** The zkpassport release rules: the recorded checks, the trust record, the stored proof's hash and binding (DESIGN 6.15). */
function zkReleaseRules(checks: unknown, i: AttestationInput, msg: Uint8Array) {
  const c = checksShape(checks, ZK_RELEASE_SHAPE);
  // OD-34: `face_match_passed` is the honest result and production needs true. Only a demo proof made in dev mode may
  // carry an explicit false (no face match ran: the headless flow); the gate adds the DEMO_NO_FACE_MATCH warning.
  const noFaceMatch =
    i.profile === 'demo' && isObj(c.trust) && c.trust.dev_mode === true && c.face_match_passed === false;
  allTrue(
    c,
    noFaceMatch ? ZK_RELEASE_SHAPE.booleans.filter((n) => n !== 'face_match_passed') : ZK_RELEASE_SHAPE.booleans,
  );
  if (!matches(HEX32, c.proof_sha256)) refuse('ZK_RECORD_INCOMPLETE');
  const trust = checkTrustRecord(c.trust, i.profile ?? 'production');
  if (!trust.ok) refuse(trust.code);
  if (!i.zkProof) return refuse('PROOF_MISSING');
  if (bytesToHex(sha256(i.zkProof)) !== c.proof_sha256) refuse('PROOF_HASH_MISMATCH');
  const bound = checkProofBinding(i.zkProof, i.deal.id, msg);
  if (!bound.ok) refuse(bound.code);
}

// ---------- verifyAttestation ----------

const BASE_KEYS = [
  'deal_id',
  'contract_root',
  'deal_seal',
  'side',
  'commitment',
  'ledger_anchor',
  'method',
  'checks',
  'lawyer_nonce',
  'checked_by_role',
  'sig_algs',
];

/**
 * Checks a PassportAttestation envelope for one side of one deal (DESIGN 6.15). The shared rules run first: signer,
 * deal binding, commitment, method, presence signature, ledger anchor and freshness; then the rules of the method.
 * Reports the first rule that fails. Never parses passport data and never throws.
 * Source: DESIGN.md 6.15 (verifyAttestation), 6.17 (PASSPORT_A_OK, PASSPORT_B_OK)
 */
export function verifyAttestation(i: AttestationInput): AttestResult {
  return run(() => {
    const { p, keyIds } = openEnvelope(i);
    if (!hasKeys(p, BASE_KEYS, ['presence_sig'])) refuse('PAYLOAD_MALFORMED');
    const anchor = p.ledger_anchor;
    if (
      !isObj(anchor) ||
      !hasKeys(anchor, ['ledger_index', 'ledger_hash']) ||
      !isUint32(anchor.ledger_index, 1) ||
      !UHEX32.test(String(anchor.ledger_hash))
    ) {
      refuse('PAYLOAD_MALFORMED');
    }
    if (typeof p.lawyer_nonce !== 'string' || !/^([0-9a-f]{2})*$/.test(p.lawyer_nonce)) refuse('PAYLOAD_MALFORMED');
    if (String(p.lawyer_nonce).length !== 64) refuse('NONCE_LENGTH');

    signerRule(i, p, keyIds);
    let seal: Uint8Array;
    try {
      seal = dealSeal(i.deal.data);
    } catch {
      return refuse('DEAL_INVALID');
    }
    if (p.deal_id !== i.deal.id || p.contract_root !== i.deal.data.contractRoot || p.deal_seal !== bytesToHex(seal)) {
      refuse('WRONG_DEAL');
    }
    if (p.commitment !== sealedCommitment(i)) refuse('COMMITMENT_MISMATCH');
    const method = methodRule(i, p.method);
    checksShape(p.checks, method === 'nfc-chip' ? CHIP_SHAPE : ZK_RELEASE_SHAPE);

    // Client present: the sealed slot key signed presenceMsg, strictly (a FROST signature is plain Ed25519).
    if (p.presence_sig === undefined || p.presence_sig === '') refuse('PRESENCE_MISSING');
    const { ledger_index: index, ledger_hash: hash } = anchor as { ledger_index: number; ledger_hash: string };
    const msg = presenceMsg(seal, i.side, hexToBytes(hash), hexToBytes(String(p.lawyer_nonce)));
    const sig = typeof p.presence_sig === 'string' && /^[0-9a-f]{128}$/.test(p.presence_sig) ? p.presence_sig : '';
    const xPub = i.side === 'A' ? i.deal.data.xPubA : i.deal.data.xPubB;
    if (!sig || !verifyXrplKeySig(xPub, msg, sig)) refuse('PRESENCE_INVALID');

    // Fresh by ledger time: the anchor is in validated history, and at most maxAge older than the current close_time.
    const ledger = i.ledgerLookup(index);
    if (!ledger) refuse('ANCHOR_UNKNOWN');
    if (ledger?.hash !== hash) refuse('ANCHOR_MISMATCH');
    const age = i.now - (ledger?.closeTime ?? Number.NaN);
    if (!(age >= 0 && age <= (i.config ?? DEFAULT_CONFIG).maxAgeSeconds)) refuse('STALE');

    if (method === 'nfc-chip') chipRules(p.checks);
    else zkReleaseRules(p.checks, i, msg);
    return method;
  });
}

// ---------- verifyOnboarding ----------

const ONBOARDING_KEYS = [
  'deal_id',
  'contract_root',
  'side',
  'slot_pub',
  'commitment',
  'disclosure_box_sha256',
  'distinct_tag',
  'method',
  'checks',
  'checked_by_role',
  'sig_algs',
];

/**
 * Checks an `identity.onboarded` attestation (DESIGN 6.17 ONBOARDING_OK): signed by the client's own lawyer, this
 * deal, the sealed C_side, a method allowed by the policy and equal to the sealed idMethod_side; for nfc-chip every
 * check true; for zkpassport the recorded booleans and the trust record. The zero-knowledge specifics (scope, domain,
 * bound value, identifier, proof hash) are task 1.17's `checkZkResult`.
 * Source: DESIGN.md 6.10 (onboarding), 6.17 (ONBOARDING_OK), 8.1 (`identity.onboarded`)
 */
export function verifyOnboarding(i: OnboardingInput): AttestResult {
  return run(() => {
    const { p, keyIds } = openEnvelope(i);
    if (!hasKeys(p, ONBOARDING_KEYS) || typeof p.deal_id !== 'string' || !UUID7.test(p.deal_id))
      refuse('PAYLOAD_MALFORMED');
    signerRule(i, p, keyIds);
    if (p.deal_id !== i.deal.id || p.contract_root !== i.deal.data.contractRoot) refuse('WRONG_DEAL');
    if (p.commitment !== sealedCommitment(i)) refuse('COMMITMENT_MISMATCH');
    if (p.slot_pub !== (i.side === 'A' ? i.deal.data.xPubA : i.deal.data.xPubB)) refuse('SLOT_PUB_MISMATCH');
    if (!matches(HEX32, p.distinct_tag)) refuse('PAYLOAD_MALFORMED');
    const method = methodRule(i, p.method);
    if (method === 'nfc-chip') {
      chipRules(p.checks);
    } else {
      const c = checksShape(p.checks, ZK_ONBOARDING_SHAPE);
      allTrue(c, ZK_ONBOARDING_SHAPE.booleans);
      const trust = checkTrustRecord(c.trust, i.profile ?? 'production');
      if (!trust.ok) refuse(trust.code);
      // The zero-knowledge tag follows from the signed identifier, so the gate recomputes it (OD-29).
      if (!matches(/^[0-9]{1,78}$/, c.unique_identifier)) refuse('CHECKS_SHAPE_WRONG');
      const tag = distinctTag(i.deal.id, utf8ToBytes(String(c.unique_identifier)));
      if (p.distinct_tag !== bytesToHex(tag)) refuse('DISTINCT_TAG_MISMATCH');
    }
    return method;
  });
}
