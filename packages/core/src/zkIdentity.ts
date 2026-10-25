// Zero-knowledge identity checks (DESIGN 6.2, 6.10, 6.15; IMPLEMENTATION 1.17).
// Pure: no ZKPassport SDK, no network, no clock. Proof verification sits behind ZkVerifierPort (task 3.11);
// this module checks the recorded result the port returns.

import type { PublicDealData } from '@legx/contracts/deal';
import { ZK_DOMAIN, type ZkTrustRecord, type ZkVerification } from '@legx/contracts/records';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { checkTrustRecord, type Method, type Profile, type TrustCode, zkScope } from './attest.ts';
import { dealSeal, mth, tupleHash } from './dealcore.ts';
import { PACKAGE_SUITES, type SealedPackage, XWING_SUITE } from './pq.ts';

export { zkScope };

export type ZkCheck<C extends string = ZkCode> = { readonly ok: true } | { readonly ok: false; readonly code: C };

export type ZkCode = 'BOUND_TOO_LONG';

/** `custom_data` limit: the SDK caps the bound blob at 509 bytes, minus 1 tag byte and 2 length bytes. */
export const BIND_MAX_BYTES = 506;

/**
 * C_side = tupleHash("legx/zk-identity/v1", [zkSalt32, utf8(N_side)]), N_side being the SDK's decimal string.
 * Source: DESIGN 6.2 and the encoding rules of DESIGN 6
 */
export function zkIdentityCommitment(zkSalt32: Uint8Array, identifier: string): Uint8Array {
  if (zkSalt32.length !== 32) throw new Error('zkSalt32 must be 32 bytes');
  if (identifier === '') throw new Error('identifier must not be empty');
  return tupleHash('legx/zk-identity/v1', [zkSalt32, utf8ToBytes(identifier)]);
}

/**
 * The onboarding `custom_data`: hex(tupleHash("legx/zk-onboard/v1", [contractRoot, slotPub_side])).
 * Source: DESIGN 6.10 (two proofs per client); slot keys in the 33-byte XRPL form (DESIGN 6 encoding rules)
 */
export function onboardingBoundValue(contractRoot: Uint8Array, slotPub: Uint8Array): string {
  if (contractRoot.length !== 32) throw new Error('contractRoot must be 32 bytes');
  if (slotPub.length !== 33 || slotPub[0] !== 0xed) throw new Error('slotPub must be a 33-byte ED-prefixed key');
  return bytesToHex(tupleHash('legx/zk-onboard/v1', [contractRoot, slotPub]));
}

/** The release `custom_data`: hex(presenceMsg_side) (DESIGN 6.10, 6.15). */
export function releaseBoundValue(presenceMsg: Uint8Array): string {
  if (presenceMsg.length !== 32) throw new Error('presenceMsg must be 32 bytes');
  return bytesToHex(presenceMsg);
}

/**
 * Run before a request is shown as a QR code: the SDK checks the bound length only when the phone proves.
 * Source: @zkpassport/utils 0.40.0-beta.2 formatBoundData ("Data is too long: 603 > 509"; tag + 2-byte length)
 */
export function checkBindLength(value: string): ZkCheck<'BOUND_TOO_LONG'> {
  return utf8ToBytes(value).length <= BIND_MAX_BYTES ? { ok: true } : { ok: false, code: 'BOUND_TOO_LONG' };
}

// ---------- the recorded result (ZkVerifierPort output, IMPLEMENTATION P1.2-08) ----------

export type ZkResultCode =
  | 'ZK_RESULT_MISSING'
  | 'ZK_RECORD_INCOMPLETE'
  | 'TRUST_RECORD_INCOMPLETE'
  | 'WRONG_DOMAIN'
  | 'WRONG_SCOPE'
  | 'DOCUMENT_EXPIRED'
  | 'FACE_MATCH_FAILED'
  | 'QUERY_ERRORS'
  | 'PROOF_NOT_VERIFIED'
  | Exclude<TrustCode, 'ZK_RECORD_INCOMPLETE'>
  | 'BOUND_TOO_LONG'
  | 'BOUND_VALUE_MISMATCH'
  | 'EXPIRY_TOO_EARLY'
  | 'IDENTIFIER_MISMATCH';

/** What a result must show, from the deal data. The release side compares against the sealed C_side. */
export interface ZkExpectation {
  readonly stage: 'onboarding' | 'release';
  readonly dealId: string;
  readonly boundValue: string;
  /** The run profile is an input, never a global (IMPLEMENTATION 1.17 "Think"). */
  readonly profile: Profile;
  /** Onboarding: the escrow's CancelAfter in unix seconds. */
  readonly cancelAfter?: number;
  /** Release: the client's salt and the sealed C_side (hex). */
  readonly identity?: { readonly zkSalt32: Uint8Array; readonly commitment: string };
  /** Release: the deal data turns the strict face match off (O12). */
  readonly faceMatchOptional?: boolean;
}

export type ZkResultCheck =
  | { readonly ok: true; readonly identifier: string }
  | { readonly ok: false; readonly code: ZkResultCode };

const EXPIRY_MARGIN_SECONDS = 30 * 86400;

/**
 * The SDK's verdict: an expiry-date check out of its validity window means the proof does not show an unexpired
 * document; a face match error is its own reason; any other error, or `verified: false`, fails the proof.
 * Source: @zkpassport/sdk 0.19.2 checkCurrentDate ("The date used to check the validity of the ID falls out of the
 * validity period", key `date`) and checkFacematchPublicInputs (category `facematch`)
 */
function verdict(r: ZkVerification): ZkResultCode | undefined {
  const errors = Object.entries(r.queryResultErrors);
  if (errors.some(([category, checks]) => category === 'expiry_date' || 'date' in checks)) return 'DOCUMENT_EXPIRED';
  if (errors.some(([category]) => category === 'facematch')) return 'FACE_MATCH_FAILED';
  if (errors.length > 0) return 'QUERY_ERRORS';
  return r.verified ? undefined : 'PROOF_NOT_VERIFIED';
}

type Json = Readonly<Record<string, unknown>>;
const field = (q: Json, k: string): Json => (typeof q[k] === 'object' && q[k] !== null ? (q[k] as Json) : {});

/**
 * Checks one recorded verification against the deal: domain, scope (the SDK result has none, so the record holds
 * the one we requested), the SDK verdict, the trust record, the production refusals, the bound value, and per stage
 * the expiry (onboarding) or the face match and the sealed identity (release). `query` is the stored original query.
 * Source: DESIGN 6.10 ("Who verifies", "Trust anchors"), IMPLEMENTATION T-U-28, T-U-32a, P1.17-17
 */
export function checkZkResult(
  result: ZkVerification | undefined,
  query: Json | undefined,
  x: ZkExpectation,
): ZkResultCheck {
  const fail = (code: ZkResultCode): ZkResultCheck => ({ ok: false, code });
  if (!result || !query) return fail('ZK_RESULT_MISSING');
  if (!result.scope) return fail('ZK_RECORD_INCOMPLETE');
  if (result.domain !== ZK_DOMAIN) return fail('WRONG_DOMAIN');
  if (result.scope !== zkScope(x.dealId)) return fail('WRONG_SCOPE');
  const bad = verdict(result);
  if (bad) return fail(bad);
  // The nine trust fields and the production refusals, as the attestation path checks them (task 1.9).
  const trust = checkTrustRecord(trustRecordOf(result), x.profile);
  if (!trust.ok) return fail(trust.code === 'ZK_RECORD_INCOMPLETE' ? 'TRUST_RECORD_INCOMPLETE' : trust.code);
  if (result.uniqueIdentifier === null) return fail('ZK_RECORD_INCOMPLETE');
  const bound = result.committedInputs.custom_data;
  if (!checkBindLength(bound).ok) return fail('BOUND_TOO_LONG');
  if (bound !== x.boundValue || field(query, 'bind').custom_data !== x.boundValue) return fail('BOUND_VALUE_MISMATCH');
  if (x.stage === 'onboarding') {
    if (x.cancelAfter === undefined) throw new Error('onboarding needs cancelAfter');
    // gt("expiry_date", X) proves expiry > X, so X must be at least CancelAfter + 30 days (DESIGN 6.10).
    const provenAfter = Date.parse(String(field(query, 'expiry_date').gt)) / 1000;
    if (!(provenAfter >= x.cancelAfter + EXPIRY_MARGIN_SECONDS)) return fail('EXPIRY_TOO_EARLY');
    return { ok: true, identifier: result.uniqueIdentifier };
  }
  if (!x.identity) throw new Error('release needs the sealed identity');
  if (field(query, 'facematch').mode !== 'strict' && !x.faceMatchOptional) return fail('FACE_MATCH_FAILED');
  const c = zkIdentityCommitment(x.identity.zkSalt32, result.uniqueIdentifier);
  if (bytesToHex(c) !== x.identity.commitment) return fail('IDENTIFIER_MISMATCH');
  return { ok: true, identifier: result.uniqueIdentifier };
}

/** The facts a contract asks for, compared between the onboarding and the release request (P1.17-16). */
const FACT_KEYS = ['age', 'nationality', 'issuing_country', 'sanctions'] as const;
const facts = (q: Json) =>
  JSON.stringify(
    FACT_KEYS.map((k) => {
      const { disclose: _shownToLawyer, ...condition } = field(q, k);
      return [k, condition];
    }),
  );

/**
 * The release request repeats the onboarding facts (disclosures aside) and turns the strict face match on, unless
 * the deal data turns it off (O12). Source: DESIGN 6.10 (`release = request(scope).gte("age", 18) [.same facts]
 * .facematch("strict")`)
 */
export function checkReleaseQuery(
  onboarding: Json,
  release: Json,
  faceMatchOptional = false,
): ZkCheck<'RELEASE_FACTS_DIFFER' | 'FACE_MATCH_FAILED'> {
  if (facts(onboarding) !== facts(release)) return { ok: false, code: 'RELEASE_FACTS_DIFFER' };
  if (field(release, 'facematch').mode !== 'strict' && !faceMatchOptional)
    return { ok: false, code: 'FACE_MATCH_FAILED' };
  return { ok: true };
}

/** The trust record of a result in the snake_case form an attestation signs (DESIGN 6.15). */
export function trustRecordOf(r: ZkVerification): TrustRecord {
  const t = r.trust;
  return {
    chain_id: t.chainId,
    block_number: t.blockNumber,
    block_hash: t.blockHash,
    registry_address: t.registryAddress,
    root: t.root,
    circuit_manifest_version: t.circuitManifestVersion,
    vkey_hashes: t.vkeyHashes,
    identifier_type: r.uniqueIdentifierType as TrustRecord['identifier_type'],
    dev_mode: t.devMode,
  };
}
type TrustRecord = ReturnType<typeof ZkTrustRecord.parse>;

/**
 * The stored proof set without disclosed values: the disclose proof's committed inputs hold the disclosed bytes
 * in clear, so they go only into the box sealed to the client's own lawyer (DESIGN 6.10, invariant I7).
 */
export function publicProofSet<P extends { readonly committedInputs?: object }>(proofs: readonly P[]): P[] {
  return proofs.map((p) => {
    if (!p.committedInputs || !('disclose_bytes' in p.committedInputs)) return p;
    const { disclose_bytes: _sealedToLawyer, ...rest } = p.committedInputs as Record<string, unknown>;
    return { ...p, committedInputs: rest };
  });
}

// ---------- the salt and the onboarding disclosure, sealed to the client's own lawyer (DESIGN 6.2, 6.10, 6.13) ----------

const BOX_INFO = { salt: 'legx/hpke/zk-salt/v1', disclosure: 'legx/hpke/zk-disclosure/v1' } as const;
type BoxKind = keyof typeof BOX_INFO;
const boxAad = (dealId: string, side: string) =>
  tupleHash('legx/zk-box-aad/v1', [utf8ToBytes(dealId), utf8ToBytes(side)]);

// X-Wing through the task 1.16 suite table; each box kind has its own HPKE `info`, so one never opens as the other.
// Source: https://www.rfc-editor.org/rfc/rfc9180.html (single-shot Seal and Open), DESIGN 6.13
async function sealBox(
  kind: BoxKind,
  pub: Uint8Array,
  pt: Uint8Array,
  dealId: string,
  side: string,
): Promise<SealedPackage> {
  const suite = PACKAGE_SUITES[XWING_SUITE] as NonNullable<(typeof PACKAGE_SUITES)[string]>;
  return { suite: XWING_SUITE, ...(await suite.seal(pub, pt, utf8ToBytes(BOX_INFO[kind]), boxAad(dealId, side))) };
}

async function openBox(kind: BoxKind, pkg: SealedPackage, sk: Uint8Array, dealId: string, side: string) {
  const suite = Object.hasOwn(PACKAGE_SUITES, pkg.suite) ? PACKAGE_SUITES[pkg.suite] : undefined;
  if (!suite) return undefined;
  try {
    return await suite.open(sk, pkg.enc, pkg.ct, utf8ToBytes(BOX_INFO[kind]), boxAad(dealId, side));
  } catch {
    return undefined;
  }
}

/** The box digest an attestation carries (`disclosure_box_sha256`). */
export function boxDigest(pkg: SealedPackage): string {
  return bytesToHex(tupleHash('legx/zk-box/v1', [utf8ToBytes(pkg.suite), pkg.enc, pkg.ct]));
}

/** zkSalt32, sealed to the client's own lawyer (DESIGN 6.2: "a copy is encrypted to the client's own lawyer"). */
export async function sealSalt(zkSalt32: Uint8Array, lawyerPub: Uint8Array, dealId: string, side: string) {
  if (zkSalt32.length !== 32) throw new Error('zkSalt32 must be 32 bytes');
  return sealBox('salt', lawyerPub, zkSalt32, dealId, side);
}

export async function openSalt(pkg: SealedPackage, lawyerSecret: Uint8Array, dealId: string, side: string) {
  const salt = await openBox('salt', pkg, lawyerSecret, dealId, side);
  return salt?.length === 32 ? ({ ok: true, zkSalt32: salt } as const) : ({ ok: false, code: 'OPEN_FAILED' } as const);
}

/** The facts disclosed at onboarding, for the client's own lawyer only (DESIGN 6.10). */
export interface Disclosure {
  readonly firstname: string;
  readonly lastname: string;
  readonly birthdate: string;
  readonly nationality: string;
}

export async function sealDisclosure(facts: Disclosure, lawyerPub: Uint8Array, dealId: string, side: string) {
  const { firstname, lastname, birthdate, nationality } = facts;
  const pt = utf8ToBytes(JSON.stringify({ firstname, lastname, birthdate, nationality }));
  return sealBox('disclosure', lawyerPub, pt, dealId, side);
}

export async function openDisclosure(pkg: SealedPackage, lawyerSecret: Uint8Array, dealId: string, side: string) {
  const pt = await openBox('disclosure', pkg, lawyerSecret, dealId, side);
  return pt
    ? ({ ok: true, facts: JSON.parse(new TextDecoder().decode(pt)) as Disclosure } as const)
    : ({ ok: false, code: 'OPEN_FAILED' } as const);
}

// ---------- identity changes mid-deal, disputes, checkpoint input (DESIGN 6.10) ----------

const SIDE_FIELDS = {
  A: { idMethod: 'idMethodA', commitment: 'commitmentA' },
  B: { idMethod: 'idMethodB', commitment: 'commitmentB' },
} as const;
const ALL_SLOTS = ['A', 'LA', 'B', 'LB'] as const;
type SealSlot = (typeof ALL_SLOTS)[number];

/** The identity a release presents, compared with the seal: same method, same commitment. */
export function checkAgainstSeal(
  deal: PublicDealData,
  side: 'A' | 'B',
  presented: { readonly method: Method; readonly commitment: string },
): ZkCheck<'METHOD_MISMATCH' | 'COMMITMENT_MISMATCH'> {
  const f = SIDE_FIELDS[side];
  if (deal[f.idMethod] !== presented.method) return { ok: false, code: 'METHOD_MISMATCH' };
  return deal[f.commitment] === presented.commitment ? { ok: true } : { ok: false, code: 'COMMITMENT_MISMATCH' };
}

/**
 * A renewed passport, a changed identifier derivation or a switch to the chip path each need a new commitment in
 * the seal: a 4-of-4 seal update signed by every slot. Source: DESIGN 6.10 ("Changes in mid-deal")
 */
export function identityChangePlan(
  deal: PublicDealData,
  side: 'A' | 'B',
  next: { readonly method: Method; readonly commitment: string },
) {
  const f = SIDE_FIELDS[side];
  const updated: PublicDealData = { ...deal, [f.idMethod]: next.method, [f.commitment]: next.commitment };
  return {
    side,
    changes: { [f.idMethod]: next.method, [f.commitment]: next.commitment },
    oldSeal: bytesToHex(dealSeal(deal)),
    newSeal: bytesToHex(dealSeal(updated)), // throws if the policy does not allow the new method
    signers: ALL_SLOTS,
    threshold: ALL_SLOTS.length,
  } as const;
}

/** A slot that refuses the update counts like a refusal of the release-time passport check (O9): a stall. */
export function identityChangeOutcome(responses: Partial<Readonly<Record<SealSlot, 'signed' | 'refused'>>>) {
  const refusedBy = ALL_SLOTS.filter((s) => responses[s] === 'refused');
  if (refusedBy.length > 0) return { state: 'refused', refusedBy, reason: 'O9' } as const;
  const waiting = ALL_SLOTS.filter((s) => responses[s] !== 'signed');
  return waiting.length > 0 ? ({ state: 'pending', waiting } as const) : ({ state: 'applied' } as const);
}

export interface DisputeBundle {
  readonly dealId: string;
  readonly side: 'A' | 'B';
  /** The identity.onboarded payload's fields this needs. */
  readonly onboarding: {
    readonly commitment: string;
    readonly disclosure_box_sha256: string;
    readonly checks: { readonly unique_identifier: string };
  };
  readonly disclosureBox: SealedPackage;
  readonly saltBox: SealedPackage;
  /** Optional extra evidence: a new proof with the same scope (an expired or renewed passport cannot make one). */
  readonly newProof?: ZkVerification;
}

/**
 * The client's identity in a dispute comes from the onboarding disclosure and attestation in the bundle, opened
 * by the client's own lawyer; no new proof is needed. Source: DESIGN 6.10 ("Disputes")
 */
export async function disputeIdentity(b: DisputeBundle, lawyerSecret: Uint8Array) {
  if (boxDigest(b.disclosureBox) !== b.onboarding.disclosure_box_sha256)
    return { ok: false, code: 'DISCLOSURE_HASH_MISMATCH' } as const;
  const disclosed = await openDisclosure(b.disclosureBox, lawyerSecret, b.dealId, b.side);
  const salt = await openSalt(b.saltBox, lawyerSecret, b.dealId, b.side);
  if (!disclosed.ok || !salt.ok) return { ok: false, code: 'OPEN_FAILED' } as const;
  const identifier = b.onboarding.checks.unique_identifier;
  if (bytesToHex(zkIdentityCommitment(salt.zkSalt32, identifier)) !== b.onboarding.commitment)
    return { ok: false, code: 'COMMITMENT_MISMATCH' } as const;
  const id = b.newProof?.uniqueIdentifier;
  const newProof = !b.newProof ? 'absent' : id && id === identifier ? 'matches' : 'differs';
  return { ok: true, identity: disclosed.facts, identifier, newProof } as const;
}

/**
 * The recorded trust record and files as leaves of the next evidence checkpoint input, so an arbitrator can trust
 * them through the ledger anchor (DESIGN 6.10, 8.3). Each leaf is SHA-256 over its name and bytes.
 */
export function zkCheckpointInput(trust: ZkVerification['trust'], files: ReadonlyMap<string, Uint8Array>) {
  const leaves = [
    ['trust', utf8ToBytes(JSON.stringify(trust))] as const,
    ...[...files].map(([k, v]) => [`file/${k}`, v] as const),
  ]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([name, bytes]) => ({ name, sha256: sha256(bytes) }));
  const root = mth(leaves.map((l) => tupleHash('legx/zk-trust-leaf/v1', [utf8ToBytes(l.name), l.sha256])));
  return { leaves: leaves.map((l) => ({ name: l.name, sha256: bytesToHex(l.sha256) })), root: bytesToHex(root) };
}
