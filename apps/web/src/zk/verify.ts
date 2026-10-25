// What the party app posts, and what the client's own lawyer's console checks. The proof goes to the server's ZK
// route (3.11, 3.7), but the disclosed name, birth date and nationality never do: they are sealed to the lawyer.
// Source: DESIGN 6.10 ("Who verifies"), 6.13 (X-Wing), IMPLEMENTATION 4.8
import { ZK_DOMAIN, type ZkVerification, type ZkVerifyRequest } from '@legx/contracts/records';
import type { Profile, Side } from '@legx/core/attest';
import { bytesToHex } from '@legx/core/dealcore';
import {
  checkZkResult,
  type Disclosure,
  publicProofSet,
  sealDisclosure,
  sealSalt,
  trustRecordOf,
  type ZkExpectation,
  zkScope,
} from '@legx/core/zkIdentity';
import type { ApiClient } from '../lib/api.ts';
import { checkAnchorAge, type LawyerNonces, type ZkWebCode } from './policy.ts';
import { boundValueOf, type ReleaseInput } from './request.ts';
import type { ZkOutcome } from './sdk.ts';

const SEPOLIA_CHAIN_ID = 11155111; // the test registry, refused in production (DESIGN 6.10)
const DISCLOSED = ['firstname', 'lastname', 'birthdate', 'nationality'] as const;

/** The disclosed values of the query result, and the result with them removed (what may leave the phone openly). */
export function splitDisclosure(queryResult: Record<string, unknown>) {
  const facts: Record<string, unknown> = {};
  const rest: Record<string, unknown> = { ...queryResult };
  for (const key of DISCLOSED) {
    const entry = queryResult[key] as { disclose?: { result?: unknown } } | undefined;
    if (entry?.disclose && 'result' in entry.disclose) {
      facts[key] = entry.disclose.result;
      const { disclose: { result: _sealed, ...disclose } = {}, ...others } = entry as Record<
        string,
        Record<string, unknown>
      >;
      rest[key] = { ...others, disclose };
    }
  }
  return { facts, rest };
}

/** The ZK route request: public proofs only, domain `legx.app`, scope of the deal. */
export function submissionOf(
  stage: 'onboarding' | 'release',
  dealId: string,
  devMode: boolean,
  o: ZkOutcome,
): ZkVerifyRequest {
  return {
    stage,
    domain: ZK_DOMAIN,
    scope: zkScope(dealId),
    devMode,
    proofs: publicProofSet(o.proofs),
    originalQuery: o.originalQuery,
    queryResult: splitDisclosure(o.queryResult).rest,
  };
}

/** Onboarding: the disclosed facts, sealed with X-Wing to the client's own lawyer's enrollment key only. */
export async function sealOnboardingFacts(o: ZkOutcome, lawyerPub: Uint8Array, dealId: string, side: Side) {
  return sealDisclosure(splitDisclosure(o.queryResult).facts as unknown as Disclosure, lawyerPub, dealId, side);
}

/** The salt: made here, kept with share 2 by the vault, and an encrypted copy for the client's own lawyer. */
export async function makeSealedSalt(lawyerPub: Uint8Array, dealId: string, side: Side) {
  const zkSalt32 = crypto.getRandomValues(new Uint8Array(32));
  return { zkSalt32, sealed: await sealSalt(zkSalt32, lawyerPub, dealId, side) };
}

export type ServerCheck =
  | { readonly ok: true; readonly verification: ZkVerification }
  | { readonly ok: false; readonly code: 'CANNOT_CHECK_NOW' };

/** Calls the ZK route. Any failure (501 today, 503, a network error) is "cannot check now": it blocks, never passes. */
export async function verifyOnServer(
  client: ApiClient,
  dealId: string,
  side: Side,
  request: ZkVerifyRequest,
  zkSalt32: Uint8Array,
): Promise<ServerCheck> {
  try {
    return {
      ok: true,
      verification: await client.zk.verify({ dealId, side, request, zkSalt32: bytesToHex(zkSalt32) }),
    };
  } catch {
    return { ok: false, code: 'CANNOT_CHECK_NOW' };
  }
}

interface ConsoleCheck {
  readonly name: string;
  readonly status: 'PASS' | 'FAIL';
}

/** Which console line each failure code belongs to; every other line passes. */
const LINE_OF: Record<string, string> = {
  ZK_RESULT_MISSING: 'Proof result',
  PROOF_NOT_VERIFIED: 'Proof verified',
  QUERY_ERRORS: 'Proof verified',
  WRONG_DOMAIN: 'Domain and scope',
  WRONG_SCOPE: 'Domain and scope',
  BOUND_VALUE_MISMATCH: 'Bound value',
  BOUND_TOO_LONG: 'Bound value',
  IDENTIFIER_MISMATCH: 'Same passport as onboarding',
  FACE_MATCH_FAILED: 'Face match',
  DOCUMENT_EXPIRED: 'Document not expired',
  EXPIRY_TOO_EARLY: 'Document not expired',
  LEDGER_STALE: 'Fresh ledger anchor',
  LEDGER_TOO_OLD: 'Fresh ledger anchor',
  NONCE_UNKNOWN: 'Lawyer nonce unused',
  NONCE_REUSED: 'Lawyer nonce unused',
  NONCE_LENGTH: 'Lawyer nonce unused',
};
const LINES = [
  'Proof verified',
  'Domain and scope',
  'Trust record',
  'Bound value',
  'Document not expired',
  'Same passport as onboarding',
  'Face match',
  'Fresh ledger anchor',
  'Lawyer nonce unused',
] as const;

export interface ConsoleVerdict {
  readonly ok: boolean;
  readonly code?: ZkWebCode | string;
  readonly checks: readonly ConsoleCheck[];
}

function verdictOf(code: string | undefined): ConsoleVerdict {
  const failing = code === undefined ? undefined : (LINE_OF[code] ?? 'Trust record');
  return {
    ok: code === undefined,
    ...(code === undefined ? {} : { code: code === 'IDENTIFIER_MISMATCH' ? 'ZK_IDENTIFIER_MISMATCH' : code }),
    checks: LINES.map((name) => ({ name, status: name === failing ? 'FAIL' : 'PASS' })),
  };
}

export interface ConsoleInput {
  readonly verification: ZkVerification | undefined;
  readonly originalQuery: Record<string, unknown> | undefined;
  readonly expectation: ZkExpectation;
  /** Release only: the lawyer's own record of the anchor and nonce, from which the bound value is recomputed. */
  readonly release?: { readonly input: ReleaseInput; readonly nonces: LawyerNonces };
}

/**
 * The console's list of checks on the adapter's output. Release: the bound value is recomputed from the lawyer's
 * nonce, the anchor must be fresh, and the nonce is consumed only after every other check passed, so the same proof
 * submitted twice fails the second time (replay). Production refuses devMode, Sepolia and mock identifiers.
 */
export function checkForConsole(i: ConsoleInput): ConsoleVerdict {
  const { release, expectation } = i;
  let expected = expectation;
  if (release) {
    const age = checkAnchorAge(release.input.ledgerCloseTime, release.input.nowLedgerTime, release.input.maxAgeSeconds);
    if (age) return verdictOf(age);
    expected = { ...expectation, boundValue: boundValueOf(release.input) };
  }
  const r = checkZkResult(i.verification, i.originalQuery, expected);
  if (!r.ok) return verdictOf(r.code);
  const replay = release?.nonces.consume(release.input.lawyerNonce);
  return verdictOf(replay);
}

export interface TrustRow {
  readonly label: string;
  readonly value: string;
  readonly status: 'PASS' | 'FAIL';
}

/** The trust record view: each field, and FAIL on the ones the production profile refuses (Sepolia, mock, devMode). */
export function trustRows(v: ZkVerification, profile: Profile): TrustRow[] {
  const t = trustRecordOf(v);
  const prod = profile === 'production';
  const row = (label: string, value: string, failing = false): TrustRow => ({
    label,
    value,
    status: failing ? 'FAIL' : 'PASS',
  });
  return [
    row('Chain', String(t.chain_id), prod && t.chain_id === SEPOLIA_CHAIN_ID),
    row('Registry root', t.root),
    row('Circuit manifest version', t.circuit_manifest_version),
    row('Verification key hashes', t.vkey_hashes.join(', ')),
    row('Identifier type', String(t.identifier_type), prod && String(t.identifier_type).includes('MOCK')),
    row('Dev mode', String(t.dev_mode), prod && t.dev_mode),
  ];
}
