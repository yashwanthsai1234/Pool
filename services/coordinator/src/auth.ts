// Hybrid request-signature authentication (OD-5, DESIGN 8.10). The caller signs
// tupleHash("legx/api-request/v1", [method, path, SHA-256(body), nonce32, uint32_be(ledgerIndex)]) with both halves
// of a pinned enrollment key. The server checks the key against the deal's rows, refuses a reused nonce and a ledger
// index more than 20 ledgers old. It runs on the RAW body bytes, in the Fastify handler, before oRPC sees anything.
// Source: https://fastify.dev/docs/latest/Reference/ContentTypeParser/ (parseAs buffer keeps the exact bytes)
// Source: https://orpc.dev/docs/adapters/fastify (the oRPC adapter would bypass Fastify's body parsing)
import {
  API_AUTH_HEADER,
  API_MAX_LEDGER_AGE,
  API_REQUEST_TAG,
  ApiAuth,
  type AuthRule,
  PRIMARY_HOLDER_ROLES,
} from '@legx/contracts/api';
import type { MlDsaContext } from '@legx/contracts/ports';
import type { Role, Slot } from '@legx/contracts/values';
import { bytesToHex, sha256, tupleHash, utf8ToBytes } from '@legx/core/dealcore';
import { fromBase64Strict, mldsaVerify } from '@legx/core/pq';
import { KeyNotRecorded } from '@legx/db';
import { ed25519 } from '@noble/curves/ed25519.js';
import type { CoordinatorDeps } from './deps.ts';
import { forbidden, unauthorized } from './errors.ts';
import { ED_SUFFIX, PQ_SUFFIX, pairIdOf, ROLE_OF_SLOT } from './keys.ts';

/** The ML-DSA context of API requests (DESIGN 8.10; OD-5). */
const API_CONTEXT = API_REQUEST_TAG satisfies MlDsaContext;
/** A client may be at most this many ledgers ahead of our validated ledger (its view can run slightly ahead of ours). */
export const API_MAX_LEDGER_AHEAD = 2;

export type Principal =
  /** A primary holder of a slot (OD-17): it acts as the slot's party or lawyer. */
  | { readonly kind: 'deal'; readonly dealId: string; readonly role: Role; readonly pairId: string }
  /** Any holder of a slot, on a `share-holder` route only (the FROST relay): never the party or the lawyer. */
  | {
      readonly kind: 'holder';
      readonly dealId: string;
      readonly slot: Slot;
      readonly holderRole: string;
      readonly pairId: string;
    }
  | { readonly kind: 'lawyer'; readonly pairId: string }
  | { readonly kind: 'enrolled'; readonly pairId: string }
  /** The projector dashboard's pinned key (OD-31): read routes and the live feed only. */
  | { readonly kind: 'observer'; readonly pairId: string };

/** Holder roles that act as the party or the lawyer of their slot (OD-17; DESIGN 6.4, 8.10). */
export const isPrimaryHolder = (holderRole: string): boolean =>
  (PRIMARY_HOLDER_ROLES as readonly string[]).includes(holderRole);

export interface RawRequest {
  readonly method: string;
  /** pathname + search exactly as sent (OD-8). */
  readonly path: string;
  readonly body: Uint8Array;
  readonly header: string | undefined;
  /** The dealId named by the route, when it has one. */
  readonly dealId: string | undefined;
}

const u32be = (n: number) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);

/** The message both signatures cover. Source: DESIGN 8.10; OD-5, OD-8. */
export function apiRequestMessage(
  method: string,
  path: string,
  body: Uint8Array,
  nonceHex: string,
  ledgerIndex: number,
): Uint8Array {
  return tupleHash(API_REQUEST_TAG, [
    utf8ToBytes(method),
    utf8ToBytes(path),
    sha256(body),
    new Uint8Array(Buffer.from(nonceHex, 'hex')),
    u32be(ledgerIndex),
  ]);
}

export async function authenticate(deps: CoordinatorDeps, rule: AuthRule, req: RawRequest): Promise<Principal> {
  let parsed: ReturnType<typeof ApiAuth.safeParse>;
  try {
    parsed = ApiAuth.safeParse(JSON.parse(req.header ?? ''));
  } catch {
    throw unauthorized('auth_malformed', `missing or malformed ${API_AUTH_HEADER} header`);
  }
  if (!parsed.success) throw unauthorized('auth_malformed', `malformed ${API_AUTH_HEADER} header`);
  const { nonce, ledgerIndex, signatures } = parsed.data;
  const [edSig, pqSig] = signatures;

  const validated = await deps.ledger.validatedLedger();
  if (ledgerIndex < validated.ledgerIndex - API_MAX_LEDGER_AGE)
    throw unauthorized('stale_ledger_index', `ledger index is more than ${API_MAX_LEDGER_AGE} ledgers old`);
  if (ledgerIndex > validated.ledgerIndex + API_MAX_LEDGER_AHEAD)
    throw unauthorized('future_ledger_index', 'ledger index is ahead of the validated ledger');

  const edPair = pairIdOf(edSig.keyid, 'ed25519');
  const pqPair = pairIdOf(pqSig.keyid, 'ml-dsa-65');
  if (edPair === undefined || edPair !== pqPair)
    throw unauthorized('auth_key_unknown', `key ids must be <pair>${ED_SUFFIX} and <pair>${PQ_SUFFIX} of one pair`);

  const key = await resolveKey(deps, edPair, validated.closeTime);
  const msg = apiRequestMessage(req.method, req.path, req.body, nonce, ledgerIndex);
  const edBytes = fromBase64Strict(edSig.sig);
  const pqBytes = fromBase64Strict(pqSig.sig);
  // Strict RFC 8032 verification (zip215: false), a hard rule (IMPLEMENTATION 1.3).
  const edOk =
    edBytes !== undefined &&
    key.ed25519.length === 32 &&
    edBytes.length === 64 &&
    ed25519.verify(edBytes, msg, key.ed25519, { zip215: false });
  const pqOk = pqBytes !== undefined && mldsaVerify('ml-dsa-65', key.mlDsa65, msg, pqBytes, API_CONTEXT);
  if (!edOk || !pqOk) throw unauthorized('bad_signature', 'request signature does not verify');

  // Only a verified request may burn a nonce, so a stranger cannot use up someone else's.
  if (!(await deps.db.repos.usedNonces.consume(nonce, edPair, ledgerIndex)))
    throw unauthorized('nonce_reused', 'this nonce was already used');

  return authorize(rule, key, edPair, req.dealId);
}

type ResolvedKey =
  | {
      readonly kind: 'deal';
      readonly ed25519: Uint8Array;
      readonly mlDsa65: Uint8Array;
      readonly dealId: string;
      readonly slot: Slot;
      readonly holderRole: string;
    }
  | { readonly kind: 'lawyer' | 'observer'; readonly ed25519: Uint8Array; readonly mlDsa65: Uint8Array };

async function resolveKey(deps: CoordinatorDeps, pairId: string, closeTime: number): Promise<ResolvedKey> {
  try {
    const row = await deps.db.repos.enrollmentKeys.getUsable(pairId);
    if (closeTime < row.valid_from || (row.valid_to !== undefined && closeTime > row.valid_to))
      throw unauthorized('key_not_valid', 'enrollment key is outside its validity window');
    const mlDsa65 = fromBase64Strict(row.mldsa65_pub);
    if (!mlDsa65) throw unauthorized('auth_key_unknown', 'stored key is malformed');
    return {
      kind: 'deal',
      ed25519: new Uint8Array(Buffer.from(row.ed25519_pub, 'hex')),
      mlDsa65,
      dealId: row.deal_id,
      slot: row.slot as Slot,
      holderRole: row.holder_role,
    };
  } catch (e) {
    if (!(e instanceof KeyNotRecorded)) throw e;
    const lawyer = deps.lawyerKeys(pairId);
    if (lawyer) return { kind: 'lawyer', ...lawyer };
    const observer = deps.observerKeys?.(pairId);
    if (observer) return { kind: 'observer', ...observer };
    throw unauthorized('auth_key_unknown', 'unknown enrollment key');
  }
}

/**
 * The party role comes from the slot AND the holder role (I-S-A1): only a primary holder acts as the party or the
 * lawyer. The recovery agent, the firm HSM and the partner hold one share each and act only through the FROST relay
 * (`share-holder` routes) and their own services (DESIGN 6.4, 8.10). Source: DESIGN 6.4 table; OD-17; OD-31.
 */
export function authorize(
  rule: AuthRule,
  key: ResolvedKey,
  pairId: string,
  routeDealId: string | undefined,
): Principal {
  const callers: readonly string[] = rule.callers;
  if (key.kind === 'observer') {
    if (callers.includes('observer')) return { kind: 'observer', pairId };
    throw forbidden('role_not_allowed', 'the observer key may only read');
  }
  if (key.kind !== 'deal') {
    if (callers.includes('lawyer')) return { kind: 'lawyer', pairId };
    throw forbidden('role_not_allowed', 'this key may not call this route');
  }
  if (routeDealId === undefined) {
    if (callers.includes('enrolled')) return { kind: 'enrolled', pairId };
    throw forbidden('role_not_allowed', 'this route needs a deal');
  }
  if (key.dealId !== routeDealId) throw forbidden('wrong_deal', 'this key belongs to another deal');
  const role = ROLE_OF_SLOT[key.slot];
  if (isPrimaryHolder(key.holderRole) && callers.includes(role))
    return { kind: 'deal', dealId: key.dealId, role, pairId };
  if (callers.includes('share-holder'))
    return { kind: 'holder', dealId: key.dealId, slot: key.slot, holderRole: key.holderRole, pairId };
  throw forbidden('role_not_allowed', `holder ${key.holderRole} of slot ${key.slot} may not call this route`);
}

/**
 * May this authenticated caller read the deal's live feed (DESIGN 8.10; OD-31)? A primary holder of the deal, or the
 * observer key. Service holders never read the feed.
 */
export async function canReadDeal(deps: Pick<CoordinatorDeps, 'db'>, p: Principal, dealId: string): Promise<boolean> {
  if (p.kind === 'observer') return true;
  if (p.kind === 'deal') return p.dealId === dealId;
  if (p.kind !== 'enrolled') return false; // a lawyer directory key belongs to no deal until it is enrolled in one
  try {
    const row = await deps.db.repos.enrollmentKeys.getUsable(p.pairId);
    return row.deal_id === dealId && isPrimaryHolder(row.holder_role);
  } catch (e) {
    if (e instanceof KeyNotRecorded) return false;
    throw e;
  }
}

export { bytesToHex };
