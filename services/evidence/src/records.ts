// Client records view (DESIGN 8.10, OD-5, OD-8): one client's records for one deal, each with three checks (signature,
// chain position, ledger link), reachable only through a signed request from that client's pinned enrollment keys or
// their own lawyer's. Every request is authenticated the same way:
//   message = tupleHash("legx/api-request/v1", [utf8(method), utf8(path), SHA-256(body), nonce32, uint32_be(ledgerIndex)])
// signed with Ed25519 and with ML-DSA-65 (context `legx/api-request/v1`). The path is `pathname + search` as sent (OD-8).
// A reused nonce, or a ledger index more than 20 ledgers old, is refused.
// Source: DESIGN.md 8.10 "Access"; contracts `ApiAuth`, `API_REQUEST_TAG`, `API_MAX_LEDGER_AGE`

import { API_MAX_LEDGER_AGE, API_REQUEST_TAG, ApiAuth, PRIMARY_HOLDER_ROLES } from '@legx/contracts/api';
import type { LegxEvent } from '@legx/contracts/events';
import type { ClockPort, LedgerPort } from '@legx/contracts/ports';
import type { XrplHash } from '@legx/contracts/values';
import { PQ_SUFFIX, pairIdOf } from '@legx/coordinator/keys';
import { verifyClientRecords } from '@legx/core/clientRecords';
import { tupleHash } from '@legx/core/dealcore';
import { type ChainEntry, leafHashOf } from '@legx/core/evidence';
import { type KeyRegistry, verifyHybrid } from '@legx/core/hybridEnvelope';
import { fromBase64Strict, mldsaVerify } from '@legx/core/pq';
import type { Database } from '@legx/db';
import type { EnrollmentKeyRow } from '@legx/db/repos/identity';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { parseEnvelope } from './events.ts';

const utf8 = new TextEncoder();
const PRIMARY: ReadonlySet<string> = new Set(PRIMARY_HOLDER_ROLES);
/** Ahead of the validated ledger a signer may be by a ledger or two (its own view is a little newer). */
export const FUTURE_LEDGERS = 2;

export type Side = 'A' | 'B';
export type RefusalCode =
  | 'UNSIGNED'
  | 'MALFORMED'
  | 'KEY_UNKNOWN'
  | 'KEY_WRONG_DEAL'
  | 'NOT_PRIMARY_HOLDER'
  | 'KEY_NOT_PAIRED'
  | 'KEY_EXPIRED'
  | 'STALE'
  | 'FUTURE'
  | 'BAD_SIGNATURE'
  | 'REPLAY'
  | 'NOT_YOUR_SIDE';

/** 401: we do not know who is asking. 403: we know, and the answer is no. */
export class Refused extends Error {
  readonly status: 401 | 403;
  readonly code: RefusalCode;
  constructor(code: RefusalCode) {
    super(code);
    this.name = 'Refused';
    this.code = code;
    this.status = code === 'NOT_YOUR_SIDE' || code === 'KEY_WRONG_DEAL' || code === 'NOT_PRIMARY_HOLDER' ? 403 : 401;
  }
}

export interface SignedRequest {
  readonly method: string;
  /** `pathname + search` exactly as sent, no scheme, host or port (OD-8). */
  readonly path: string;
  readonly body: Uint8Array;
  /** The parsed `x-legx-auth` header, or `undefined` when the header is missing. */
  readonly auth: unknown;
}

/** The message every signed request covers. Source: DESIGN 8.10; OD-5 */
export function apiRequestMessage(
  method: string,
  path: string,
  body: Uint8Array,
  nonceHex: string,
  ledgerIndex: number,
): Uint8Array {
  const index = new Uint8Array(4);
  new DataView(index.buffer).setUint32(0, ledgerIndex);
  return tupleHash(API_REQUEST_TAG, [
    utf8.encode(method),
    utf8.encode(path),
    sha256(body),
    hexToBytes(nonceHex),
    index,
  ]);
}

export const sideOfSlot = (slot: string): Side | undefined =>
  slot === 'A' || slot === 'LA' ? 'A' : slot === 'B' || slot === 'LB' ? 'B' : undefined;

export interface AccessDeps {
  readonly db: Database;
  readonly clock: ClockPort;
}

/** Who signed the request: the pinned key row of `dealId`. Refuses (throws `Refused`) anything else. */
export async function authenticate(deps: AccessDeps, req: SignedRequest, dealId: string): Promise<EnrollmentKeyRow> {
  if (req.auth === undefined || req.auth === null) throw new Refused('UNSIGNED');
  const parsed = ApiAuth.safeParse(req.auth);
  if (!parsed.success) throw new Refused('MALFORMED');
  const { nonce, ledgerIndex, signatures } = parsed.data;
  const [edSig, pqSig] = signatures;

  const validated = await deps.clock.now();
  if (ledgerIndex < validated.ledgerIndex - API_MAX_LEDGER_AGE) throw new Refused('STALE');
  if (ledgerIndex > validated.ledgerIndex + FUTURE_LEDGERS) throw new Refused('FUTURE');

  // Until apps/server drops its `evidenceKeyIds` bridge, the legacy ids (`<pair>`, `<pair>:pq`) are accepted as well.
  const pairId = pairIdOf(edSig.keyid, 'ed25519') ?? edSig.keyid;
  if (pqSig.keyid !== pairId + PQ_SUFFIX && pqSig.keyid !== `${edSig.keyid}:pq`) throw new Refused('KEY_NOT_PAIRED');
  let key: EnrollmentKeyRow;
  try {
    key = await deps.db.repos.enrollmentKeys.getUsable(pairId);
  } catch {
    throw new Refused('KEY_UNKNOWN');
  }
  if (key.deal_id !== dealId) throw new Refused('KEY_WRONG_DEAL');
  // A service holder (recovery agent, firm HSM) is not the party: only a primary holder reads records (I-S-A1).
  if (!PRIMARY.has(key.holder_role)) throw new Refused('NOT_PRIMARY_HOLDER');
  if (validated.closeTime < key.valid_from || (key.valid_to !== undefined && validated.closeTime > key.valid_to)) {
    throw new Refused('KEY_EXPIRED');
  }

  const message = apiRequestMessage(req.method, req.path, req.body, nonce, ledgerIndex);
  const ed = fromBase64Strict(edSig.sig);
  const pq = fromBase64Strict(pqSig.sig);
  const ok =
    ed !== undefined &&
    pq !== undefined &&
    ed25519.verify(ed, message, hexToBytes(key.ed25519_pub), { zip215: false }) &&
    mldsaVerify(
      'ml-dsa-65',
      fromBase64Strict(key.mldsa65_pub) ?? new Uint8Array(),
      message,
      pq,
      API_REQUEST_TAG as never,
    );
  if (!ok) throw new Refused('BAD_SIGNATURE');

  // Only a request that passed every check burns its nonce, so strangers cannot use up a client's nonces.
  if (!(await deps.db.repos.usedNonces.consume(nonce, key.key_id, ledgerIndex))) throw new Refused('REPLAY');
  await deps.db.repos.usedNonces.pruneBelow(validated.ledgerIndex - API_MAX_LEDGER_AGE);
  return key;
}

/** Only the client of `side`, or that client's own lawyer (DESIGN 8.10). The caller is already authenticated. */
export function assertOwnSide(key: EnrollmentKeyRow, side: Side): void {
  if (sideOfSlot(key.slot) !== side) throw new Refused('NOT_YOUR_SIDE');
}

const CLIENT_OF: Record<Side, readonly string[]> = { A: ['alice', 'lawyerA'], B: ['bob', 'lawyerB'] };
const SHARED = new Set(['coordinator', 'watcher', 'verifier']);

/**
 * Whether `side` may see this record. Its own client and own lawyer, and the deal-level records of the services. Never
 * the other side's records, and never a record whose data names the other side (DQ-3.4-2).
 */
export function visibleTo(side: Side, event: LegxEvent): boolean {
  const p = event.predicate;
  const role = p.actor.role;
  if (!SHARED.has(role) && !CLIENT_OF[side].includes(role)) return false;
  const named = (p.data as { side?: unknown }).side;
  return named === undefined || named === side;
}

export interface ClientRecord {
  readonly seq: number;
  readonly leafHash: string;
  /** The exact stored bytes, never re-serialized. */
  readonly envelope: Uint8Array;
  readonly checks: {
    readonly signature: boolean;
    readonly chain: boolean;
    readonly ledger: 'linked' | 'none' | 'mismatch';
  };
}

export interface RecordsDeps extends AccessDeps {
  /** The ledger the `ledger` check reads; the check is "this transaction hash is in this validated ledger". */
  readonly ledger: LedgerPort;
  readonly registry: (dealId: string) => Promise<KeyRegistry>;
}

/** The three checks for every record of the deal (whole chain), in `seq` order. */
export async function checkDealRecords(deps: RecordsDeps, dealId: string) {
  const rows = await deps.db.repos.evidenceEvents.listAfter(dealId, -1, 100_000);
  const registry = await deps.registry(dealId);
  const at = (await deps.clock.now()).closeTime;
  const hashes = new Set<string>();
  const parsed = rows.map((r) => {
    try {
      const e = parseEnvelope(r.envelope);
      if (e.event.predicate.ledger) hashes.add(e.event.predicate.ledger.tx_hash);
      return e;
    } catch {
      return undefined;
    }
  });
  const known = new Map<string, number>();
  await Promise.all(
    [...hashes].map(async (h) => {
      const tx = await deps.ledger.tx(h as XrplHash);
      if (tx) known.set(h, tx.ledgerIndex);
    }),
  );
  const entries: ChainEntry[] = rows.map((r) => ({ envelopeBytes: r.envelope, leafHash: r.leaf_hash }));
  const checks = verifyClientRecords(entries, (env) => verifyHybrid(env, registry, at).ok, {
    ledgerIndexOf: (h) => known.get(h),
  });
  return { rows, parsed, checks };
}

/** `records.list` (DESIGN 8.10): authenticate, check the side, return that side's records with their checks. */
export async function listClientRecords(
  deps: RecordsDeps,
  req: SignedRequest,
  q: { dealId: string; side: Side },
): Promise<{ records: ClientRecord[] }> {
  assertOwnSide(await authenticate(deps, req, q.dealId), q.side);
  const { rows, parsed, checks } = await checkDealRecords(deps, q.dealId);
  const records: ClientRecord[] = [];
  for (const [i, row] of rows.entries()) {
    const ev = parsed[i];
    const c = checks[i];
    if (!ev || !c || !visibleTo(q.side, ev.event)) continue;
    records.push({
      seq: row.seq,
      leafHash: row.leaf_hash,
      envelope: row.envelope,
      checks: { signature: c.signature, chain: c.chain, ledger: c.ledger },
    });
  }
  return { records };
}

export { leafHashOf };
