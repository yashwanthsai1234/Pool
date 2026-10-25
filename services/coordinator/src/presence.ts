// Passport presence relay (DESIGN 6.15; contracts `presence.*`, task 4.3). The client's own lawyer posts the request
// (method, nonce, the validated ledger it anchored on); the client's phone reads it, signs presenceMsg with the slot
// key and posts the signature; the lawyer's console reads it back and verifies it against the sealed slot key. The
// coordinator only relays: it cannot build a presence it was not given, and the console checks every byte itself.
import { sql } from 'kysely';
import { requireDeal } from './deal.ts';
import type { CoordinatorDeps } from './deps.ts';
import { conflict } from './errors.ts';
import { kyselyOf } from './frost/store.ts';

export interface PresenceRequest {
  readonly method: 'zkpassport' | 'nfc-chip';
  readonly lawyerNonce: string;
  readonly ledgerHash: string;
  readonly ledgerIndex: number;
}
export interface PresenceState {
  readonly status: 'none' | 'open' | 'signed';
  readonly request?: PresenceRequest;
  readonly signature?: string;
}

interface Row {
  method: PresenceRequest['method'];
  lawyer_nonce: string;
  ledger_hash: string;
  ledger_index: string | number;
  signature: string | null;
}

const view = (r: Row | undefined): PresenceState =>
  r
    ? {
        status: r.signature ? 'signed' : 'open',
        request: {
          method: r.method,
          lawyerNonce: r.lawyer_nonce,
          ledgerHash: r.ledger_hash,
          ledgerIndex: Number(r.ledger_index),
        },
        ...(r.signature ? { signature: r.signature } : {}),
      }
    : { status: 'none' };

async function read(deps: CoordinatorDeps, dealId: string, side: string): Promise<Row | undefined> {
  const r = await sql<Row>`SELECT method, lawyer_nonce, ledger_hash, ledger_index, signature FROM presence_request
    WHERE deal_id = ${dealId} AND side = ${side}`.execute(kyselyOf(deps.db));
  return r.rows[0];
}

/** A new request replaces the old one and clears its signature (a fresh nonce means a fresh presence). */
export async function openPresence(
  deps: CoordinatorDeps,
  dealId: string,
  side: string,
  q: PresenceRequest,
): Promise<PresenceState> {
  await requireDeal(deps.db.repos, dealId);
  await sql`INSERT INTO presence_request (deal_id, side, method, lawyer_nonce, ledger_hash, ledger_index)
    VALUES (${dealId}, ${side}, ${q.method}, ${q.lawyerNonce}, ${q.ledgerHash}, ${q.ledgerIndex})
    ON CONFLICT (deal_id, side) DO UPDATE SET method = EXCLUDED.method, lawyer_nonce = EXCLUDED.lawyer_nonce,
      ledger_hash = EXCLUDED.ledger_hash, ledger_index = EXCLUDED.ledger_index, signature = NULL`.execute(
    kyselyOf(deps.db),
  );
  return view(await read(deps, dealId, side));
}

export async function getPresence(deps: CoordinatorDeps, dealId: string, side: string): Promise<PresenceState> {
  await requireDeal(deps.db.repos, dealId);
  return view(await read(deps, dealId, side));
}

/** The signature answers exactly the open request: its nonce must match, so an answer to an old request is refused. */
export async function submitPresence(
  deps: CoordinatorDeps,
  dealId: string,
  side: string,
  lawyerNonce: string,
  signature: string,
): Promise<PresenceState> {
  const r = await sql`UPDATE presence_request SET signature = ${signature}
    WHERE deal_id = ${dealId} AND side = ${side} AND lawyer_nonce = ${lawyerNonce} AND signature IS NULL
    RETURNING side`.execute(kyselyOf(deps.db));
  if (r.rows.length === 0) throw conflict('presence_not_open', 'no open presence request with this nonce');
  return view(await read(deps, dealId, side));
}
