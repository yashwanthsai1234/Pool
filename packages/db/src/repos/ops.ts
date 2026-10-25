// release_gate, signature_request, signature, ledger_observation, watcher_cursor (DESIGN 9).
import type { Kysely } from 'kysely';
import { bin, bytes, hex } from '../bytes.ts';
import type { DB } from '../schema.ts';

export interface ReleaseGateRow {
  deal_id: string;
  leaf_hash: string;
  envelope: Uint8Array;
  ledger_index: number;
}

export class ReleaseGatesRepo {
  readonly #db: Kysely<DB>;
  constructor(db: Kysely<DB>) {
    this.#db = db;
  }
  /** Idempotent by leaf hash. The finish transaction hash goes in `release.performed`, never here by UPDATE. */
  async insert(g: ReleaseGateRow): Promise<ReleaseGateRow> {
    await this.#db
      .insertInto('release_gate')
      .values({ ...g, leaf_hash: bin(g.leaf_hash) })
      .onConflict((oc) => oc.column('leaf_hash').doNothing())
      .execute();
    return (await this.get(g.leaf_hash)) as ReleaseGateRow;
  }
  async get(leafHash: string): Promise<ReleaseGateRow | undefined> {
    const r = await this.#db
      .selectFrom('release_gate')
      .selectAll()
      .where('leaf_hash', '=', bin(leafHash))
      .executeTakeFirst();
    return r && { ...r, leaf_hash: hex(r.leaf_hash), envelope: bytes(r.envelope) };
  }
  async list(dealId: string): Promise<ReleaseGateRow[]> {
    const rows = await this.#db
      .selectFrom('release_gate')
      .selectAll()
      .where('deal_id', '=', dealId)
      .orderBy('ledger_index')
      .execute();
    return rows.map((r) => ({ ...r, leaf_hash: hex(r.leaf_hash), envelope: bytes(r.envelope) }));
  }
}

export interface SignatureRequestRow {
  request_id: string;
  deal_id: string;
  purpose: string;
  unsigned_tx: unknown;
  last_ledger: number;
  status: string;
}

export class SignatureRequestsRepo {
  readonly #db: Kysely<DB>;
  constructor(db: Kysely<DB>) {
    this.#db = db;
  }
  async insert(
    r: Omit<SignatureRequestRow, 'request_id' | 'status'> & { request_id?: string },
  ): Promise<SignatureRequestRow> {
    return await this.#db
      .insertInto('signature_request')
      .values({ ...r, unsigned_tx: JSON.stringify(r.unsigned_tx) })
      .returningAll()
      .executeTakeFirstOrThrow();
  }
  async get(requestId: string): Promise<SignatureRequestRow | undefined> {
    return await this.#db
      .selectFrom('signature_request')
      .selectAll()
      .where('request_id', '=', requestId)
      .executeTakeFirst();
  }
  async setStatus(requestId: string, status: string): Promise<void> {
    await this.#db.updateTable('signature_request').set({ status }).where('request_id', '=', requestId).execute();
  }
  async listOpen(dealId: string): Promise<SignatureRequestRow[]> {
    return await this.#db
      .selectFrom('signature_request')
      .selectAll()
      .where('deal_id', '=', dealId)
      .where('status', '=', 'open')
      .orderBy('request_id')
      .execute();
  }
}

export interface SignatureRow {
  request_id: string;
  role: string;
  signer_blob: string;
}

export class SignaturesRepo {
  readonly #db: Kysely<DB>;
  constructor(db: Kysely<DB>) {
    this.#db = db;
  }
  /** One signature per (request, role); a second one for the same role is ignored. */
  async insert(s: SignatureRow): Promise<void> {
    await this.#db
      .insertInto('signature')
      .values(s)
      .onConflict((oc) => oc.columns(['request_id', 'role']).doNothing())
      .execute();
  }
  async list(requestId: string): Promise<SignatureRow[]> {
    return await this.#db
      .selectFrom('signature')
      .selectAll()
      .where('request_id', '=', requestId)
      .orderBy('role')
      .execute();
  }
}

export interface LedgerObservationRow {
  tx_hash: string;
  ledger_index: number;
  tx_index: number;
  account: string;
  tx_type: string;
  result: string;
  meta: unknown;
}

export class LedgerObservationsRepo {
  readonly #db: Kysely<DB>;
  constructor(db: Kysely<DB>) {
    this.#db = db;
  }
  /** True when the row is new; false when the transaction was already observed (I-3.5-c). */
  async insert(o: LedgerObservationRow): Promise<boolean> {
    const r = await this.#db
      .insertInto('ledger_observation')
      .values({ ...o, tx_hash: bin(o.tx_hash), meta: JSON.stringify(o.meta) })
      .onConflict((oc) => oc.column('tx_hash').doNothing())
      .returning('tx_hash')
      .executeTakeFirst();
    return r !== undefined;
  }
  async listForAccount(account: string, fromLedger: number): Promise<LedgerObservationRow[]> {
    const rows = await this.#db
      .selectFrom('ledger_observation')
      .selectAll()
      .where('account', '=', account)
      .where('ledger_index', '>=', fromLedger)
      .orderBy('ledger_index')
      .orderBy('tx_index')
      .execute();
    return rows.map((r) => ({ ...r, tx_hash: hex(r.tx_hash) }));
  }
}

export class WatcherCursorsRepo {
  readonly #db: Kysely<DB>;
  constructor(db: Kysely<DB>) {
    this.#db = db;
  }
  async get(account: string): Promise<number | undefined> {
    const r = await this.#db
      .selectFrom('watcher_cursor')
      .select('last_validated_ledger')
      .where('account', '=', account)
      .executeTakeFirst();
    return r?.last_validated_ledger;
  }
  /** The cursor only moves forward. */
  async advance(account: string, ledger: number): Promise<void> {
    await this.#db
      .insertInto('watcher_cursor')
      .values({ account, last_validated_ledger: ledger })
      .onConflict((oc) =>
        oc.column('account').doUpdateSet((eb) => ({
          last_validated_ledger: eb.fn('greatest', [eb.ref('watcher_cursor.last_validated_ledger'), eb.val(ledger)]),
        })),
      )
      .execute();
  }
}
