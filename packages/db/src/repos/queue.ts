// outbox, used_nonce, frost_nonce_use (DESIGN 8.10, 6.4 and the Outbox section of IMPLEMENTATION 4.3).
// Source: https://www.postgresql.org/docs/18/sql-select.html#SQL-FOR-UPDATE-SHARE (SKIP LOCKED)
import { type Kysely, sql } from 'kysely';
import { bin, bytes, hex } from '../bytes.ts';
import type { DB } from '../schema.ts';

export interface OutboxRow {
  id: string;
  topic: string;
  payload: Uint8Array;
  deal_id: string | null;
  seq: number | null;
  created_at: Date;
  sent_at: Date | null;
}
export interface NewOutbox {
  topic: string;
  payload: Uint8Array;
  deal_id?: string;
  seq?: number;
}

export class OutboxRepo {
  readonly #db: Kysely<DB>;
  constructor(db: Kysely<DB>) {
    this.#db = db;
  }
  async enqueue(o: NewOutbox): Promise<string> {
    const r = await this.#db
      .insertInto('outbox')
      .values({ topic: o.topic, payload: o.payload, deal_id: o.deal_id ?? null, seq: o.seq ?? null })
      .returning('id')
      .executeTakeFirstOrThrow();
    return r.id;
  }

  /**
   * Writes a row of a deal's live feed with the deal's next seq: one gap-free sequence shared by every topic of the
   * deal (`deal.event`, `deal.state`, `signature.request`), because the feed's cursor is that seq. A transaction-scoped
   * advisory lock per deal orders concurrent writers; call it on a transaction repo, so the lock lasts until commit.
   * Source: https://www.postgresql.org/docs/18/explicit-locking.html#ADVISORY-LOCKS
   */
  async enqueueNext(dealId: string, topic: string, payload: Uint8Array): Promise<number> {
    await sql`select pg_advisory_xact_lock(hashtextextended(${`outbox:${dealId}`}, 0))`.execute(this.#db);
    const next = await this.#db
      .selectFrom('outbox')
      .select(sql<string | null>`max(seq)`.as('top'))
      .where('deal_id', '=', dealId)
      .executeTakeFirstOrThrow();
    const seq = next.top === null ? 0 : Number(next.top) + 1;
    await this.enqueue({ topic, payload, deal_id: dealId, seq });
    return seq;
  }

  /**
   * Locks up to `limit` unsent rows that no other worker holds (`FOR UPDATE SKIP LOCKED`). Call it on a transaction repo,
   * process the rows, then `markSent` in the same transaction, so a crash returns the rows to the queue.
   */
  async claim(limit: number): Promise<OutboxRow[]> {
    const rows = await this.#db
      .selectFrom('outbox')
      .selectAll()
      .where('sent_at', 'is', null)
      .orderBy('created_at')
      .orderBy('id')
      .limit(limit)
      .forUpdate()
      .skipLocked()
      .execute();
    return rows.map((r) => ({ ...r, payload: bytes(r.payload) }));
  }

  async markSent(ids: readonly string[]): Promise<void> {
    if (ids.length === 0) return;
    await this.#db.updateTable('outbox').set({ sent_at: sql`now()` }).where('id', 'in', ids).execute();
  }

  /** The live-update replay: every row of a deal after the client's last seq, by seq (IMPLEMENTATION 3.7). */
  async listAfter(dealId: string, afterSeq: number, limit = 1000): Promise<OutboxRow[]> {
    const rows = await this.#db
      .selectFrom('outbox')
      .selectAll()
      .where('deal_id', '=', dealId)
      .where('seq', '>', afterSeq)
      .orderBy('seq')
      .orderBy('id')
      .limit(limit)
      .execute();
    return rows.map((r) => ({ ...r, payload: bytes(r.payload) }));
  }
}

export class UsedNoncesRepo {
  readonly #db: Kysely<DB>;
  constructor(db: Kysely<DB>) {
    this.#db = db;
  }
  /** True the first time a nonce is seen, false for a reuse (DESIGN 8.10). One atomic insert decides. */
  async consume(nonce: string, keyId: string, ledgerIndex: number): Promise<boolean> {
    const r = await this.#db
      .insertInto('used_nonce')
      .values({ nonce: bin(nonce), key_id: keyId, ledger_index: ledgerIndex })
      .onConflict((oc) => oc.column('nonce').doNothing())
      .returning('nonce')
      .executeTakeFirst();
    return r !== undefined;
  }
  /** Requests older than 20 ledgers are refused anyway, so their nonces can go. Returns the number deleted. */
  async pruneBelow(ledgerIndex: number): Promise<number> {
    const r = await this.#db.deleteFrom('used_nonce').where('ledger_index', '<', ledgerIndex).executeTakeFirst();
    return Number(r.numDeletedRows);
  }
}

export class FrostNonceUsesRepo {
  readonly #db: Kysely<DB>;
  constructor(db: Kysely<DB>) {
    this.#db = db;
  }
  /**
   * Marks a nonce commitment used, atomically, before the holder releases a signature share (DESIGN 6.4). True for the
   * first use of (key_id, commitment_id); false for any later one, whatever the message.
   */
  async markUsed(u: {
    key_id: string;
    commitment_id: string;
    deal_id: string;
    message_hash: string;
  }): Promise<boolean> {
    const r = await this.#db
      .insertInto('frost_nonce_use')
      .values({ ...u, message_hash: bin(u.message_hash) })
      .onConflict((oc) => oc.columns(['key_id', 'commitment_id']).doNothing())
      .returning('commitment_id')
      .executeTakeFirst();
    return r !== undefined;
  }
  async get(keyId: string, commitmentId: string): Promise<{ deal_id: string; message_hash: string } | undefined> {
    const r = await this.#db
      .selectFrom('frost_nonce_use')
      .select(['deal_id', 'message_hash'])
      .where('key_id', '=', keyId)
      .where('commitment_id', '=', commitmentId)
      .executeTakeFirst();
    return r && { deal_id: r.deal_id, message_hash: hex(r.message_hash) };
  }
}
