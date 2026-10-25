// evidence_event, evidence_log_entry, deal_head, checkpoint_anchor (DESIGN 8.1, 9). The per-deal seq is the cursor.
// Source: https://www.postgresql.org/docs/18/sql-select.html#SQL-FOR-UPDATE-SHARE (row locks)
import type { Kysely } from 'kysely';
import { bin, bytes, hex, isUniqueViolation } from '../bytes.ts';
import { SeqTaken } from '../errors.ts';
import type { DB } from '../schema.ts';

export interface EvidenceEventRow {
  event_id: string;
  deal_id: string;
  seq: number;
  prev_hash: string;
  envelope: Uint8Array;
  leaf_hash: string;
  received_at: Date;
}
export type NewEvidenceEvent = Omit<EvidenceEventRow, 'event_id' | 'received_at'> & { event_id?: string };

/** What the next event of a deal must carry. `seq` 0 has a prev_hash of 32 zero bytes. */
export interface DealHead {
  nextSeq: number;
  prevHash: string;
}

const ZERO_HASH = '0'.repeat(64);

const toEvent = (r: {
  event_id: string;
  deal_id: string;
  seq: number;
  prev_hash: Uint8Array;
  envelope: Uint8Array;
  leaf_hash: Uint8Array;
  received_at: Date;
}): EvidenceEventRow => ({
  ...r,
  prev_hash: hex(r.prev_hash),
  envelope: bytes(r.envelope),
  leaf_hash: hex(r.leaf_hash),
});

export class EvidenceEventsRepo {
  readonly #db: Kysely<DB>;
  constructor(db: Kysely<DB>) {
    this.#db = db;
  }

  /**
   * Insert one event. The same `leaf_hash` twice is a no-op that returns the first row (idempotency). Another writer
   * holding the same (deal_id, seq) raises `SeqTaken`. Use `appendNext` when the seq must be assigned.
   */
  async insert(e: NewEvidenceEvent): Promise<EvidenceEventRow> {
    try {
      await this.#db
        .insertInto('evidence_event')
        .values({ ...e, prev_hash: bin(e.prev_hash), leaf_hash: bin(e.leaf_hash) })
        .onConflict((oc) => oc.constraint('evidence_event_leaf_hash_key').doNothing())
        .execute();
    } catch (err) {
      if (isUniqueViolation(err, 'evidence_event_deal_id_seq_key')) throw new SeqTaken(e.deal_id, e.seq);
      throw err;
    }
    return toEvent(
      await this.#db
        .selectFrom('evidence_event')
        .selectAll()
        .where('leaf_hash', '=', bin(e.leaf_hash))
        .executeTakeFirstOrThrow(),
    );
  }

  /**
   * Assigns the next gap-free seq inside the caller's transaction: lock the deal's head row, let `build` make the event
   * for that seq and prev_hash, insert it and move the head. Call it on a transaction repo (`Database.transaction`):
   * on a plain connection the lock would end before the insert. Concurrent callers queue on the lock, so seq has no gaps.
   */
  async appendNext(
    dealId: string,
    build: (
      head: DealHead,
    ) =>
      | Promise<Omit<NewEvidenceEvent, 'deal_id' | 'seq' | 'prev_hash'>>
      | Omit<NewEvidenceEvent, 'deal_id' | 'seq' | 'prev_hash'>,
  ): Promise<EvidenceEventRow> {
    await this.#db
      .insertInto('deal_head')
      .values({ deal_id: dealId, head_seq: -1, head_hash: bin(ZERO_HASH) })
      .onConflict((oc) => oc.column('deal_id').doNothing())
      .execute();
    const head = await this.#db
      .selectFrom('deal_head')
      .selectAll()
      .where('deal_id', '=', dealId)
      .forUpdate()
      .executeTakeFirstOrThrow();
    const seq = head.head_seq + 1;
    const prevHash = head.head_seq === -1 ? ZERO_HASH : hex(head.head_hash);
    const built = await build({ nextSeq: seq, prevHash });
    const row = await this.insert({ ...built, deal_id: dealId, seq, prev_hash: prevHash });
    if (row.leaf_hash !== built.leaf_hash || row.seq !== seq)
      throw new Error('appendNext: the leaf was already stored');
    await this.#db
      .updateTable('deal_head')
      .set({ head_seq: seq, head_hash: bin(built.leaf_hash) })
      .where('deal_id', '=', dealId)
      .execute();
    return row;
  }

  async getBySeq(dealId: string, seq: number): Promise<EvidenceEventRow | undefined> {
    const r = await this.#db
      .selectFrom('evidence_event')
      .selectAll()
      .where('deal_id', '=', dealId)
      .where('seq', '=', seq)
      .executeTakeFirst();
    return r && toEvent(r);
  }

  /** Events with seq greater than `afterSeq`, in order. Pass -1 for all. */
  async listAfter(dealId: string, afterSeq: number, limit = 1000): Promise<EvidenceEventRow[]> {
    const rows = await this.#db
      .selectFrom('evidence_event')
      .selectAll()
      .where('deal_id', '=', dealId)
      .where('seq', '>', afterSeq)
      .orderBy('seq')
      .limit(limit)
      .execute();
    return rows.map(toEvent);
  }
}

export class EvidenceLogEntriesRepo {
  readonly #db: Kysely<DB>;
  constructor(db: Kysely<DB>) {
    this.#db = db;
  }
  /** The Merkle log position of an event, written once the log has integrated the leaf. Idempotent per event. */
  async insert(eventId: string, logIndex: number): Promise<void> {
    await this.#db
      .insertInto('evidence_log_entry')
      .values({ event_id: eventId, log_index: logIndex })
      .onConflict((oc) => oc.column('event_id').doNothing())
      .execute();
  }
  async get(eventId: string): Promise<number | undefined> {
    const r = await this.#db
      .selectFrom('evidence_log_entry')
      .select('log_index')
      .where('event_id', '=', eventId)
      .executeTakeFirst();
    return r?.log_index;
  }
}

export interface CheckpointAnchorRow {
  tree_size: number;
  root: string;
  checkpoint: Uint8Array;
  anchor_tx_hash: string | null;
  anchor_ledger: number | null;
  rfc3161_token: Uint8Array | null;
}

export class CheckpointAnchorsRepo {
  readonly #db: Kysely<DB>;
  constructor(db: Kysely<DB>) {
    this.#db = db;
  }
  async insert(c: Pick<CheckpointAnchorRow, 'tree_size' | 'root' | 'checkpoint'>): Promise<void> {
    await this.#db
      .insertInto('checkpoint_anchor')
      .values({ ...c, root: bin(c.root) })
      .onConflict((oc) => oc.column('tree_size').doNothing())
      .execute();
  }
  /** The ledger anchor and the RFC 3161 token arrive after the checkpoint exists. */
  async setAnchor(
    treeSize: number,
    a: { anchor_tx_hash?: string; anchor_ledger?: number; rfc3161_token?: Uint8Array },
  ): Promise<void> {
    await this.#db.updateTable('checkpoint_anchor').set(a).where('tree_size', '=', treeSize).execute();
  }
  async latest(): Promise<CheckpointAnchorRow | undefined> {
    const r = await this.#db
      .selectFrom('checkpoint_anchor')
      .selectAll()
      .orderBy('tree_size', 'desc')
      .limit(1)
      .executeTakeFirst();
    return (
      r && {
        ...r,
        root: hex(r.root),
        checkpoint: bytes(r.checkpoint),
        rfc3161_token: r.rfc3161_token && bytes(r.rfc3161_token),
      }
    );
  }
}
