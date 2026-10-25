// The relay's message queue in Postgres (IMPLEMENTATION 3.9): the two `frost_relay_*` tables of migration 0003.
// The queue holds bytes: the exact signed message as received. It never holds a nonce or an opened share.
// Source: https://kysely.dev/docs/recipes/raw-sql (raw SQL through `sql`)
import type { FrostSignedMessage } from '@legx/contracts/frost';
import type { Database } from '@legx/db';
import type { KyselyDatabase } from '@legx/db/client';
import { type Kysely, sql } from 'kysely';
import type { z } from 'zod';

export type SignedMessage = z.infer<typeof FrostSignedMessage>;
export type Purpose = 'dkg' | 'sign' | 'refresh' | 'repair';
export type SessionStatus = 'open' | 'timed_out' | 'aborted' | 'failed';

export interface Participant {
  readonly identifier: string;
  readonly keyId: string;
  readonly role: string;
}

export interface SessionRow {
  readonly sessionId: string;
  readonly dealId: string;
  readonly slot: string;
  readonly purpose: Purpose;
  readonly participants: readonly Participant[];
  readonly status: SessionStatus;
  readonly attempt: number;
  readonly parent: string | null;
  /** Signing sessions: the two identifiers asked to sign in this attempt. */
  readonly pair: readonly [string, string] | null;
  readonly deadlineMs: number | null;
}

export interface StoredMessage {
  readonly seq: number;
  readonly kind: string;
  readonly from: string;
  readonly to: string | null;
  readonly signed: SignedMessage;
}

/** The kysely handle behind a `Database` (the relay needs raw SQL; the repositories hide kysely). */
export function kyselyOf(db: Database): Kysely<unknown> {
  const k = (db as Partial<KyselyDatabase>).kysely;
  if (!k) throw new Error('the relay needs a Database made by createDatabase (it exposes kysely)');
  return k as Kysely<unknown>;
}

const toSession = (r: Record<string, unknown>): SessionRow => ({
  sessionId: r.session_id as string,
  dealId: r.deal_id as string,
  slot: r.slot as string,
  purpose: r.purpose as Purpose,
  participants: r.participants as Participant[],
  status: r.status as SessionStatus,
  attempt: Number(r.attempt),
  parent: (r.parent as string | null) ?? null,
  pair: (r.pair as [string, string] | null) ?? null,
  deadlineMs: r.deadline_ms === null || r.deadline_ms === undefined ? null : Number(r.deadline_ms),
});

export class RelayStore {
  readonly #k: Kysely<unknown>;
  constructor(db: Database) {
    this.#k = kyselyOf(db);
  }

  async createSession(s: SessionRow): Promise<void> {
    await sql`insert into frost_relay_session (session_id, deal_id, slot, purpose, participants, status, attempt, parent, pair, deadline_ms)
      values (${s.sessionId}, ${s.dealId}, ${s.slot}, ${s.purpose}, ${JSON.stringify(s.participants)}::jsonb, ${s.status},
        ${s.attempt}, ${s.parent}, ${s.pair === null ? null : JSON.stringify(s.pair)}::jsonb, ${s.deadlineMs})`.execute(
      this.#k,
    );
  }

  async session(id: string): Promise<SessionRow | undefined> {
    const r = await sql<Record<string, unknown>>`select * from frost_relay_session where session_id = ${id}`.execute(
      this.#k,
    );
    return r.rows[0] ? toSession(r.rows[0]) : undefined;
  }

  /** The child attempt of a timed-out signing session, if one was opened. */
  async child(id: string): Promise<SessionRow | undefined> {
    const r = await sql<Record<string, unknown>>`select * from frost_relay_session where parent = ${id}`.execute(
      this.#k,
    );
    return r.rows[0] ? toSession(r.rows[0]) : undefined;
  }

  /** Moves an open session to a final status. True only for the call that made the change. */
  async fail(id: string): Promise<void> {
    await sql`update frost_relay_session set status = 'failed' where session_id = ${id}`.execute(this.#k);
  }

  async close(id: string, status: Exclude<SessionStatus, 'open'>): Promise<boolean> {
    const r =
      await sql`update frost_relay_session set status = ${status} where session_id = ${id} and status = 'open'`.execute(
        this.#k,
      );
    return Number(r.numAffectedRows ?? 0) === 1;
  }

  /**
   * Appends in one statement pair inside a transaction: the next sequence number is taken from the session row, so
   * concurrent senders never share a number. A second message with the same (kind, from, to) is refused.
   */
  async append(sessionId: string, m: Omit<StoredMessage, 'seq'>): Promise<number | 'duplicate'> {
    return await this.#k.transaction().execute(async (trx) => {
      const taken = await sql<{
        seq: number;
      }>`select next_seq as seq from frost_relay_session where session_id = ${sessionId} for update`.execute(trx);
      const seq = Number(taken.rows[0]?.seq);
      const ins = await sql`insert into frost_relay_message (session_id, seq, kind, from_id, to_id, signed)
        values (${sessionId}, ${seq}, ${m.kind}, ${m.from}, ${m.to ?? ''}, ${JSON.stringify(m.signed)}::jsonb)
        on conflict (session_id, kind, from_id, to_id) do nothing returning seq`.execute(trx);
      if (ins.rows.length === 0) return 'duplicate';
      await sql`update frost_relay_session set next_seq = ${seq + 1} where session_id = ${sessionId}`.execute(trx);
      return seq;
    });
  }

  async messages(sessionId: string, afterSeq: number): Promise<StoredMessage[]> {
    const r = await sql<Record<string, unknown>>`select seq, kind, from_id, to_id, signed from frost_relay_message
      where session_id = ${sessionId} and seq > ${afterSeq} order by seq`.execute(this.#k);
    return r.rows.map((x) => ({
      seq: Number(x.seq),
      kind: x.kind as string,
      from: x.from_id as string,
      to: (x.to_id as string) === '' ? null : (x.to_id as string),
      signed: x.signed as SignedMessage,
    }));
  }
}
