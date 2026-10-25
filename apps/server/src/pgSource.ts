// The Postgres side of the live feed: replay reads come from `OutboxRepo.listAfter`, wake-ups from LISTEN on a
// dedicated connection (a pooled connection would be returned to the pool and lose the subscription).
// Source: https://node-postgres.com/features/notifications  Source: https://www.postgresql.org/docs/18/sql-listen.html
import type { Database } from '@legx/db';
import pg from 'pg';
import type { FeedRow, LiveSource } from './live.ts';

export const NOTIFY_CHANNEL = 'legx_outbox';

export interface PgLiveSource extends LiveSource {
  close(): Promise<void>;
}

export function pgLiveSource(db: Database, connectionString: string, channel = NOTIFY_CHANNEL): PgLiveSource {
  const pool = new pg.Pool({ connectionString, max: 2 });
  pool.on('error', () => undefined); // an idle client that dies is replaced on the next query
  let closed = false;
  return {
    async rowsAfter(dealId, after, limit): Promise<FeedRow[]> {
      const rows = await db.repos.outbox.listAfter(dealId, after, limit);
      return rows.flatMap((r) => (r.seq === null ? [] : [{ seq: r.seq, topic: r.topic, payload: r.payload }]));
    },
    async latestLedger() {
      const r = await pool.query<{ id: string; payload: Buffer }>(
        `select id, payload from outbox where topic = 'ledger.validated' order by created_at desc, id desc limit 1`,
      );
      const row = r.rows[0];
      return row ? { id: row.id, payload: new Uint8Array(row.payload) } : undefined;
    },
    async onNotify(fn) {
      let client: pg.Client | undefined;
      let retry: NodeJS.Timeout | undefined;
      const schedule = () => {
        if (!closed) retry = setTimeout(() => void connect(), 500);
      };
      const connect = async (): Promise<void> => {
        if (closed) return;
        const c = new pg.Client({ connectionString });
        let dead = false;
        const lost = () => {
          if (dead) return;
          dead = true;
          if (client === c) client = undefined;
          c.end().catch(() => undefined);
          schedule();
        };
        c.on('error', lost);
        c.on('end', lost);
        c.on('notification', (m) => fn(m.payload ?? ''));
        try {
          await c.connect();
          await c.query(`LISTEN ${channel}`);
        } catch {
          return lost();
        }
        client = c;
        fn(''); // notifications sent while we were away are gone: wake everything once
      };
      await connect();
      return async () => {
        closed = true;
        if (retry) clearTimeout(retry);
        const c = client;
        client = undefined;
        await c?.end().catch(() => undefined);
        await pool.end().catch(() => undefined);
      };
    },
    async close() {
      closed = true;
      await pool.end().catch(() => undefined);
    },
  };
}
