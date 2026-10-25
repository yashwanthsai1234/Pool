// The live feed on real Postgres 18 (port 5510): replay from the outbox table, wake-ups by LISTEN/NOTIFY on a dedicated
// connection, a reconnect with the last seq (P3.7-02, P3.7-03), and the load test (P3.7-04): 3 clients, 100 events per
// second, one minute (LEGX_LOAD_SECONDS shortens it for a quick run).
import { afterAll, describe, expect, it } from 'vitest';
import { uuid7 } from '../../../services/coordinator/src/uuid.ts';
import { pgLiveSource } from '../src/pgSource.ts';
import { Client, hubServer, range } from '../test/support/feed.ts';
import { freshDb } from './support/pg.ts';

const dbs: { drop(): Promise<void> }[] = [];
afterAll(async () => {
  for (const d of dbs) await d.drop();
});

const enc = (s: string) => new TextEncoder().encode(s);

async function setup(opts: { trigger?: boolean } = {}) {
  const f = await freshDb(opts);
  dbs.push(f);
  const source = pgLiveSource(f.db, f.url);
  const s = await hubServer(source, { pollMs: 500 });
  return {
    ...f,
    s,
    source,
    close: async () => {
      await s.close();
      await source.close();
    },
  };
}

describe('live feed on Postgres', () => {
  it('P3.7-02 / P3.7-03: after seq 5 gives 6, 7, ...; a drop and a reconnect with the last seq gives no gap and no repeat', async () => {
    const t = await setup();
    try {
      const deal = uuid7();
      for (let i = 0; i < 10; i++)
        await t.db.repos.outbox.enqueue({ topic: 'deal.event', payload: enc(`{"i":${i}}`), deal_id: deal, seq: i });
      const a = new Client(t.s.url, deal, 5);
      await a.waitSeq(9);
      await t.db.repos.outbox.enqueue({ topic: 'deal.event', payload: enc('{"i":10}'), deal_id: deal, seq: 10 });
      await a.waitSeq(10); // woken by NOTIFY
      expect(a.rows).toEqual(range(6, 10));
      a.close();
      await a.closed;
      for (let i = 11; i < 20; i++)
        await t.db.repos.outbox.enqueue({ topic: 'deal.event', payload: enc(`{"i":${i}}`), deal_id: deal, seq: i });
      const b = new Client(t.s.url, deal, a.rows.at(-1) as number);
      await b.waitSeq(19);
      expect([...a.rows, ...b.rows]).toEqual(range(6, 19));
      expect(Buffer.from(b.messages[0]?.payload as string, 'base64').toString()).toBe('{"i":11}');
    } finally {
      await t.close();
    }
  });

  it('the payload bytes come from the table, whatever NOTIFY said: a lost NOTIFY is covered by the poll', async () => {
    const t = await setup({ trigger: false }); // no trigger: nothing is ever notified
    try {
      const deal = uuid7();
      const c = new Client(t.s.url, deal, -1);
      await c.waitFor(() => c.ws.readyState === 1);
      await t.db.repos.outbox.enqueue({ topic: 'deal.event', payload: enc('{"late":true}'), deal_id: deal, seq: 0 });
      await c.waitSeq(0, 5000);
    } finally {
      await t.close();
    }
  });

  it('ledger.validated rows (no deal) are pushed to every subscribed socket once', async () => {
    const t = await setup();
    try {
      const c = new Client(t.s.url, uuid7(), -1);
      await c.waitFor(() => c.ws.readyState === 1);
      await new Promise((r) => setTimeout(r, 300));
      for (const index of [7, 8, 9])
        await t.db.repos.outbox.enqueue({
          topic: 'ledger.validated',
          payload: enc(JSON.stringify({ index, hash: 'AB'.repeat(32), close_time: index })),
        });
      await c.waitFor(() => c.messages.filter((m) => m.type === 'ledger').length >= 1);
      await new Promise((r) => setTimeout(r, 1200));
      const indexes = c.messages.filter((m) => m.type === 'ledger').map((m) => (m.payload as { index: number }).index);
      expect(indexes.at(-1)).toBe(9); // the newest is always delivered; intermediate ones may coalesce
      expect(new Set(indexes).size).toBe(indexes.length); // never twice
    } finally {
      await t.close();
    }
  });

  it('survives the LISTEN connection being killed: it reconnects and nothing is lost', async () => {
    const t = await setup();
    try {
      const deal = uuid7();
      const c = new Client(t.s.url, deal, -1);
      await c.waitFor(() => c.ws.readyState === 1);
      await t.db.repos.outbox.enqueue({ topic: 'deal.event', payload: enc('{}'), deal_id: deal, seq: 0 });
      await c.waitSeq(0);
      const pgmod = (await import('pg')).default;
      const admin = new pgmod.Client({
        connectionString: new URL('/postgres', t.url).toString().replace(/\/[^/]*$/, '/postgres'),
      });
      await admin.connect();
      await admin.query(`select pg_terminate_backend(pid) from pg_stat_activity where query like 'LISTEN%'`);
      await admin.end();
      await t.db.repos.outbox.enqueue({ topic: 'deal.event', payload: enc('{}'), deal_id: deal, seq: 1 });
      await c.waitSeq(1, 8000);
      expect(c.rows).toEqual([0, 1]);
    } finally {
      await t.close();
    }
  });
});

describe('rows that commit out of order', () => {
  it('a row is held back until its predecessor commits: no gap is ever sent', async () => {
    const t = await setup();
    try {
      const deal = uuid7();
      const c = new Client(t.s.url, deal, -1);
      await c.waitFor(() => c.ws.readyState === 1);
      // 200 rows inserted concurrently: they commit in any order.
      await Promise.all(
        range(0, 199).map((i) =>
          t.db.repos.outbox.enqueue({ topic: 'deal.event', payload: enc(`{"i":${i}}`), deal_id: deal, seq: i }),
        ),
      );
      await c.waitSeq(199, 10_000);
      expect(c.rows).toEqual(range(0, 199));
    } finally {
      await t.close();
    }
  });
});

describe('P3.7-04 load: 3 clients, 100 events per second', () => {
  const seconds = Number(process.env.LEGX_LOAD_SECONDS ?? 60);
  it(`every client sees every event of ${seconds} s, in order, once`, async () => {
    const t = await setup();
    try {
      const deal = uuid7();
      const clients = [0, 1, 2].map(() => new Client(t.s.url, deal, -1));
      await Promise.all(clients.map((c) => c.waitFor(() => c.ws.readyState === 1)));
      const total = seconds * 100;
      const started = Date.now();
      let sent = 0;
      // 100 events per second, each its own transaction, in seq order (the writers hold the deal's head lock).
      while (sent < total) {
        const tick = started + (sent / 100) * 1000;
        await t.db.repos.outbox.enqueue({
          topic: 'deal.event',
          payload: enc(JSON.stringify({ n: sent })),
          deal_id: deal,
          seq: sent,
        });
        sent += 1;
        const wait = tick + 10 - Date.now();
        if (wait > 0) await new Promise((r) => setTimeout(r, wait));
      }
      const publishedMs = Date.now() - started;
      await Promise.all(clients.map((c) => c.waitSeq(total - 1, 15_000)));
      for (const c of clients) {
        expect(c.rows.length).toBe(total);
        expect(c.rows).toEqual(range(0, total - 1));
        const lastPayload = JSON.parse(Buffer.from(c.messages.at(-1)?.payload as string, 'base64').toString());
        expect(lastPayload.n).toBe(total - 1);
      }
      expect(publishedMs).toBeGreaterThanOrEqual(seconds * 1000 * 0.95); // it really took the minute
      for (const c of clients) c.close();
    } finally {
      await t.close();
    }
  }, 120_000);
});
