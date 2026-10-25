// P3.7-02, P3.7-03 and the "test in all directions" rows for the live feed, on an in-memory outbox.

import fc from 'fast-check';
import { afterEach, describe, expect, it } from 'vitest';
import { uuid7 as randomUUID } from '../../../services/coordinator/src/uuid.ts';
import { Client, hubServer, MemorySource, range } from './support/feed.ts';

const open: { close(): Promise<void> }[] = [];
afterEach(async () => {
  for (const c of open.splice(0)) await c.close();
});
const start = async (...a: Parameters<typeof hubServer>) => {
  const s = await hubServer(...a);
  open.push(s);
  return s;
};

describe('P3.7-02 subscribe after seq 5', () => {
  it('replays 6, 7, ... with no gap and no repeat, then pushes live rows', async () => {
    const src = new MemorySource();
    const deal = randomUUID();
    for (let i = 0; i < 10; i++) src.append(deal);
    const s = await start(src);
    const c = new Client(s.url, deal, 5);
    await c.waitSeq(9);
    for (let i = 0; i < 5; i++) src.append(deal);
    await c.waitSeq(14);
    expect(c.rows).toEqual(range(6, 14));
    c.close();
  });

  it('row messages follow the contract and carry the exact payload bytes (base64)', async () => {
    const src = new MemorySource();
    const deal = randomUUID();
    src.append(deal, '{"envelope":"AAA","summary":{"kind":"x"}}');
    const s = await start(src);
    const c = new Client(s.url, deal, -1);
    await c.waitSeq(0);
    const m = c.messages[0];
    expect(m).toEqual({
      type: 'row',
      dealId: deal,
      seq: 0,
      topic: 'deal.event',
      payload: Buffer.from('{"envelope":"AAA","summary":{"kind":"x"}}').toString('base64'),
    });
  });

  it('pages: 1000 rows with a page size of 7 arrive once each, in order', async () => {
    const src = new MemorySource();
    const deal = randomUUID();
    for (let i = 0; i < 1000; i++) src.append(deal);
    const s = await start(src, { pageSize: 7 });
    const c = new Client(s.url, deal, -1);
    await c.waitSeq(999, 10_000);
    expect(c.rows).toEqual(range(0, 999));
  });

  it('only the subscribed deal reaches a socket', async () => {
    const src = new MemorySource();
    const [a, b] = [randomUUID(), randomUUID()];
    const s = await start(src);
    const c = new Client(s.url, a, -1);
    src.append(b);
    src.append(a);
    src.append(b);
    await c.waitSeq(0);
    await new Promise((r) => setTimeout(r, 100));
    expect(c.messages.map((m) => m.dealId)).toEqual([a]);
  });

  it('delivers by the fallback poll when NOTIFY never arrives', async () => {
    const src = new MemorySource();
    src.notifyOn = false;
    const deal = randomUUID();
    const s = await start(src, { pollMs: 30 });
    const c = new Client(s.url, deal, -1);
    await new Promise((r) => setTimeout(r, 50));
    src.append(deal);
    await c.waitSeq(0);
  });
});

describe('P3.7-03 reconnect with the last seq', () => {
  it('no gap and no repeat across a drop', async () => {
    const src = new MemorySource();
    const deal = randomUUID();
    const s = await start(src);
    for (let i = 0; i < 20; i++) src.append(deal);
    const first = new Client(s.url, deal, -1);
    await first.waitSeq(19);
    first.close();
    await first.closed;
    for (let i = 0; i < 15; i++) src.append(deal); // written while the client is away
    const second = new Client(s.url, deal, first.rows.at(-1) as number);
    for (let i = 0; i < 5; i++) src.append(deal);
    await second.waitSeq(39);
    expect([...first.rows, ...second.rows]).toEqual(range(0, 39));
  });

  it('random drops and reconnects while rows are written (fast-check): the union is gap-free and repeat-free', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.tuple(fc.integer({ min: 0, max: 12 }), fc.integer({ min: 0, max: 15 })), {
          minLength: 1,
          maxLength: 6,
        }),
        async (plan) => {
          const src = new MemorySource();
          const deal = randomUUID();
          const s = await hubServer(src, { pageSize: 5 });
          try {
            const seen: number[] = [];
            let last = -1;
            for (const [written, wait] of plan) {
              const c = new Client(s.url, deal, last);
              for (let i = 0; i < written; i++) src.append(deal);
              await new Promise((r) => setTimeout(r, wait));
              c.close(); // dropped at an arbitrary point of the replay
              await c.closed;
              seen.push(...c.rows);
              last = seen.at(-1) ?? last;
            }
            const final = new Client(s.url, deal, last);
            const total = src.deals.get(deal)?.length ?? 0;
            if (total - 1 > last) await final.waitSeq(total - 1);
            seen.push(...final.rows);
            final.close();
            expect(seen).toEqual(range(0, total - 1).slice(0, seen.length));
            expect(seen.length).toBe(total);
          } finally {
            await s.close();
          }
        },
      ),
      { numRuns: 15 },
    );
  });
});

describe('a row whose predecessor has not committed', () => {
  const put = (src: MemorySource, deal: string, seq: number) => {
    const rows = src.deals.get(deal) ?? [];
    rows.push({ seq, topic: 'deal.event', payload: new TextEncoder().encode('{}') });
    rows.sort((a, b) => a.seq - b.seq);
    src.deals.set(deal, rows);
    for (const l of src.listeners) l(deal);
  };
  it('is held back, then sent in order when the predecessor arrives', async () => {
    const src = new MemorySource();
    const deal = randomUUID();
    const s = await start(src);
    const c = new Client(s.url, deal, -1);
    await c.waitFor(() => c.ws.readyState === 1);
    put(src, deal, 1);
    put(src, deal, 2);
    await new Promise((r) => setTimeout(r, 200));
    expect(c.rows).toEqual([]);
    put(src, deal, 0);
    await c.waitSeq(2);
    expect(c.rows).toEqual([0, 1, 2]);
  });
  it('is sent after the grace period when the predecessor never comes (the client then resubscribes)', async () => {
    const src = new MemorySource();
    const deal = randomUUID();
    const s = await start(src, { gapWaitMs: 150 });
    const c = new Client(s.url, deal, -1);
    await c.waitFor(() => c.ws.readyState === 1);
    put(src, deal, 3);
    await c.waitSeq(3);
    expect(c.rows).toEqual([3]);
  });
});

describe('closing and limits', () => {
  it('a malformed first message closes with 4400', async () => {
    const s = await start(new MemorySource());
    const c = new Client(s.url, 'not-a-uuid', -1);
    expect(await c.closed).toBe(4400);
    expect(c.messages).toEqual([{ type: 'error', code: 'BAD_REQUEST' }]);
  });

  it('a deal the caller may not read closes with 4403 and sends nothing of it', async () => {
    const src = new MemorySource();
    const deal = randomUUID();
    src.append(deal);
    const s = await start(src, {}, async () => false);
    const c = new Client(s.url, deal, -1);
    expect(await c.closed).toBe(4403);
    expect(c.rows).toEqual([]);
  });

  it('a second subscribe on the same socket closes with 4400', async () => {
    const s = await start(new MemorySource());
    const deal = randomUUID();
    const c = new Client(s.url, deal, -1);
    await c.waitFor(() => c.ws.readyState === 1);
    c.ws.send(JSON.stringify({ subscribe: deal, after: -1 }));
    expect(await c.closed).toBe(4400);
  });

  it('a client that does not read is closed with 4408 and never blocks the others; it can subscribe again', async () => {
    const src = new MemorySource();
    const deal = randomUUID();
    const big = 'x'.repeat(60_000);
    const s = await start(src, { maxQueue: 4, stallMs: 300 });
    const slow = new Client(s.url, deal, -1, { pause: true });
    const fast = new Client(s.url, deal, -1);
    await fast.waitFor(() => fast.ws.readyState === 1);
    const n = 400;
    for (let i = 0; i < n; i++) src.append(deal, JSON.stringify({ big }));
    await fast.waitSeq(n - 1, 10_000); // the stalled neighbour did not slow it down
    expect(fast.rows).toEqual(range(0, n - 1));
    await slow.waitFor(() => s.hub.sockets === 1, 10_000); // the server dropped it: only the fast client is left
    slow.ws.resume();
    expect([4408, 1006]).toContain(await slow.closed); // 4408 if the close frame got through, a reset if the client was too stuck
    expect(slow.rows).toEqual(range(0, slow.rows.length - 1)); // what it did get is a gap-free prefix
    const again = new Client(s.url, deal, slow.rows.at(-1) ?? -1);
    await again.waitSeq(n - 1, 10_000);
    expect([...slow.rows, ...again.rows]).toEqual(range(0, n - 1));
  }, 30_000);

  it('pushes ledger.validated to every subscribed socket, only new ones, as {topic, payload}', async () => {
    const src = new MemorySource();
    src.pushLedger(1); // already there at start: not pushed
    const deal = randomUUID();
    const s = await start(src);
    const a = new Client(s.url, deal, -1);
    const b = new Client(s.url, randomUUID(), -1);
    await a.waitFor(() => a.ws.readyState === 1);
    await b.waitFor(() => b.ws.readyState === 1);
    await new Promise((r) => setTimeout(r, 100));
    src.pushLedger(2);
    src.pushLedger(3);
    const ledgerOf = (c: Client) =>
      c.messages.filter((m) => m.type === 'ledger').map((m) => (m.payload as { index: number }).index);
    await a.waitFor(() => ledgerOf(a).length >= 1);
    await b.waitFor(() => ledgerOf(b).length >= 1);
    expect(a.messages.find((m) => m.type === 'ledger')).toMatchObject({
      topic: 'ledger.validated',
      payload: { hash: 'AB'.repeat(32) },
    });
    expect(ledgerOf(a)).not.toContain(1);
  });
});
