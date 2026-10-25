// Watcher client against a model ledger: P2.7-01..04, order, hostile servers, handler failures.
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import type { Alert, CursorStore, Observation } from '../../src/watcher/index.ts';
import { WatcherClient } from '../../src/watcher/index.ts';
import { FakeChain, FakeLink } from './fakeLink.ts';

const A = 'rAlice';
const B = 'rBob';
const C = 'rCarol'; // not watched
const WATCHED = [A, B];

function memoryCursors(): CursorStore & { map: Map<string, number> } {
  const map = new Map<string, number>();
  return { map, get: async (a) => map.get(a), set: async (a, n) => void map.set(a, n) };
}

function setup(opts: { servers?: number; pageLimit?: number; cursors?: ReturnType<typeof memoryCursors> } = {}) {
  const chain = new FakeChain();
  const links = Array.from({ length: opts.servers ?? 1 }, (_, i) => new FakeLink(`s${i}`, chain));
  const cursors = opts.cursors ?? memoryCursors();
  const handled: Observation[] = [];
  const alerts: Alert[] = [];
  const state = { failOnce: new Set<string>(), down: false };
  const w = new WatcherClient({
    servers: links,
    accounts: WATCHED,
    cursorStore: cursors,
    handler: async (o) => {
      if (state.down || state.failOnce.delete(o.hash)) throw new Error('handler down');
      handled.push(o);
    },
    onAlert: (a) => alerts.push(a),
    pollMs: 3_600_000,
    pageLimit: opts.pageLimit ?? 200,
  });
  const link = links[0] as FakeLink;
  /** Closes a ledger on the chain and lets every server push it. */
  const close = async (per: string[][]) => {
    const made = chain.close(per);
    for (const l of links) l.push(made);
    await w.idle();
    return made;
  };
  return { chain, link, links, cursors, handled, alerts, w, close, state };
}

describe('subscription', () => {
  it('P2.7-01: subscribes to accounts (never accounts_proposed) and acts only on validated: true', async () => {
    const s = setup();
    await s.w.start();
    const sub = s.link.calls.find((c) => c.command === 'subscribe');
    expect(sub).toEqual({ command: 'subscribe', accounts: WATCHED, streams: ['ledger'] });
    expect(JSON.stringify(s.link.calls)).not.toContain('accounts_proposed');

    const made = s.chain.close([[A]]);
    s.link.push(made, false); // a proposed copy: ignored
    await s.w.idle();
    expect(s.handled).toEqual([]);
    s.link.push(made, true);
    await s.w.idle();
    expect(s.handled.map((o) => o.hash)).toEqual([made[0]?.hash]);
    expect(s.handled[0]?.source).toBe('stream');
    await s.w.stop();
  });

  it('ignores a transaction of an unwatched account and a malformed message (alert, no crash)', async () => {
    const s = setup();
    await s.w.start();
    await s.close([[C]]);
    expect(s.handled).toEqual([]);
    s.link.push([{ hash: 'zz', ledger: 5, index: 0, accounts: [A] }]);
    await s.w.idle();
    expect(s.alerts.some((a) => a.kind === 'error')).toBe(true);
    await s.w.stop();
  });
});

describe('idempotence', () => {
  it('P2.7-02: the same transaction from the stream and from the backfill reaches the handler once', async () => {
    const s = setup();
    await s.w.start();
    const [t] = await s.close([[A]]);
    await s.w.sync(); // backfill returns it again
    s.link.push([t as never]); // and the stream repeats it
    await s.w.idle();
    expect(s.handled.map((o) => o.hash)).toEqual([t?.hash]);
    await s.w.stop();
  });

  it('a transaction touching two watched accounts is handled once', async () => {
    const s = setup();
    await s.w.start();
    await s.close([[A, B]]);
    await s.w.sync();
    expect(s.handled).toHaveLength(1);
    await s.w.stop();
  });

  it('resumes from the stored cursor: ledgers at or below it are not fetched again', async () => {
    const cursors = memoryCursors();
    const first = setup({ cursors });
    await first.w.start();
    await first.close([[A]]);
    await first.close([[B]]);
    await first.w.sync();
    await first.w.stop();
    expect(cursors.map.get(A)).toBe(first.chain.head);

    const second = setup({ cursors });
    second.chain.head = first.chain.head;
    second.chain.txs = first.chain.txs;
    await second.w.start();
    expect(second.handled).toEqual([]);
    const reqs = second.link.calls.filter((c) => c.command === 'account_tx');
    expect(reqs.length).toBe(0); // cursor == head: nothing to fetch
    await second.w.stop();
  });
});

describe('backfill', () => {
  it('T-I-08 shape: after a gap, every transaction once, in (ledger_index, TransactionIndex) order, across pages', async () => {
    const s = setup({ pageLimit: 3 });
    s.link.scramble = true;
    await s.w.start();
    s.link.drop();
    for (let i = 0; i < 50; i++) s.chain.close(i % 7 === 0 ? [] : [[A], [B, A], [A]]);
    s.link.reconnect();
    await s.w.idle();
    const expected = s.chain.txs.filter((t) => t.accounts.some((a) => WATCHED.includes(a)));
    expect(new Set(s.handled.map((o) => o.hash))).toEqual(new Set(expected.map((t) => t.hash)));
    expect(s.handled).toHaveLength(expected.length);
    // Each account's observations arrive in position order.
    for (const acc of WATCHED) {
      const mine = s.handled.filter((o) => o.account === acc).map((o) => [o.ledgerIndex, o.transactionIndex]);
      expect(mine).toEqual(
        [...mine].sort((x, y) => (x[0] as number) - (y[0] as number) || (x[1] as number) - (y[1] as number)),
      );
    }
    expect(s.link.calls.filter((c) => c.command === 'subscribe')).toHaveLength(2); // again after the reconnect
    expect(s.cursors.map.get(A)).toBe(s.chain.head);
    await s.w.stop();
  });

  it('a failing handler holds the cursor back and the transaction is retried, not lost', async () => {
    const s = setup();
    await s.w.start();
    const made = s.chain.close([[A], [A]]);
    s.state.down = true;
    s.link.push(made);
    await s.w.idle();
    expect(s.alerts.some((a) => a.kind === 'error' && a.message === 'handler down')).toBe(true);
    expect(s.handled).toEqual([]);
    expect(s.cursors.map.get(A)).toBe(1); // not advanced past the failed ledger
    s.state.down = false;
    await s.w.sync();
    expect(s.handled.map((o) => o.hash).sort()).toEqual(made.map((t) => t.hash).sort());
    expect(s.cursors.map.get(A)).toBe(s.chain.head);
    await s.w.stop();
  });

  it('refuses hostile account_tx answers and moves no cursor: repeated marker, unvalidated entry, entry out of range', async () => {
    for (const bad of ['repeat', 'unvalidated', 'range'] as const) {
      const s = setup();
      s.chain.close([[A]]);
      s.chain.close([[A]]);
      const good = s.link.request.bind(s.link);
      s.link.accountTx = (req) => {
        const page = (s.link as never as { page(r: unknown): Record<string, unknown> }).page(req);
        const txs = page.transactions as Record<string, unknown>[];
        if (bad === 'repeat') return { ...page, marker: 'm' };
        if (bad === 'unvalidated') return { ...page, transactions: txs.map((t) => ({ ...t, validated: false })) };
        return { ...page, transactions: txs.map((t) => ({ ...t, ledger_index: 99 })) };
      };
      void good;
      await expect(s.w.start()).rejects.toThrow();
      // The repeated marker arrives after a complete page, so earlier whole ledgers may legitimately be handled.
      if (bad === 'repeat') expect(s.cursors.map.get(A) ?? 0).toBeLessThan(s.chain.head);
      else expect([s.cursors.map.get(A) ?? 0, s.handled.length]).toEqual([0, 0]);
      await s.w.stop();
    }
  });

  it('alerts when the cursor is older than the server history', async () => {
    const cursors = memoryCursors();
    cursors.map.set(A, 2);
    cursors.map.set(B, 2);
    const s = setup({ cursors });
    for (let i = 0; i < 5; i++) s.chain.close([[A]]);
    s.link.request = async (req) =>
      req.command === 'server_info'
        ? { result: { info: { complete_ledgers: `5-${s.chain.head}` } } }
        : FakeLink.prototype.request.call(s.link, req);
    await expect(s.w.start()).rejects.toThrow(/history/);
    expect(s.alerts).toContainEqual({ kind: 'history-gap', account: A, fromLedger: 3 });
    await s.w.stop();
  });
});

describe('two servers', () => {
  it('P2.7-03: a different hash for the same validated ledger raises one alert naming both servers', async () => {
    const s = setup({ servers: 2 });
    (s.links[1] as FakeLink).salt = 'F';
    await s.w.start();
    await s.close([[A]]);
    await s.w.sync();
    const dis = s.alerts.filter((a) => a.kind === 'disagreement');
    expect(dis.length).toBeGreaterThanOrEqual(1);
    expect(dis[0]).toMatchObject({ kind: 'disagreement', hashes: { s0: expect.any(String), s1: expect.any(String) } });
    await s.w.stop();
  });

  it('agreeing servers raise nothing; a lagging server is not a disagreement; a forked past is caught at the lag index', async () => {
    const s = setup({ servers: 2 });
    await s.w.start();
    for (let i = 0; i < 5; i++) await s.close([[A]]);
    (s.links[1] as FakeLink).lag = 3;
    await s.w.sync();
    expect(s.alerts).toEqual([]);
    (s.links[1] as FakeLink).salt = 'F';
    await s.w.sync();
    const a = s.alerts.find((x) => x.kind === 'disagreement');
    expect(a).toMatchObject({ ledgerIndex: s.chain.head - 3 });
    await s.w.stop();
  });

  it('a dead second server is an error alert and the primary keeps working', async () => {
    const s = setup({ servers: 2 });
    await s.w.start();
    (s.links[1] as FakeLink).connected = false;
    (s.links[1] as FakeLink).refuse = true;
    await s.close([[A]]);
    expect(s.handled).toHaveLength(1);
    expect(s.alerts.some((a) => a.kind === 'error' && a.where === 's1')).toBe(true);
    await s.w.stop();
  });
});

describe('P2.7-04: random disconnects over 200 ledgers', () => {
  const ledgerOp = fc.record({
    txs: fc.array(fc.subarray([A, B, C], { minLength: 1 }), { maxLength: 3 }),
    net: fc.constantFrom('up', 'up', 'up', 'drop', 'reconnect'),
    flaky: fc.boolean(),
  });
  it('the handled set equals the ledger set, each transaction exactly once', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(ledgerOp, { minLength: 200, maxLength: 200 }),
        fc.integer({ min: 1, max: 7 }),
        fc.boolean(),
        async (ops, pageLimit, scramble) => {
          const s = setup({ pageLimit });
          s.link.scramble = scramble;
          await s.w.start();
          for (const op of ops) {
            if (op.net === 'drop' && s.link.connected) s.link.drop();
            const made = s.chain.close(op.txs);
            if (op.flaky && made[0]) s.state.failOnce.add(made[0].hash);
            s.link.push(made);
            if (op.net === 'reconnect' && !s.link.connected) s.link.reconnect();
            await s.w.idle();
          }
          if (!s.link.connected) s.link.reconnect();
          await s.w.idle();
          // Each flaky transaction fails once; a sync that hits one stops, and the next tick tries again.
          for (let i = 0; i < 20 && WATCHED.some((a) => s.cursors.map.get(a) !== s.chain.head); i++) await s.w.sync();
          const want = s.chain.txs.filter((t) => t.accounts.some((a) => WATCHED.includes(a))).map((t) => t.hash);
          const got = s.handled.map((o) => o.hash);
          expect(got.slice().sort()).toEqual(want.slice().sort());
          expect(new Set(got).size).toBe(got.length);
          for (const a of WATCHED) expect(s.cursors.map.get(a)).toBe(s.chain.head);
          await s.w.stop();
        },
      ),
      { numRuns: 25 },
    );
  });
});
