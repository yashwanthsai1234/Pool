// Task 2.7 against the standalone ledger: T-I-08, P2.7-02 (stream and backfill), P2.7-04 (random outages over 200
// ledgers) and the two-server disagreement alert.
import fc from 'fast-check';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Client } from 'xrpl';
import { connect } from '../../src/connect.ts';
import { standaloneEnv } from '../../src/env.ts';
import { fundAccount } from '../../src/fund.ts';
import { type Alert, type CursorStore, type Observation, WatcherClient, xrplLink } from '../../src/watcher/index.ts';
import { blockableProxy, closeLedgerWith, lying, until } from './support.ts';

const env = standaloneEnv(process.env.XRPLD_WS ?? 'ws://127.0.0.1:6107');
let admin: Client;
let w1: string;
let w2: string;

beforeAll(async () => {
  admin = await connect(env);
  w1 = (await fundAccount(env, admin, 100)).classicAddress;
  w2 = (await fundAccount(env, admin, 100)).classicAddress;
});
afterAll(async () => {
  await admin.disconnect();
});

/** Cursors start at the current validated ledger, so the funding payments of other tests are not ours. */
async function cursors(accounts: string[]): Promise<CursorStore> {
  const head = (await admin.request({ command: 'ledger', ledger_index: 'validated' })).result.ledger_index;
  const map = new Map<string, number>(accounts.map((a) => [a, head]));
  return { get: async (a) => map.get(a), set: async (a, n) => void map.set(a, n) };
}

async function watch(servers: ReturnType<typeof xrplLink>[], accounts = [w1, w2]) {
  const handled: Observation[] = [];
  const alerts: Alert[] = [];
  const w = new WatcherClient({
    servers,
    accounts,
    cursorStore: await cursors(accounts),
    handler: async (o) => void handled.push(o),
    onAlert: (a) => alerts.push(a),
    pollMs: 300,
  });
  return { w, handled, alerts };
}

describe('watcher on the standalone ledger', () => {
  it('T-I-08 and P2.7-02: 50 ledgers missed behind a dead connection are backfilled, each transaction once', async () => {
    const proxy = await blockableProxy(env.wsUrl);
    const { w, handled, alerts } = await watch([xrplLink('primary', proxy.url, { timeoutMs: 3000 })]);
    try {
      await w.start();
      const expected: string[] = [];
      for (const t of await closeLedgerWith(admin, [w1])) expected.push(t.hash); // seen live
      await until('the live transaction', () => handled.length === 1);
      // The ledger message can overtake the transaction message, so either path may deliver it; never both.

      proxy.block();
      for (let i = 0; i < 50; i++) {
        const dests = i % 5 === 0 ? [] : i % 3 === 0 ? [w1, w2] : [i % 2 ? w1 : w2];
        for (const t of await closeLedgerWith(admin, dests)) expected.push(t.hash);
      }
      expect(handled).toHaveLength(1); // nothing arrived while the link was down
      proxy.unblock();
      await until('the backfill', () => handled.length === expected.length);
      await new Promise((r) => setTimeout(r, 1000)); // anything extra would show up now
      expect(handled.map((o) => o.hash).sort()).toEqual([...expected].sort());
      expect(handled.some((o) => o.source === 'backfill')).toBe(true);
      for (const acc of [w1, w2]) {
        const mine = handled.filter((o) => o.account === acc).map((o) => o.ledgerIndex * 1000 + o.transactionIndex);
        expect(mine).toEqual([...mine].sort((a, b) => a - b));
      }
      expect(alerts.filter((a) => a.kind === 'disagreement')).toEqual([]);
    } finally {
      await w.stop();
      await proxy.close();
    }
  });

  it('P2.7-04: random outages over 200 ledgers; the handled set is the ledger set', async () => {
    const plan = fc.sample(
      fc.record({
        dests: fc.constantFrom<string[]>([], ['w1'], ['w2'], ['w1', 'w2'], ['w1', 'w1']),
        net: fc.constantFrom('keep', 'keep', 'keep', 'block', 'unblock'),
      }),
      { numRuns: 200, seed: 27 },
    );
    const proxy = await blockableProxy(env.wsUrl);
    const { w, handled } = await watch([xrplLink('primary', proxy.url, { timeoutMs: 3000 })]);
    const expected: string[] = [];
    try {
      await w.start();
      for (const step of plan) {
        if (step.net === 'block') proxy.block();
        if (step.net === 'unblock') proxy.unblock();
        for (const t of await closeLedgerWith(
          admin,
          step.dests.map((d) => (d === 'w1' ? w1 : w2)),
        ))
          expected.push(t.hash);
      }
      proxy.unblock();
      await until('every transaction', () => new Set(handled.map((o) => o.hash)).size === expected.length, 120_000);
      await new Promise((r) => setTimeout(r, 1000));
      expect(handled.map((o) => o.hash).sort()).toEqual([...expected].sort());
    } finally {
      await w.stop();
      await proxy.close();
    }
  });

  it('P2.7-03: a second server with other ledger hashes raises a disagreement alert; an honest one does not', async () => {
    const honest = await watch([xrplLink('a', env.wsUrl), xrplLink('b', env.wsUrl)]);
    await honest.w.start();
    await closeLedgerWith(admin, [w1]);
    await honest.w.sync();
    await honest.w.stop();
    expect(honest.alerts).toEqual([]);

    const bad = await watch([xrplLink('a', env.wsUrl), lying(xrplLink('liar', env.wsUrl))]);
    await bad.w.start();
    await closeLedgerWith(admin, [w1]);
    await bad.w.sync();
    await bad.w.stop();
    const dis = bad.alerts.find((a) => a.kind === 'disagreement');
    expect(dis).toMatchObject({ kind: 'disagreement', hashes: { a: expect.any(String), liar: expect.any(String) } });
  });
});
