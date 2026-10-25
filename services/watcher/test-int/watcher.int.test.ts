// Task 3.5 on Postgres 18.6 (port 5508) and the standalone xrpld (port 6112): a real kill between the writes of
// P3.5-01, and T-I-08 through the whole service (real ledger, real database, notifications received).
import { spawnSync } from 'node:child_process';
import { openPg } from '@legx/db';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Client } from 'xrpl';
import { connect } from '../../../packages/xrpl/src/connect.ts';
import { standaloneEnv } from '../../../packages/xrpl/src/env.ts';
import { fundAccount } from '../../../packages/xrpl/src/fund.ts';
import { xrplLink } from '../../../packages/xrpl/src/watcher/index.ts';
import { blockableProxy, closeLedgerWith, until } from '../../../packages/xrpl/test-int/watcher/support.ts';
import { NOTIFY_CHANNEL, pgNotify, type Step, WatcherService } from '../src/index.ts';
import { freshPgDatabase } from './support.ts';

const env = standaloneEnv(process.env.XRPLD_WS ?? 'ws://127.0.0.1:6112');
const WALLET = 'rKillTestWallet';

describe('P3.5-01 a real kill between the three writes', () => {
  it.each(['observation', 'outbox', 'cursor'] as Step[])(
    'SIGKILL after the %s write: none of the three survive',
    async (step) => {
      const url = await freshPgDatabase();
      const db = openPg(url, 2);
      await db.migrate();
      const run = (kill?: string) =>
        spawnSync(process.execPath, ['services/watcher/test-int/kill-child.ts'], {
          env: { ...process.env, LEGX_PG_URL: url, ...(kill ? { LEGX_KILL_AFTER: kill } : {}) },
          cwd: process.cwd(),
        });
      const killed = run(step);
      expect(killed.signal).toBe('SIGKILL');
      const counts = async () => ({
        obs: (await db.repos.ledgerObservations.listForAccount(WALLET, 0)).length,
        outbox: (await db.repos.outbox.claim(100)).length, // a read-only look: the transaction ends with this statement
        cursor: await db.repos.watcherCursors.get(WALLET),
      });
      expect(await counts()).toEqual({ obs: 0, outbox: 0, cursor: undefined });
      const ok = run();
      expect(ok.status, String(ok.stderr)).toBe(0);
      expect(await counts()).toEqual({ obs: 1, outbox: 1, cursor: 41 });
      await db.close();
    },
  );
});

describe('T-I-08 through the service: real xrpld, real Postgres', () => {
  let admin: Client;
  beforeAll(async () => {
    admin = await connect(env);
  });
  afterAll(async () => {
    await admin.disconnect();
  });

  it('50 ledgers behind a refusing proxy: every transaction once, outbox rows and notifications for each', async () => {
    const w1 = (await fundAccount(env, admin, 100)).classicAddress;
    const w2 = (await fundAccount(env, admin, 100)).classicAddress;
    const url = await freshPgDatabase();
    const db = openPg(url, 4);
    await db.migrate();
    const head = (await admin.request({ command: 'ledger', ledger_index: 'validated' })).result.ledger_index;
    for (const a of [w1, w2]) await db.repos.watcherCursors.advance(a, head);
    const listener = new pg.Client({ connectionString: url });
    await listener.connect();
    await listener.query(`LISTEN ${NOTIFY_CHANNEL}`);
    const notified: string[] = [];
    listener.on('notification', (n) => void notified.push(n.payload ?? ''));

    const proxy = await blockableProxy(env.wsUrl);
    const svc = new WatcherService({
      db,
      servers: [xrplLink('primary', proxy.url, { timeoutMs: 3000 })],
      accounts: [w1, w2],
      deals: async () => [],
      evidence: async () => undefined,
      notify: pgNotify(db),
      pollMs: 300,
    });
    const expected: string[] = [];
    try {
      await svc.start();
      for (const t of await closeLedgerWith(admin, [w1])) expected.push(t.hash);
      proxy.block();
      for (let i = 0; i < 50; i++) {
        const dests = i % 5 === 0 ? [] : i % 3 === 0 ? [w1, w2] : [i % 2 ? w1 : w2];
        for (const t of await closeLedgerWith(admin, dests)) expected.push(t.hash);
      }
      proxy.unblock();
      const stored = async () => [
        ...(await db.repos.ledgerObservations.listForAccount(w1, 0)),
        ...(await db.repos.ledgerObservations.listForAccount(w2, 0)),
      ];
      const settle = async () => {
        for (const t0 = Date.now(); (await stored()).length < expected.length; ) {
          if (Date.now() - t0 > 60_000) throw new Error('timed out waiting for the backfill');
          await new Promise((r) => setTimeout(r, 200));
        }
      };
      await settle();
      for (const t of await closeLedgerWith(admin, [w2])) expected.push(t.hash); // a ledger closed while connected
      await settle();
      await svc.idle();
      const hashes = (await stored()).map((r) => r.tx_hash.toUpperCase());
      expect(hashes.sort()).toEqual([...expected].sort());
      const out = await db.repos.outbox.claim(10_000);
      expect(out.filter((r) => r.topic === 'ledger.observation')).toHaveLength(expected.length);
      let validated = 0; // OD-9: a ledger closed while connected is pushed
      for (const t0 = Date.now(); validated === 0 && Date.now() - t0 < 15_000; ) {
        await new Promise((r) => setTimeout(r, 100));
        validated = (await db.repos.outbox.claim(10_000)).filter((r) => r.topic === 'ledger.validated').length;
      }
      expect(validated).toBeGreaterThan(0);
      await until(
        'the notifications',
        () => notified.includes('ledger.observation') && notified.includes('ledger.validated'),
        10_000,
      );
    } finally {
      await svc.stop();
      await proxy.close();
      await listener.end();
      await db.close();
    }
  });
});
