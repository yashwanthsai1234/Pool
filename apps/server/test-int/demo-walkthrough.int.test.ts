// The guided walkthrough (build/WALKTHROUGH.md) on the real demo stack: the server of `start()` over a fresh database on
// LEGX_PG_URL and the standalone ledger on XRPLD_WS, driven over HTTP one step at a time, as the lawyer console does.
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect } from '@legx/xrpl/connect';
import { standaloneEnv } from '@legx/xrpl/env';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { StepResult, WalkthroughState } from '../src/demo-walkthrough/types.ts';
import { start } from '../src/main.ts';
import { freshDb } from './support/pg.ts';

const LEDGER = process.env.XRPLD_WS ?? 'ws://127.0.0.1:6200';
const PORT = 8790;
const S = `http://127.0.0.1:${PORT}`;

function demoKey(prefix: string) {
  const der = (k: { export(o: object): Buffer }, type: string) => k.export({ format: 'der', type }).toString('hex');
  const ed = generateKeyPairSync('ed25519');
  const pq = generateKeyPairSync('ml-dsa-65');
  const ed25519Public = der(ed.publicKey, 'spki');
  return {
    keyId: `${prefix}-${ed25519Public.slice(-16)}`,
    ed25519Public,
    mlDsa65Public: der(pq.publicKey, 'spki'),
    ed25519Private: der(ed.privateKey, 'pkcs8'),
    mlDsa65Private: der(pq.privateKey, 'pkcs8'),
  };
}

let stack: Awaited<ReturnType<typeof start>> | undefined;
let db: Awaited<ReturnType<typeof freshDb>> | undefined;

beforeAll(async () => {
  db = await freshDb();
  const dir = mkdtempSync(join(tmpdir(), 'legx-walk-'));
  const state = join(dir, 'state.json');
  const keys = { 'lawyer-a': demoKey('lawyer-a'), 'lawyer-b': demoKey('lawyer-b'), operator: demoKey('operator') };
  writeFileSync(state, JSON.stringify({ version: 1, network: 'standalone', observer: demoKey('observer'), keys }));
  stack = await start({
    ...process.env,
    LEGX_PROFILE: 'demo',
    LEGX_PG: db.url,
    LEGX_LEDGER_WS: LEDGER,
    LEGX_PORT: String(PORT),
    LEGX_DATA_DIR: dir,
    LEGX_DEMO_STATE: state,
  });
}, 120_000);

afterAll(async () => {
  await stack?.stop();
  await db?.drop();
});

const post = async (path: string, body?: unknown) => {
  const r = await fetch(`${S}${path}`, {
    method: 'POST',
    ...(body === undefined ? {} : { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }),
  });
  return { status: r.status, body: (await r.json()) as Record<string, unknown> };
};

describe('demo walkthrough', () => {
  it('runs every step with tesSUCCESS through release to Bob and the wallet deleted', async () => {
    const created = await post('/demo/walkthrough', { amountXrp: 50, identity: 'chip' });
    expect(created.status).toBe(200);
    const { id, dealId, steps } = created.body as unknown as WalkthroughState;
    expect(steps.filter((s) => s.skipped)).toEqual([]); // ship-core-ready exists: delivery is mandatory (OD-38)
    const runnable = steps.filter((s) => !s.skipped);

    const results: StepResult[] = [];
    for (const s of runnable) {
      const r = await post(`/demo/walkthrough/${id}/next`);
      expect(r.status, JSON.stringify(r.body)).toBe(200);
      const res = r.body as unknown as StepResult;
      expect(res.step).toBe(s.id);
      expect(res.status, res.detail).toBe('ok');
      results.push(res);
    }
    const byId = Object.fromEntries(results.map((r) => [r.step, r]));
    for (const s of ['enroll', 'contract', 'funding', 'lock', 'release', 'close'])
      expect(byId[s]?.txHashes.length, s).toBeGreaterThan(0);
    expect(byId.gate?.gate?.length).toBe(17);
    expect(byId.gate?.gate?.every((f) => f.ok)).toBe(true);
    const bob = byId.release?.bob as { before: string; after: string };
    expect(BigInt(bob.after) - BigInt(bob.before)).toBe(50_000_000n);

    // every transaction of the walk was validated tesSUCCESS on the ledger, and the wallet is gone
    const client = await connect(standaloneEnv(LEDGER));
    try {
      for (const h of results.flatMap((r) => r.txHashes)) {
        const tx = (await client.request({ command: 'tx', transaction: h })).result as {
          validated: boolean;
          meta: { TransactionResult: string };
        };
        expect(tx.validated && tx.meta.TransactionResult, h).toBe('tesSUCCESS');
      }
      const state = (await (await fetch(`${S}/demo/walkthrough/${id}`)).json()) as WalkthroughState;
      expect(state.status).toBe('done');
      await expect(
        client.request({ command: 'account_info', account: state.wallet, ledger_index: 'validated' }),
      ).rejects.toMatchObject({ data: { error: 'actNotFound' } });
    } finally {
      await client.disconnect();
    }

    // the coordinator holds the deal, and the feed has one walkthrough.step row per step
    const c = new pg.Client({ connectionString: db?.url });
    await c.connect();
    try {
      const rows = await c.query<{ topic: string }>('select topic from outbox where deal_id = $1 order by seq', [
        dealId,
      ]);
      expect(rows.rows.filter((r) => r.topic === 'deal.event').length).toBeGreaterThan(0);
      expect(rows.rows.filter((r) => r.topic === 'walkthrough.step').length).toBe(runnable.length);
    } finally {
      await c.end();
    }

    const after = await post(`/demo/walkthrough/${id}/next`);
    expect(after.status).toBe(409);
    expect(after.body.error).toBe('walkthrough_done');
  }, 600_000);

  it('refuses a bad body and an unknown walkthrough', async () => {
    expect((await post('/demo/walkthrough', { amountXrp: 50, identity: 'x' })).status).toBe(400);
    expect((await post('/demo/walkthrough/nope/next')).status).toBe(404);
  });
});
