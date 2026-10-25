// The wiring audit as tests (IMPLEMENTATION Phase 6, wave "wiring audit"): for every contract route, outbox topic, event
// kind and port, a real producer and a real consumer must be connected in the composed server, outside the tests.
// `it.fails(...)` is a known gap with its issue ID: the test flips (and must be changed to `it`) when the issue is fixed.
import { execSync } from 'node:child_process';
import { listRoutes } from '@legx/contracts/catalog';
import { EventKind } from '@legx/contracts/events';
import { OutboxTopic } from '@legx/contracts/ws';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createDeal, type Deal } from '../support/deal.ts';
import { walletObserved } from '../support/probes.ts';
import {
  containersUp,
  LEDGER_CONTAINER,
  makeHolder,
  PG_CONTAINER,
  type Stack,
  startStack,
  waitFor,
} from '../support/stack.ts';

let stack: Stack;
let deal: Deal;
const sql = async <T extends object>(text: string, params: unknown[] = []) => {
  const c = new pg.Client({ connectionString: stack.pgUrl });
  await c.connect();
  try {
    return (await c.query(text, params)).rows as T[];
  } finally {
    await c.end();
  }
};

beforeAll(async () => {
  if (!containersUp())
    throw new Error(
      `start ${PG_CONTAINER} and ${LEDGER_CONTAINER} first (LEGX_SYS_PG, LEGX_SYS_LEDGER, LEGX_SYS_*_CONTAINER)`,
    );
  stack = await startStack();
  deal = await createDeal(stack);
}, 180_000);
afterAll(async () => {
  await stack?.stop();
});

// ---- routes: every contract route is mounted and does not answer 501 after authentication ----
const KNOWN_501: Record<string, string> = {
  'bar.manualEvidence': 'I-3.7-d / I-W-9 (no operator key can authenticate: operatorKeys is () => undefined)',
};
const uuid = '01a171ec-6b00-7228-8339-013593d69479';
describe('W-ROUTES every contract route is served', () => {
  for (const r of listRoutes()) {
    const gap = KNOWN_501[r.name];
    (gap ? it.fails : it)(`${r.name} ${r.method} ${r.path}${gap ? ` (${gap})` : ''}`, async () => {
      const path = (r.path as string)
        .replace('{dealId}', deal.dealId)
        .replace('{requestId}', uuid)
        .replace('{sessionId}', uuid)
        .replace('{recoveryId}', uuid)
        .replace('{sha256}', '0'.repeat(64))
        .replace('{keyId}', deal.alice.pairId)
        .replace('{side}', 'A')
        .replace('{address}', 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh');
      // The role each route wants: a pinned party key for deal routes; the lawyer key for lawyer routes.
      const holder =
        r.name === 'bar.dealLink' || r.name.startsWith('zk.') || r.name === 'firmHsm.sign'
          ? deal.lawyerA
          : r.name.startsWith('bar.') || r.name === 'deals.create'
            ? stack.lawyer
            : deal.alice;
      const body = r.method === 'POST' ? sampleBody(r.name) : undefined;
      const res = await stack.call(holder, r.method as 'GET' | 'POST', path, body);
      expect(res.status, JSON.stringify(res.body)).not.toBe(501);
      expect(res.status, JSON.stringify(res.body)).not.toBe(404);
      expect(res.status, `no key can authenticate here: ${JSON.stringify(res.body)}`).not.toBe(401);
    });
  }
});
const sampleBody = (name: string): unknown =>
  name === 'signatures.create'
    ? { purpose: 'pay_bob' }
    : name === 'bar.verify'
      ? { opsAccount: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh', jurisdiction: 'XA', barNumber: '1' }
      : {};

describe('W-PURPOSES every signature purpose of the contract is built', () => {
  for (const p of ['ticket_create', 'signer_list_update', 'seal_update', 'escrow_finish'])
    it.fails(`signatures.create purpose ${p} (I-14)`, async () => {
      const res = await stack.call(deal.alice, 'POST', `/deals/${deal.dealId}/signature-requests`, { purpose: p });
      expect(res.status, JSON.stringify(res.body)).not.toBe(501);
    });
});

// ---- outbox topics and the live feed ----
describe('W-OUTBOX every outbox topic has a producer and the feed delivers it', () => {
  it('deal.event rows are written and reach a signed live-feed socket', async () => {
    const feed = await stack.feed(deal.alice, deal.dealId);
    await waitFor(
      () => feed.messages.some((m) => m.type === 'row' && m.topic === 'deal.event'),
      10_000,
      'a deal.event row',
    );
    feed.close();
  });
  it('ledger.validated reaches the feed as a push of the server (OD-9)', async () => {
    const feed = await stack.feed(deal.alice, deal.dealId);
    await waitFor(() => feed.messages.some((m) => m.type === 'ledger'), 10_000, 'a ledger push');
    feed.close();
  });
  // signature.request rows exist only after a signature request is created, which deals.create does not do.
  for (const topic of OutboxTopic.options.filter((t) => t === 'deal.state' || t === 'signature.request'))
    (topic === 'signature.request' ? it.fails : it)(`a producer writes topic ${topic} (I-W-5)`, async () => {
      await new Promise((r) => setTimeout(r, 1500));
      const rows = await sql('select 1 from outbox where topic = $1 limit 1', [topic]);
      expect(rows.length).toBe(1);
    });
  it('the contract lists ledger.validated, the topic the server really pushes (I-3.7-b)', () => {
    expect(OutboxTopic.options as readonly string[]).toContain('ledger.validated');
  });
  it('a row written by deals.create wakes the feed by pg_notify, not by the 1 s poll (I-3.7-a)', async () => {
    const c = new pg.Client({ connectionString: stack.pgUrl });
    await c.connect();
    await c.query('LISTEN legx_outbox');
    const got: string[] = [];
    c.on('notification', (m) => got.push(m.payload ?? ''));
    const d = await createDeal(stack);
    await new Promise((r) => setTimeout(r, 700));
    await c.end();
    expect(got).toContain(d.dealId);
  });
});

// ---- watcher: it must watch the deal wallets it is told about ----
describe('W-WATCHER', () => {
  it('the watcher observes transactions of a deal wallet after deals.setWallet (I-W-4: deals() is a constant [])', async () => {
    expect(await walletObserved(stack, deal)).toBe(true);
  }, 60_000);
});

// ---- event kinds: every kind has a producer somewhere in the shipped server code (heuristic: the quoted kind appears
// in a non-test source file of a service that writes events, outside the validation tables) ----
const NO_PRODUCER: Record<string, string> = {
  'bar.deal_linked': 'I-3.7-d',
  'attorney.credential.issued': 'I-W-6',
  'checkpoint.anchored': 'I-W-6',
};
describe('W-EVENTS every event kind has a producer', () => {
  const sources = (kind: string) =>
    execSync(
      `grep -rlF "'${kind}'" services/*/src apps/server/src --include=*.ts | grep -v -E "/(test|test-int)/" | grep -v "evidence/src/(bundle|anchor)" || true`,
      { cwd: new URL('../../../', import.meta.url).pathname, encoding: 'utf8', shell: '/bin/bash' },
    )
      .trim()
      .split('\n')
      .filter(Boolean);
  for (const kind of EventKind.options) {
    const gap = NO_PRODUCER[kind];
    (gap ? it.fails : it)(`${kind}${gap ? ` (${gap})` : ''}`, () => {
      expect(sources(kind), `no shipped service mentions ${kind}`).not.toEqual([]);
    });
  }
});

// ---- ports: demo ports that stand in for real wiring ----
describe('W-PORTS every port is a real implementation, and every service port is used', () => {
  let health: { ports: Record<string, { impl: string; status: string }> };
  beforeAll(async () => {
    health = (await (await fetch(`${stack.url}/health`)).json()) as typeof health;
  });
  it('every port reports ok', () => {
    for (const [n, p] of Object.entries(health.ports)) expect(p.status, n).toBe('ok');
  });
  it('release-gate is the real gate of @legx/core, not a stub (I-3.7-g)', () => {
    expect(health.ports['release-gate']?.impl).not.toBe('stub');
  });
  it('the ZK verifier port is used by a route: zk.verify verifies and stores (I-3.7-d)', async () => {
    const res = await stack.call(deal.lawyerA, 'POST', `/deals/${deal.dealId}/zk/verify`, {});
    expect(res.status).not.toBe(501);
  });
  it('a TSA port is composed, so evidence gets RFC 3161 timestamps (I-W-7)', () => {
    expect(Object.keys(health.ports)).toContain('tsa');
  });
  it('the checkpoint job is registered: a checkpoint anchor exists after 3 s (I-W-6)', async () => {
    await new Promise((r) => setTimeout(r, 3000));
    expect((await sql('select 1 from checkpoint_anchor limit 1')).length).toBe(1);
  });
  it('a key can be enrolled through the API without direct database access (I-W-1)', async () => {
    const k = makeHolder('new');
    const res = await stack.call(k, 'POST', '/enrollment-keys', {});
    expect(res.status).not.toBe(501);
  });
});
