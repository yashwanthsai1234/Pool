// The real process (P3.7-01, P3.7-05, P3.7-06 health): `node apps/server/src/main.ts` against Postgres 5510, the standalone
// ledger 6113 and the mock bar registry; and the production profile refusing to start with demo settings.
import { type ChildProcess, spawn, spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { startRegistry } from '@legx/mock-bar-registry';
import { pgNotify, WatcherService } from '@legx/watcher';
import { connect } from '@legx/xrpl/connect';
import { standaloneEnv } from '@legx/xrpl/env';
import { advanceLedgers } from '@legx/xrpl/ledger';
import { xrplLink } from '@legx/xrpl/watcher/index';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { uuid7 } from '../../../services/coordinator/src/uuid.ts';
import { pgLiveSource } from '../src/pgSource.ts';
import { Client, hubServer } from '../test/support/feed.ts';
import { freshDb } from './support/pg.ts';

const root = resolve(import.meta.dirname, '../../..');
const MAIN = join(root, 'apps/server/src/main.ts');
const LEDGER = process.env.LEGX_37_LEDGER ?? process.env.XRPLD_WS ?? 'ws://127.0.0.1:6113';
const PORT = 8711;

let child: ChildProcess | undefined;
let registry: { close(cb?: () => void): void } | undefined;
let drop: (() => Promise<void>) | undefined;
let out = '';

beforeAll(async () => {
  registry = await startRegistry(7070);
  const f = await freshDb({ trigger: false });
  drop = f.drop;
  await f.db.close();
  child = spawn('node', [MAIN], {
    cwd: root,
    env: {
      ...process.env,
      LEGX_PROFILE: 'demo',
      LEGX_PG: f.url,
      LEGX_LEDGER_WS: LEDGER,
      LEGX_BAR_REGISTRY: 'http://127.0.0.1:7070',
      LEGX_PORT: String(PORT),
      LEGX_DATA_DIR: mkdtempSync(join(tmpdir(), 'legx37-')),
    },
  });
  child.stderr?.on('data', (d) => {
    out += d;
  });
  child.stdout?.on('data', (d) => {
    out += d;
  });
  const end = Date.now() + 90_000;
  for (;;) {
    const ok = await fetch(`http://127.0.0.1:${PORT}/health`).then(
      (r) => r.ok,
      () => false,
    );
    if (ok) break;
    if (Date.now() > end || child.exitCode !== null) throw new Error(`server did not start: ${out}`);
    await new Promise((r) => setTimeout(r, 500));
  }
}, 120_000);

afterAll(async () => {
  child?.kill('SIGTERM');
  await new Promise((r) => child?.once('exit', r));
  registry?.close();
  await drop?.();
});

describe('P3.7-01 the started stack', () => {
  it('GET /health lists each port with its implementation and the profile, all ok', async () => {
    const body = (await (await fetch(`http://127.0.0.1:${PORT}/health`)).json()) as {
      profile: string;
      ports: Record<string, { impl: string; status: string }>;
    };
    expect(body.profile).toBe('demo');
    for (const port of [
      'coordinator',
      'frost-relay',
      'evidence',
      'verifier',
      'recovery-agent',
      'firm-cosigner',
      'zk-verifier',
      'post-quantum',
      'watcher',
      'ledger',
      'bar-registry',
      'database',
      'live-feed',
    ])
      expect(body.ports[port], port).toEqual({ impl: expect.any(String), status: 'ok' });
    expect(Object.values(body.ports).every((p) => p.status === 'ok')).toBe(true);
  });

  it('refuses an unsigned API request and carries frame-ancestors', async () => {
    const res = await fetch(`http://127.0.0.1:${PORT}/deals/${uuid7()}`);
    expect(res.status).toBe(401);
    expect(res.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
  });
});

describe('P3.7-05 the production profile refuses to start with a demo port', () => {
  const run = (env: Record<string, string>) =>
    spawnSync('node', [MAIN], {
      cwd: root,
      env: { PATH: process.env.PATH ?? '', ...env },
      encoding: 'utf8',
      timeout: 30_000,
    });

  it.each([
    ['LEGX_PROFILE=production + LEGX_DEMO_SIGNER', { LEGX_PROFILE: 'production', LEGX_DEMO_SIGNER: 'file' }],
    ['no profile (production) + LEGX_DEMO_LEDGER', { LEGX_DEMO_LEDGER: 'standalone' }],
  ])('%s: exit 1 before any connection is opened', (_n, env) => {
    const r = run({ ...env, LEGX_PORT: '8712', LEGX_PG: 'postgres://nobody@127.0.0.1:1/none' });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('production profile refuses to start: DEMO_ENV');
  });

  it('production with nothing demo builds from settings: a missing one stops the start and is named (I-3.7-g)', () => {
    const r = run({ LEGX_PROFILE: 'production', LEGX_PORT: '8712' });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('LEGX_AWS_REGION is not set');
  });
});

describe('ledger.validated reaches a socket (watcher, outbox, NOTIFY, hub)', () => {
  it('a validated ledger is pushed as {topic, payload: {index, hash, close_time}} (OD-9)', async () => {
    const f = await freshDb({ trigger: false });
    const env = standaloneEnv(LEDGER);
    const admin = await connect(env);
    const source = pgLiveSource(f.db, f.url);
    const hub = await hubServer(source, { pollMs: 500 });
    const watcher = new WatcherService({
      db: f.db,
      servers: [xrplLink('primary', env.wsUrl, { timeoutMs: 5000 })],
      accounts: ['rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh'],
      deals: async () => [],
      evidence: async () => undefined,
      notify: pgNotify(f.db),
      pollMs: 500,
    });
    try {
      await watcher.start();
      const c = new Client(hub.url, uuid7(), -1);
      await c.waitFor(() => c.ws.readyState === 1);
      await new Promise((r) => setTimeout(r, 300));
      await advanceLedgers(admin, 1);
      await c.waitFor(() => c.messages.some((m) => m.type === 'ledger'), 15_000);
      const m = c.messages.find((x) => x.type === 'ledger');
      expect(m).toMatchObject({
        topic: 'ledger.validated',
        payload: {
          index: expect.any(Number),
          hash: expect.stringMatching(/^[0-9A-F]{64}$/),
          close_time: expect.any(Number),
        },
      });
      c.close();
    } finally {
      await watcher.stop();
      await hub.close();
      await source.close();
      await admin.disconnect();
      await f.drop();
    }
  }, 60_000);
});
