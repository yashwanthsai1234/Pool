// The composed system under test: the real `apps/server/src/main.ts` process (demo profile), Postgres 5520 and the
// standalone ledger 6120 in containers named `legx-sys-*`, the mock bar registry on 7080. Nothing is stubbed here:
// what the process cannot do, a test says so with `it.fails` and an issue ID.
import { type ChildProcess, spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { API_AUTH_HEADER } from '@legx/contracts/api';
import { pinEnrollmentKey } from '@legx/coordinator';
import { apiRequestMessage } from '@legx/coordinator/auth';
import type { CoordinatorDeps } from '@legx/coordinator/deps';
import { mldsaSign, pqKeygen, toBase64 } from '@legx/core/pq';
import { openPg } from '@legx/db';
import { startRegistry } from '@legx/mock-bar-registry';
import { generateNodeSignerKeys, nodeSigner } from '@legx/signer';
import { connect } from '@legx/xrpl/connect';
import { standaloneEnv } from '@legx/xrpl/env';
import { ed25519 } from '@noble/curves/ed25519.js';
import pg from 'pg';
import { WebSocket } from 'ws';

export const ROOT = resolve(import.meta.dirname, '../../..');
export const PG_URL = process.env.LEGX_SYS_PG ?? 'postgres://postgres:pw@127.0.0.1:5520/postgres';
export const LEDGER_WS = process.env.LEGX_SYS_LEDGER ?? 'ws://127.0.0.1:6120';
/** The container names (`LEGX_SYS_PG_CONTAINER`, `LEGX_SYS_LEDGER_CONTAINER`): SYS-I2 execs into one, SYS-R2 pauses the other. */
export const PG_CONTAINER = process.env.LEGX_SYS_PG_CONTAINER ?? 'legx-sys-pg';
export const LEDGER_CONTAINER = process.env.LEGX_SYS_LEDGER_CONTAINER ?? 'legx-sys-xrpld';
export const REGISTRY_PORT = Number(process.env.LEGX_SYS_REGISTRY_PORT ?? 7080);
/** The server port; the web dev proxy reads it from LEGX_PORT (apps/web/vite.config.ts). */
export const SERVER_PORT = Number(process.env.LEGX_SYS_SERVER_PORT ?? 8787);
export const SERVER_URL = `http://127.0.0.1:${SERVER_PORT}`;

export const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

export interface Holder {
  pairId: string;
  edSecret: Uint8Array;
  edPub: Uint8Array;
  pqSecret: Uint8Array;
  pqPub: Uint8Array;
}

export function makeHolder(prefix: string): Holder {
  const edSecret = new Uint8Array(randomBytes(32));
  const pq = pqKeygen();
  return {
    pairId: `${prefix}-${randomBytes(3).toString('hex')}`,
    edSecret,
    edPub: ed25519.getPublicKey(edSecret),
    pqSecret: pq.secretKey,
    pqPub: pq.publicKey,
  };
}

/** A JSON response body; tests read the fields they expect. */
// biome-ignore lint/suspicious/noExplicitAny: test code reads untyped JSON
export type Body = Record<string, any>;
/** A message of the live feed (contracts `WsServerMessage`, or the server's ledger push). */
// biome-ignore lint/suspicious/noExplicitAny: test code reads untyped JSON
export type Msg = Record<string, any>;

export interface Stack {
  url: string;
  pgUrl: string;
  dataDir: string;
  lawyer: Holder;
  logs(): string;
  /** Kills the process (SIGKILL when `hard`) and starts a new one on the same database. */
  restart(hard?: boolean): Promise<void>;
  stop(): Promise<void>;
  validatedIndex(): Promise<number>;
  /** A request signed the way a client signs it (OD-5, OD-8). */
  signed(h: Holder, method: 'GET' | 'POST', path: string, body?: unknown): Promise<{ init: RequestInit; url: string }>;
  call(h: Holder, method: 'GET' | 'POST', path: string, body?: unknown): Promise<{ status: number; body: Body }>;
  /** Pins a holder key into a deal (the only way in: keys.register answers 501, I-W-1). */
  pin(dealId: string, h: Holder, slot: 'A' | 'LA' | 'B' | 'LB', role: string): Promise<void>;
  /** Opens a signed live-feed socket and collects its messages. */
  feed(h: Holder, dealId: string, after?: number): Promise<{ messages: Msg[]; ws: WebSocket; close(): void }>;
}

const sh = (...a: string[]) => spawnSync('docker', a, { encoding: 'utf8' });

export function containersUp(): boolean {
  const out = sh('ps', '--format', '{{.Names}}').stdout;
  return out.includes(PG_CONTAINER) && out.includes(LEDGER_CONTAINER);
}

export async function startStack(): Promise<Stack> {
  const admin = new pg.Client({ connectionString: PG_URL });
  await admin.connect();
  const dbName = `sys_${randomBytes(5).toString('hex')}`;
  await admin.query(`CREATE DATABASE ${dbName}`);
  await admin.end();
  const u = new URL(PG_URL);
  u.pathname = `/${dbName}`;
  const pgUrl = u.toString();

  const registry = await startRegistry(REGISTRY_PORT);
  const ledgerClient = await connect(standaloneEnv(LEDGER_WS));
  const lawyer = makeHolder('lawyer-sys');
  const dataDir = mkdtempSync(join(tmpdir(), 'legx-sys-'));
  let log = '';
  let child: ChildProcess | undefined;

  const spawnServer = async () => {
    child = spawn('node', [join(ROOT, 'apps/server/src/main.ts')], {
      cwd: ROOT,
      env: {
        ...process.env,
        LEGX_PROFILE: 'demo',
        LEGX_PG: pgUrl,
        LEGX_LEDGER_WS: LEDGER_WS,
        LEGX_BAR_REGISTRY: `http://127.0.0.1:${REGISTRY_PORT}`,
        LEGX_PORT: String(SERVER_PORT),
        LEGX_DATA_DIR: dataDir,
        LEGX_LAWYER_KEYS: JSON.stringify({
          [lawyer.pairId]: { ed25519: hex(lawyer.edPub), mlDsa65: toBase64(lawyer.pqPub) },
        }),
      },
    });
    child.stderr?.on('data', (d) => {
      log += d;
    });
    child.stdout?.on('data', (d) => {
      log += d;
    });
    const end = Date.now() + 120_000;
    for (;;) {
      const ok = await fetch(`${SERVER_URL}/health`).then(
        (r) => r.ok,
        () => false,
      );
      if (ok) return;
      if (Date.now() > end || child.exitCode !== null) throw new Error(`server did not start: ${log}`);
      await new Promise((r) => setTimeout(r, 500));
    }
  };
  const kill = async (hard: boolean) => {
    const c = child;
    if (!c || c.exitCode !== null) return;
    const done = new Promise((r) => c.once('exit', r));
    c.kill(hard ? 'SIGKILL' : 'SIGTERM');
    await done;
  };

  // The stack closes ledgers itself (demo.ts), so the validated index moves: ask the ledger, not the server.
  const validatedIndex = async () => {
    const r = await ledgerClient.request({ command: 'ledger', ledger_index: 'validated' });
    return Number((r.result as unknown as { ledger_index: number }).ledger_index);
  };

  await spawnServer();

  const stack: Stack = {
    url: SERVER_URL,
    pgUrl,
    dataDir,
    lawyer,
    logs: () => log,
    async restart(hard = false) {
      await kill(hard);
      await spawnServer();
    },
    async stop() {
      await kill(false);
      await ledgerClient.disconnect();
      registry.close();
      const a = new pg.Client({ connectionString: PG_URL });
      await a.connect();
      await a.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
      await a.end();
    },
    validatedIndex,
    async signed(h, method, path, body) {
      const payload = body === undefined ? undefined : JSON.stringify(body);
      const nonce = randomBytes(32).toString('hex');
      const ledgerIndex = await validatedIndex();
      const msg = apiRequestMessage(method, path, new TextEncoder().encode(payload ?? ''), nonce, ledgerIndex);
      const auth = {
        nonce,
        ledgerIndex,
        signatures: [
          { keyid: `${h.pairId}#ed25519`, sig: toBase64(ed25519.sign(msg, h.edSecret)) },
          {
            keyid: `${h.pairId}#ml-dsa-65`,
            sig: toBase64(mldsaSign('ml-dsa-65', h.pqSecret, msg, 'legx/api-request/v1' as never)),
          },
        ],
      };
      return {
        url: `${SERVER_URL}${path}`,
        init: {
          method,
          headers: {
            [API_AUTH_HEADER]: JSON.stringify(auth),
            ...(payload === undefined ? {} : { 'content-type': 'application/json' }),
          },
          ...(payload === undefined ? {} : { body: payload }),
        },
      };
    },
    async call(h, method, path, body) {
      const s = await stack.signed(h, method, path, body);
      const res = await fetch(s.url, s.init);
      const text = await res.text();
      let parsed: unknown = text;
      try {
        parsed = JSON.parse(text);
      } catch {}
      return { status: res.status, body: parsed as Body };
    },
    async pin(dealId, h, slot, role) {
      const db = openPg(pgUrl, 2);
      const deps = {
        db,
        // pinEnrollmentKey needs only the validated ledger header and a signer for the `enrollment.pinned` event.
        ledger: {
          validatedLedger: async () => ({ ledgerIndex: await validatedIndex(), closeTime: 0, hash: '0'.repeat(64) }),
        },
        signer: nodeSigner(generateNodeSignerKeys('sys-ed' as never, 'sys-pq' as never)),
      } as unknown as CoordinatorDeps;
      try {
        await pinEnrollmentKey(deps, dealId, {
          key_id: h.pairId,
          slot,
          holder_role: role,
          ed25519_pub: hex(h.edPub),
          mldsa65_pub: toBase64(h.pqPub),
          valid_from: 0,
        } as never);
      } finally {
        await db.close();
      }
    },
    async feed(h, dealId, after = -1) {
      const s = await stack.signed(h, 'GET', '/ws');
      const header = (s.init.headers as Record<string, string>)[API_AUTH_HEADER] as string;
      const ws = new WebSocket(`ws://127.0.0.1:${SERVER_PORT}/ws?auth=${encodeURIComponent(header)}`);
      const messages: Msg[] = [];
      ws.on('message', (d) => messages.push(JSON.parse(String(d))));
      await new Promise<void>((res, rej) => {
        ws.once('open', () => res());
        ws.once('error', rej);
        ws.once('unexpected-response', (_q, r) => rej(new Error(`upgrade ${r.statusCode}`)));
      });
      ws.send(JSON.stringify({ subscribe: dealId, after }));
      return { messages, ws, close: () => ws.close() };
    },
  };
  return stack;
}

export async function waitFor(ok: () => boolean | Promise<boolean>, ms = 15_000, what = 'condition'): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await ok()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`timed out waiting for ${what}`);
}
