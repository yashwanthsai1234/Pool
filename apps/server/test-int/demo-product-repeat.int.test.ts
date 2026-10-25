// The product demo (build/PRODUCT_DEMO.md) on the real demo stack: the server of `start()` over a fresh database on
// LEGX_PG_URL and the standalone ledger on XRPLD_WS. Alice and Bob register, Alice opens a 25 XRP deal with a PDF, and
// each approves their own stages until the funds reach Bob and the deal wallet is closed.
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect } from '@legx/xrpl/connect';
import { standaloneEnv } from '@legx/xrpl/env';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { start } from '../src/main.ts';
import { freshDb } from './support/pg.ts';

const LEDGER = process.env.XRPLD_WS ?? 'ws://127.0.0.1:6200';
const PORT = 8792;
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

let state = '';
let stack: Awaited<ReturnType<typeof start>> | undefined;
let db: Awaited<ReturnType<typeof freshDb>> | undefined;

beforeAll(async () => {
  db = await freshDb();
  const dir = mkdtempSync(join(tmpdir(), 'legx-product-'));
  state = join(dir, 'state.json');
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

// biome-ignore lint/suspicious/noExplicitAny: the JSON answers are checked field by field
type Json = Record<string, any>;

const post = async (path: string, body: unknown) => {
  const r = await fetch(`${S}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: r.status, body: (await r.json()) as Json };
};
const get = async (path: string) => (await (await fetch(`${S}${path}`)).json()) as Json;
const PDF = Buffer.from('%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n');

describe('product demo, repeated deals', () => {
  it('creates, fully releases, and creates again three times in a row', async () => {
    const alice = (await post('/demo/participants', { name: 'Alice' })).body;
    const bob = (await post('/demo/participants', { name: 'Bob' })).body;
    for (let i = 0; i < 3; i++) {
      const form = new FormData();
      form.set('senderRid', alice.rid);
      form.set('recipientRid', bob.rid);
      form.set('amountXrp', '2');
      form.set('terms', `round ${i}`);
      form.set('contractPdf', new Blob([PDF], { type: 'application/pdf' }), 'contract.pdf');
      const cr = await fetch(`${S}/demo/deals`, { method: 'POST', body: form });
      const created = (await cr.json()) as Json;
      expect(cr.status, `deal ${i + 1}: ${JSON.stringify(created)}`).toBe(200);
      let last: Json = created;
      for (const [who, stage] of [
        [alice, 2],
        [bob, 3],
        [alice, 4],
        [bob, 5],
        [alice, 6],
        [bob, 8],
        [alice, 9],
        [alice, 10],
        [bob, 11],
      ] as const) {
        const r = await post(`/demo/deals/${created.id}/approve`, { rid: who.rid, stage });
        expect(r.status, JSON.stringify(r.body).slice(0, 1000)).toBe(200);
        last = r.body;
      }
      expect(last.status).toBe('released');
      // a re-seed on disk (new keys) must not change what the running server signs with
      writeFileSync(
        state,
        JSON.stringify({
          version: 1,
          network: 'standalone',
          observer: demoKey('observer'),
          keys: { 'lawyer-a': demoKey('lawyer-a'), 'lawyer-b': demoKey('lawyer-b'), operator: demoKey('operator') },
        }),
      );
    }
  }, 1_500_000);
});
