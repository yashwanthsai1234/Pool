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
const PORT = 8791;
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
  const dir = mkdtempSync(join(tmpdir(), 'legx-product-'));
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

describe('product demo', () => {
  it("Alice and Bob approve every stage; Bob gets 25 XRP; the NFT was the deal wallet's", async () => {
    const alice = (await post('/demo/participants', { name: 'Alice' })).body;
    const bob = (await post('/demo/participants', { name: 'Bob' })).body;
    const carol = (await post('/demo/participants', { name: 'Carol' })).body;
    expect(alice.rid).toMatch(/^rid_[a-z2-7]{16}$/);
    expect(alice.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect((await get('/demo/participants')).map((p: Json) => p.name)).toEqual(['Alice', 'Bob', 'Carol']);

    const form = new FormData();
    form.set('senderRid', alice.rid);
    form.set('recipientRid', bob.rid);
    form.set('amountXrp', '25');
    form.set('terms', '1 crate of demo goods');
    form.set('contractPdf', new Blob([PDF], { type: 'application/pdf' }), 'contract.pdf');
    const cr = await fetch(`${S}/demo/deals`, { method: 'POST', body: form });
    const created = (await cr.json()) as Json;
    expect(cr.status, JSON.stringify(created)).toBe(200);
    const id = created.id as string;
    expect(created.contract.sha256).toBe(createHash('sha256').update(PDF).digest('hex'));
    expect(created.stages[0].status).toBe('done');
    expect(created.escrow.status).toBe('not funded');
    expect(Buffer.from(await (await fetch(created.contract.pdfUrl)).arrayBuffer())).toEqual(PDF);

    // wrong actor, wrong order
    expect((await post(`/demo/deals/${id}/approve`, { rid: bob.rid, stage: 2 })).status).toBe(403);
    expect((await post(`/demo/deals/${id}/approve`, { rid: carol.rid, stage: 2 })).status).toBe(403);
    expect((await post(`/demo/deals/${id}/approve`, { rid: alice.rid, stage: 7 })).status).toBe(403); // auto
    expect((await post(`/demo/deals/${id}/approve`, { rid: alice.rid, stage: 4 })).status).toBe(409);
    expect((await post(`/demo/deals/${id}/approve`, { rid: bob.rid, stage: 3 })).status).toBe(409);

    const client = await connect(standaloneEnv(LEDGER));
    const balance = async (a: string) =>
      BigInt(
        (await client.request({ command: 'account_info', account: a, ledger_index: 'validated' })).result.account_data
          .Balance,
      );
    try {
      let bobBefore = 0n;
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
        if (stage === 11) bobBefore = await balance(bob.xrplAddress);
        const r = await post(`/demo/deals/${id}/approve`, { rid: who.rid, stage });
        expect(r.status, JSON.stringify(r.body).slice(0, 2000)).toBe(200);
        last = r.body;
      }
      expect(await balance(bob.xrplAddress)).toBe(bobBefore + 25_000_000n);

      const s = await get(`/demo/deals/${id}`);
      expect(s).toEqual(last);
      expect(s.status).toBe('released');
      expect(s.stages.map((x: Json) => x.status)).toEqual(Array(14).fill('done'));
      expect(s.escrow.status).toBe('released');
      for (const k of ['keys', 'passports', 'approvals']) expect([s.escrow[k].done, s.escrow[k].of], k).toEqual([2, 2]);
      expect(s.escrow.approvals.by.map((b: Json) => b.name)).toEqual(['Alice', 'Bob']);
      for (const b of s.releasedBy) expect(b.signatureFingerprint).toMatch(/^[0-9a-f]{16}$/);
      expect(s.contract.nftOwner).toBe(s.escrow.walletAddress);
      expect(s.gate.passed).toBe(true);
      expect(s.gate.findings).toHaveLength(17);
      for (const k of ['fundTx', 'releaseTx', 'closeTx']) expect(s.escrow[k], k).toMatch(/^[0-9A-F]{64}$/);
      expect((await get('/demo/deals?status=released')).map((d: Json) => d.id)).toEqual([id]);
      expect(await get('/demo/deals?status=locked')).toEqual([]);

      // every transaction validated tesSUCCESS; the NFT went to Alice before the wallet was deleted
      for (const h of s.stages.flatMap((x: Json) => x.txHashes)) {
        const tx = (await client.request({ command: 'tx', transaction: h })).result as unknown as Json;
        expect(tx.validated && tx.meta.TransactionResult, h).toBe('tesSUCCESS');
      }
      const mint = (await client.request({ command: 'tx', transaction: s.contract.mintTx })).result as unknown as Json;
      expect(Buffer.from(mint.tx_json.URI, 'hex').toString()).toBe(s.contract.pdfUrl);
      expect(Buffer.from(mint.tx_json.Memos[0].Memo.MemoData, 'hex').toString('hex')).toBe(s.contract.sha256);
      const nfts = await client.request({
        command: 'account_nfts',
        account: alice.xrplAddress,
        ledger_index: 'validated',
      });
      expect(nfts.result.account_nfts.map((n) => n.NFTokenID)).toContain(s.contract.nftId);
      await expect(
        client.request({ command: 'account_info', account: s.escrow.walletAddress, ledger_index: 'validated' }),
      ).rejects.toMatchObject({ data: { error: 'actNotFound' } });
    } finally {
      await client.disconnect();
    }

    // feed rows: one walkthrough.step row per stage, carrying both deal IDs
    const c = new pg.Client({ connectionString: db?.url });
    await c.connect();
    try {
      const rows = await c.query<{ payload: Buffer }>(
        `select payload from outbox where deal_id = $1 and topic = 'walkthrough.step' order by seq`,
        [created.dealId],
      );
      const product = rows.rows.map((r) => JSON.parse(r.payload.toString())).filter((p) => p.productDealId === id);
      expect(product.map((p) => p.stage.n)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
      expect(product.every((p) => p.dealId === created.dealId)).toBe(true);
    } finally {
      await c.end();
    }
    expect((await post(`/demo/deals/${id}/approve`, { rid: bob.rid, stage: 11 })).status).toBe(409);
  }, 900_000);

  it('refuses a bad deal form', async () => {
    const r = await fetch(`${S}/demo/deals`, { method: 'POST', body: new FormData() });
    expect(r.status).toBe(400);
    expect((await post('/demo/deals/nope/approve', { rid: 'x', stage: 2 })).status).toBe(404);
  });
});
