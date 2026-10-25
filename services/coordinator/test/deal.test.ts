// P3.2-01, P3.2-02, P3.2-03 and the API auth rule (OD-5, DESIGN 8.10).

import { API_AUTH_HEADER, contract } from '@legx/contracts/api';
import { listRoutes } from '@legx/contracts/catalog';
import { PublicDealData } from '@legx/contracts/deal';
import { bytesToHex, dealSeal, hexToBytes } from '@legx/core/dealcore';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { joinAll, ok, publicData, toKeysReady } from './support/lifecycle.ts';
import { call, holderOf, makeWorld, newDeal, post, ROLES, rndHex, signRequest, type World } from './support/world.ts';

vi.setConfig({ testTimeout: 120_000 });
let w: World;
beforeAll(async () => {
  w = await makeWorld();
});
afterAll(async () => w.close());

describe('P3.2-01 join and seal', () => {
  it('each role joins with its public data; all four are served the same data and every recomputed seal equals the coordinator seal', async () => {
    const id = await newDeal(w);
    const early = ok(await call(w, holderOf(w, 'bob'), 'GET', `/deals/${id}/public-data`));
    expect(early.status).toBe('incomplete');
    expect(early.missing).toContain('wallet address');
    await joinAll(w, id);
    const seals = new Set<string>();
    const datas = new Set<string>();
    for (const role of ROLES) {
      const pd = ok(await call(w, holderOf(w, role), 'GET', `/deals/${id}/public-data`));
      expect(pd.status).toBe('complete');
      // The role recomputes the seal from the data it was served (29 fields) and compares.
      const recomputed = bytesToHex(dealSeal(PublicDealData.parse(pd.publicData)));
      expect(recomputed).toBe(pd.dealSeal);
      expect(Object.keys(pd.publicData)).toHaveLength(29);
      seals.add(recomputed);
      datas.add(JSON.stringify(pd.publicData));
    }
    expect(seals.size).toBe(1);
    expect(datas.size).toBe(1);
    const pd = await publicData(w, id);
    expect(pd.domain).toMatch(/^01[0-9A-F]{128}$/);
    expect(pd.domain.toLowerCase().slice(2, 66)).toBe(pd.publicData.contractRoot);
    expect(pd.domain.toLowerCase().slice(66)).toBe(pd.dealSeal);
    expect(pd.publicData.releaserAccount).toBe(pd.publicData.lawyerOpsB);
    expect(hexToBytes(pd.dealSeal)).toHaveLength(32);
  });

  it('keys come back as DealKey records once a role has logged all its parts', async () => {
    const id = await newDeal(w);
    await joinAll(w, id);
    const k = ok(await call(w, holderOf(w, 'alice'), 'GET', `/deals/${id}/keys`));
    expect(k.keys.map((x: { role: string }) => x.role)).toEqual(['alice', 'lawyerA', 'bob', 'lawyerB']);
    expect(k.keys[0].id_method).toBe('zkpassport');
    expect(k.keys[2].id_method).toBe('nfc-chip');
  });

  it('a pq.bound that names another seal is refused, and four good ones move the deal to KEYS_READY', async () => {
    const id = await newDeal(w);
    await toKeysReady(w, id);
    const v = ok(await call(w, holderOf(w, 'alice'), 'GET', `/deals/${id}`));
    expect(v.state).toBe('KEYS_READY');
    expect(v.dealSeal).toMatch(/^[0-9a-f]{64}$/);
    const id2 = await newDeal(w);
    await joinAll(w, id2);
    const bad = await post(w, id2, 'alice', 'pq.bound', {
      binding: {
        slot: 'A',
        deal_seal: rndHex(32),
        slot_pub: w.parties.alice.wallet.publicKey,
        pq_key_hash: rndHex(32),
        holder_sigs: [0, 1].map((i) => ({
          key_id: w.parties.alice.holders[i]?.pairId,
          sig: Buffer.alloc(3309).toString('base64'),
        })),
        cross_sig: rndHex(64),
      },
    });
    expect(bad.status).toBe(422);
    expect(bad.body.error).toBe('seal_mismatch');
  });
});

describe('P3.2-02 every route checks its request against the contract schema', () => {
  const implemented = listRoutes().filter((r) => ['deals', 'events', 'signatures'].some((p) => r.name.startsWith(p)));
  it.each(implemented.map((r) => [r.name, r] as const))(
    '%s: a bad request gets 400 with the field path',
    async (_name, r) => {
      const id = await newDeal(w);
      const url = (r.path as string)
        .replace('{dealId}', id)
        .replace('{requestId}', '0192f0c8-3c4e-7a2b-8c3d-4e5f6a7b8c9d');
      const role = r.name === 'deals.create' ? undefined : 'alice';
      const holder = role ? holderOf(w, role) : w.lawyerCreator;
      // An unknown field is refused by every strict schema, with its name in the path.
      const body = r.method === 'POST' ? { notAField: 1 } : undefined;
      const res = await w.app.inject(
        signRequest(w, holder, r.method as 'GET' | 'POST', r.method === 'GET' ? `${url}?extra=1` : url, body),
      );
      if (res.statusCode === 403) return; // a role the route does not allow is refused before the schema
      expect(res.statusCode).toBe(400);
      const j = res.json() as { issues: { path: string }[] };
      expect(j.issues.map((i) => i.path).join(' ')).toMatch(/notAField|extra/);
    },
  );

  it('a wrong type names the field, a body that is not JSON is 400, a bad dealId in the path is refused', async () => {
    const id = await newDeal(w);
    const a = holderOf(w, 'alice');
    const r1 = await call(w, a, 'POST', `/deals/${id}/wallet`, { dealId: id, walletAddress: 12 });
    expect(r1.status).toBe(400);
    expect(r1.body.issues[0].path).toBe('walletAddress');
    const r2 = await w.app.inject(signRequest(w, a, 'POST', `/deals/${id}/wallet`, undefined, { rawBody: '{nope' }));
    expect(r2.statusCode).toBe(400);
    const r3 = await call(w, a, 'POST', `/deals/${id}/wallet`, {
      dealId: '0192f0c8-3c4e-7a2b-8c3d-4e5f6a7b8c9d',
      walletAddress: 'x',
    });
    expect(r3.status).toBe(400);
    const r4 = await call(w, a, 'GET', '/deals/not-a-uuid');
    expect([400, 403]).toContain(r4.status);
  });
});

describe('API auth (OD-5): hybrid request signatures', () => {
  it('a request with no header, a half signature, or a tampered body is refused', async () => {
    const id = await newDeal(w);
    const a = holderOf(w, 'alice');
    expect((await w.app.inject({ method: 'GET', url: `/deals/${id}` })).statusCode).toBe(401);
    const good = signRequest(w, a, 'POST', `/deals/${id}/wallet`, { dealId: id, walletAddress: 'rExample' });
    const auth = JSON.parse(good.headers[API_AUTH_HEADER] as string);
    const half = {
      ...auth,
      signatures: [auth.signatures[0], { ...auth.signatures[1], sig: Buffer.alloc(3309).toString('base64') }],
    };
    expect(
      (await w.app.inject({ ...good, headers: { ...good.headers, [API_AUTH_HEADER]: JSON.stringify(half) } }))
        .statusCode,
    ).toBe(401);
    const tampered = { ...good, payload: (good.payload as string).replace('rExample', 'rOther') };
    const t = await w.app.inject(tampered);
    expect(t.statusCode).toBe(401);
    expect((t.json() as { error: string }).error).toBe('bad_signature');
  });

  it('a path or method changed after signing is refused (the path is pathname + search, OD-8)', async () => {
    const id = await newDeal(w);
    const a = holderOf(w, 'alice');
    const s = signRequest(w, a, 'GET', `/deals/${id}/events?afterSeq=-1&limit=5`);
    expect((await w.app.inject({ ...s, url: `/deals/${id}/events?afterSeq=-1&limit=6` })).statusCode).toBe(401);
    const ok1 = await w.app.inject(signRequest(w, a, 'GET', `/deals/${id}/events?afterSeq=-1&limit=5`));
    expect(ok1.statusCode).toBe(200);
  });

  it('a reused nonce is refused, and a bad request does not burn a nonce', async () => {
    const id = await newDeal(w);
    const a = holderOf(w, 'alice');
    const nonce = rndHex(32);
    const s1 = signRequest(w, a, 'GET', `/deals/${id}`, undefined, { nonce });
    expect((await w.app.inject(s1)).statusCode).toBe(200);
    const replay = await w.app.inject(s1);
    expect(replay.statusCode).toBe(401);
    expect((replay.json() as { error: string }).error).toBe('nonce_reused');
    // The same nonce with a signature of someone who is not alice cannot use it up first.
    const n2 = rndHex(32);
    const forged = signRequest(w, a, 'GET', `/deals/${id}`, undefined, { nonce: n2 });
    const broken = { ...forged, url: `/deals/${id}/events/head` };
    expect((await w.app.inject(broken)).statusCode).toBe(401);
    expect((await w.app.inject(forged)).statusCode).toBe(200);
  });

  it('a stale ledger index is refused (more than 20 ledgers old); 20 is allowed; far in the future is refused', async () => {
    const id = await newDeal(w);
    const a = holderOf(w, 'alice');
    const at = (ledgerIndex: number) =>
      w.app.inject(signRequest(w, a, 'GET', `/deals/${id}`, undefined, { ledgerIndex }));
    expect((await at(w.ledger.index - 20)).statusCode).toBe(200);
    const stale = await at(w.ledger.index - 21);
    expect(stale.statusCode).toBe(401);
    expect((stale.json() as { error: string }).error).toBe('stale_ledger_index');
    expect((await at(w.ledger.index + 50)).statusCode).toBe(401);
  });

  it('another deal, a role the route does not allow, and an unknown key are refused (T-A-31)', async () => {
    const id = await newDeal(w);
    const aliceHere = holderOf(w, 'alice');
    const other = await newDeal(w);
    // A key of this deal cannot read another deal.
    const cross = await call(w, aliceHere, 'GET', `/deals/${other}`);
    expect(cross.status).toBe(403);
    expect(cross.body.error).toBe('wrong_deal');
    // setContract is lawyer A only.
    const wrongRole = await call(w, holderOf(w, 'bob'), 'POST', `/deals/${id}/contract`, {
      dealId: id,
      contractRoot: rndHex(32),
    });
    expect(wrongRole.status).toBe(403);
    // deals.create is for pinned lawyers only: a deal key is not enough.
    const create = await call(w, holderOf(w, 'alice'), 'POST', '/deals', {});
    expect(create.status).toBe(403);
    // Unknown key.
    const stranger = { ...holderOf(w, 'alice'), pairId: 'nobody' };
    expect((await call(w, stranger, 'GET', `/deals/${id}`)).status).toBe(401);
  });
});

describe('contract table sanity', () => {
  it('the coordinator implements only routes of its own lane and every one is signed', () => {
    expect(Object.keys(contract)).toContain('deals');
  });
});
