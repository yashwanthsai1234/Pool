// The routes the fix fleet (lane F1) added to the coordinator: keys.register (DESIGN 6.3; I-W-1), the presence relay
// (DESIGN 6.15), the ledger relay (I-31), the observer key (OD-31) and the own-side rule (DESIGN 8.10).
import { ENROLLMENT_POP_TAG } from '@legx/contracts/api';
import { mldsaSign, toBase64 } from '@legx/core/pq';
import { ed25519 } from '@noble/curves/ed25519.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { enrollmentPopMessage } from '../src/enroll.ts';
import {
  call,
  type Holder,
  hex,
  holderOf,
  makeHolder,
  makeWorld,
  newDeal,
  rndHex,
  type World,
} from './support/world.ts';

let w: World;
let id: string;
beforeAll(async () => {
  w = await makeWorld();
  id = await newDeal(w);
});
afterAll(async () => w.db.close());

const keyOf = (h: Holder, slot: string) => ({
  key_id: h.pairId,
  slot,
  holder_role: h.holderRole,
  ed25519_pub: hex(h.edPub),
  mldsa65_pub: toBase64(h.pqPub),
  valid_from: 0,
});
const pop = (h: Holder, key: ReturnType<typeof keyOf>, dealId = id) => {
  const msg = enrollmentPopMessage(dealId, key as never);
  return [
    { keyid: `${h.pairId}#ed25519`, sig: toBase64(ed25519.sign(msg, h.edSecret)) },
    { keyid: `${h.pairId}#ml-dsa-65`, sig: toBase64(mldsaSign('ml-dsa-65', h.pqSecret, msg, ENROLLMENT_POP_TAG)) },
  ];
};
const register = (by: Holder, h: Holder, slot: string, proof = pop(h, keyOf(h, slot))) =>
  call(w, by, 'POST', `/deals/${id}/enrollment-keys`, { key: keyOf(h, slot), proofOfPossession: proof });

describe('keys.register (DESIGN 6.3)', () => {
  it('a primary holder pins a key of its own slot; the key then authenticates; the same key again is "exists"', async () => {
    const second = makeHolder('A', 'second-authenticator');
    const r = await register(holderOf(w, 'alice'), second, 'A');
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body).toEqual({ keyId: second.pairId, status: 'created' });
    expect((await call(w, second, 'GET', `/deals/${id}`)).status).toBe(200);
    expect((await register(holderOf(w, 'alice'), second, 'A')).body.status).toBe('exists');
  });

  it("the client's own lawyer may pin a client key; the other side and the service holders may not", async () => {
    expect((await register(holderOf(w, 'lawyerA'), makeHolder('A', 'phone'), 'A')).status).toBe(200);
    expect((await register(holderOf(w, 'lawyerB'), makeHolder('A', 'phone'), 'A')).status).toBe(403);
    expect((await register(holderOf(w, 'bob'), makeHolder('A', 'phone'), 'A')).status).toBe(403);
    expect((await register(holderOf(w, 'alice', 2), makeHolder('A', 'phone'), 'A')).status).toBe(403);
  });

  it('refuses a missing or wrong proof of possession, a role of another slot kind, and a taken key id', async () => {
    const h = makeHolder('A', 'phone');
    const other = makeHolder('A', 'phone');
    expect((await register(holderOf(w, 'alice'), h, 'A', pop(other, keyOf(h, 'A')))).status).toBe(422);
    expect((await register(holderOf(w, 'alice'), h, 'A', pop(h, keyOf(h, 'A'), rndUuid()))).status).toBe(422);
    expect((await register(holderOf(w, 'alice'), makeHolder('A', 'console'), 'A')).status).toBe(400);
    const taken = { ...makeHolder('A', 'phone'), pairId: holderOf(w, 'alice').pairId };
    expect((await register(holderOf(w, 'alice'), taken, 'A')).status).toBe(409);
  });

  it('a lawyer directory key pins itself as the console of the slot of its own operations account only', async () => {
    const self = { ...w.lawyerCreator, holderRole: 'console' };
    expect((await register(w.lawyerCreator, self, 'LB')).status).toBe(403);
    expect((await register(w.lawyerCreator, self, 'LA')).status).toBe(200);
  });
});

describe('the observer key (OD-31)', () => {
  it('reads the deal and its events, and nothing else', async () => {
    expect((await call(w, w.observer, 'GET', `/deals/${id}`)).status).toBe(200);
    expect((await call(w, w.observer, 'GET', `/deals/${id}/events?afterSeq=-1&limit=10`)).status).toBe(200);
    expect((await call(w, w.observer, 'POST', `/deals/${id}/signature-requests`, { purpose: 'pay_bob' })).status).toBe(
      403,
    );
    expect((await call(w, w.observer, 'GET', `/deals/${id}/presence/A`)).status).toBe(403);
  });
});

describe('presence relay (DESIGN 6.15)', () => {
  const request = { method: 'zkpassport', lawyerNonce: rndHex(32), ledgerHash: 'AB'.repeat(32), ledgerIndex: 999 };
  it("the side's lawyer opens, the client answers the open nonce, the lawyer reads the signature", async () => {
    expect((await call(w, holderOf(w, 'lawyerB'), 'POST', `/deals/${id}/presence/A`, { request })).status).toBe(403);
    const open = await call(w, holderOf(w, 'lawyerA'), 'POST', `/deals/${id}/presence/A`, { request });
    expect(open.body).toEqual({ status: 'open', request });
    expect((await call(w, holderOf(w, 'bob'), 'GET', `/deals/${id}/presence/A`)).status).toBe(403);
    expect((await call(w, holderOf(w, 'alice'), 'GET', `/deals/${id}/presence/A`)).body.request).toEqual(request);
    const signature = rndHex(64);
    const stale = { lawyerNonce: rndHex(32), signature };
    expect((await call(w, holderOf(w, 'alice'), 'POST', `/deals/${id}/presence/A/signature`, stale)).status).toBe(409);
    const ok = { lawyerNonce: request.lawyerNonce, signature };
    expect((await call(w, holderOf(w, 'lawyerA'), 'POST', `/deals/${id}/presence/A/signature`, ok)).status).toBe(403);
    expect((await call(w, holderOf(w, 'alice'), 'POST', `/deals/${id}/presence/A/signature`, ok)).status).toBe(200);
    expect((await call(w, holderOf(w, 'lawyerA'), 'GET', `/deals/${id}/presence/A`)).body).toEqual({
      status: 'signed',
      request,
      signature,
    });
  });
});

describe('identity box (OD-36 b): the client seals its salt and disclosure to its own lawyer', () => {
  const box = (kind: 'zk-salt' | 'zk-disclosure', key: string) => ({
    kind,
    box: {
      suite: 'hpke-xwing-v1',
      recipient_key_id: key,
      enc: Buffer.alloc(1120, 7).toString('base64'),
      ciphertext: Buffer.from(`ct-${kind}`).toString('base64'),
    },
  });
  it('the side client stores each box once; only that side lawyer console reads it back, as ciphertext', async () => {
    const lawyerKey = holderOf(w, 'lawyerA').pairId;
    const salt = box('zk-salt', lawyerKey);
    expect((await call(w, holderOf(w, 'bob'), 'POST', `/deals/${id}/identity-box/A`, salt)).status).toBe(403);
    expect((await call(w, holderOf(w, 'lawyerA'), 'POST', `/deals/${id}/identity-box/A`, salt)).status).toBe(403);
    expect((await call(w, holderOf(w, 'alice'), 'POST', `/deals/${id}/identity-box/A`, salt)).status).toBe(200);
    expect((await call(w, holderOf(w, 'alice'), 'POST', `/deals/${id}/identity-box/A`, salt)).status).toBe(409);
    await call(w, holderOf(w, 'alice'), 'POST', `/deals/${id}/identity-box/A`, box('zk-disclosure', lawyerKey));
    const got = await call(w, holderOf(w, 'lawyerA'), 'GET', `/deals/${id}/identity-box/A`);
    expect(got.status, JSON.stringify(got.body)).toBe(200);
    expect(got.body.boxes).toEqual(
      [salt, box('zk-disclosure', lawyerKey)].sort((a, b) => a.kind.localeCompare(b.kind)),
    );
    for (const who of ['alice', 'bob', 'lawyerB'] as const)
      expect((await call(w, holderOf(w, who), 'GET', `/deals/${id}/identity-box/A`)).status).toBe(403);
    expect((await call(w, w.observer, 'GET', `/deals/${id}/identity-box/A`)).status).toBe(403);
    expect((await call(w, holderOf(w, 'lawyerA'), 'GET', `/deals/${id}/identity-box/B`)).status).toBe(403);
    expect((await call(w, holderOf(w, 'lawyerB'), 'GET', `/deals/${id}/identity-box/B`)).body).toEqual({ boxes: [] });
    // nothing in the table is readable as plaintext: only the sealed fields went in
    const raw = await w.db.kysely
      .selectFrom('identity_box' as never)
      .selectAll()
      .execute();
    expect(JSON.stringify(raw)).not.toMatch(/salt32|passport|MRZ/i);
  });
});

describe('ledger relay (I-31)', () => {
  it('account_info answers from the validated ledger, and says when the account does not exist', async () => {
    const addr = w.addr.shell;
    w.ledger.accounts.set(addr, { accountData: { Flags: 8388608, Sequence: 41, Balance: '25000000' }, objects: [] });
    const r = await call(w, holderOf(w, 'alice'), 'GET', `/ledger/accounts/${addr}`);
    expect(r.body).toEqual({ exists: true, ledgerIndex: 1000, flags: 8388608, sequence: 41, balanceDrops: '25000000' });
    w.ledger.accounts.delete(addr);
    expect((await call(w, holderOf(w, 'alice'), 'GET', `/ledger/accounts/${addr}`)).body).toEqual({
      exists: false,
      ledgerIndex: 1000,
    });
  });
});

function rndUuid(): string {
  const h = rndHex(16);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-7${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20)}`;
}

describe('deals.mine (I-W-10)', () => {
  it('a lawyer directory key lists the deals of its operations account; the observer lists all; a deal key its own', async () => {
    const mine = await call(w, w.lawyerCreator, 'GET', '/deals');
    expect(mine.status, JSON.stringify(mine.body)).toBe(200);
    expect(mine.body.deals).toContainEqual({ dealId: id, role: 'lawyerA', state: 'DRAFT' });
    expect((await call(w, w.observer, 'GET', '/deals')).body.deals).toContainEqual({ dealId: id, state: 'DRAFT' });
    expect((await call(w, holderOf(w, 'bob'), 'GET', '/deals')).body.deals).toEqual([
      { dealId: id, role: 'bob', state: 'DRAFT' },
    ]);
    expect((await call(w, holderOf(w, 'bob', 2), 'GET', '/deals')).body.deals).toEqual([]); // a service holder
  });
});
