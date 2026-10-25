// P3.2-03 (atomic state changes) and P3.2-04 to P3.2-08 (signature requests, combination, expiry, slot S).

import type { SubmitResult } from '@legx/contracts/ports';
import { verifyMultisigned } from '@legx/core/verify';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { AMOUNT, account, ok, toFunded } from './support/lifecycle.ts';
import {
  call,
  holderOf,
  makeWorld,
  newDeal,
  PAY_A,
  PAY_B,
  ROLES,
  type Role,
  SHELL,
  txHash,
  type World,
} from './support/world.ts';

vi.setConfig({ testTimeout: 180_000 });
let w: World;
beforeAll(async () => {
  w = await makeWorld();
});
afterAll(async () => w.close());

const signBlob = (role: Role, unsigned: Record<string, unknown>) =>
  w.parties[role].wallet.sign(unsigned as never, true).tx_blob;
const sigUrl = (id: string, req?: string) => `/deals/${id}/signature-requests${req ? `/${req}/signatures` : ''}`;
const createReq = async (id: string, purpose: string, role: Role = 'alice') =>
  ok(await call(w, holderOf(w, role), 'POST', sigUrl(id), { dealId: id, purpose }));
const submit = (id: string, req: string, role: Role, blob: string) =>
  call(w, holderOf(w, role), 'POST', sigUrl(id, req), { dealId: id, requestId: req, role, signerBlob: blob });
const stateOf = async (id: string) => ok(await call(w, holderOf(w, 'alice'), 'GET', `/deals/${id}`));

function validated(hash = txHash()): SubmitResult {
  return {
    status: 'validated',
    result: 'tesSUCCESS',
    hash: hash as never,
    ledgerIndex: w.ledger.index,
    meta: { TransactionResult: 'tesSUCCESS', delivered_amount: AMOUNT, TransactionIndex: 0 },
  };
}

async function funded() {
  const id = await newDeal(w);
  await toFunded(w, id);
  return id;
}

describe('P3.2-04 signature request for an exit', () => {
  it('autofill(tx, 4), LastLedgerSequence = validated + 1800, stored with its expiry, listed', async () => {
    const id = await funded();
    const before = w.ledger.autofillCalls.length;
    const r = await createReq(id, 'pay_bob');
    expect(w.ledger.autofillCalls.length).toBe(before + 1);
    expect(w.ledger.autofillCalls.at(-1)?.signersCount).toBe(4);
    expect(r.lastLedger).toBe(w.ledger.index + 1800);
    // I-W-5: the request has its `signature.request` row in the deal's gap-free feed, written with the request.
    const feed = await w.db.repos.outbox.listAfter(id, -1);
    expect(feed.map((o) => o.seq)).toEqual(feed.map((_, i) => i));
    const row = feed.filter((o) => o.topic === 'signature.request');
    expect(row).toHaveLength(1);
    expect(JSON.parse(Buffer.from(row[0]?.payload as Uint8Array).toString())).toMatchObject({
      dealId: id,
      requestId: r.requestId,
      purpose: 'pay_bob',
      lastLedger: r.lastLedger,
      status: 'open',
    });
    const states = feed.filter((o) => o.topic === 'deal.state');
    expect(JSON.parse(Buffer.from(states.at(-1)?.payload as Uint8Array).toString()).state).toBe('FUNDED');
    expect(r.unsignedTx).toMatchObject({
      TransactionType: 'Payment',
      Account: SHELL,
      Destination: PAY_B,
      Amount: AMOUNT,
      Sequence: 41,
      LastLedgerSequence: r.lastLedger,
    });
    expect(r.status).toBe('open');
    const list = ok(await call(w, holderOf(w, 'bob'), 'GET', sigUrl(id)));
    expect(list.requests.map((x: { requestId: string; lastLedger: number }) => [x.requestId, x.lastLedger])).toEqual([
      [r.requestId, r.lastLedger],
    ]);
    // A retry returns the first request, not a second one.
    expect((await createReq(id, 'pay_bob', 'bob')).requestId).toBe(r.requestId);
  });

  it('an exit is refused before the money is in the wallet', async () => {
    const id = await newDeal(w);
    const r = await call(w, holderOf(w, 'alice'), 'POST', sigUrl(id), { dealId: id, purpose: 'pay_bob' });
    expect(r.status).toBe(422);
    expect(r.body.error).toBe('wrong_state');
  });

  it('purposes of other tasks answer 501, not a silent success', async () => {
    const id = await funded();
    const r = await call(w, holderOf(w, 'alice'), 'POST', sigUrl(id), { dealId: id, purpose: 'seal_update' });
    expect(r.status).toBe(501);
  });
});

describe('P3.2-05 four blobs in any order, some twice', () => {
  it('combined once, verifyMultisigned passes, submitted once, and the deal is PAID_OUT', async () => {
    const id = await funded();
    const req = await createReq(id, 'pay_bob');
    const blobs = Object.fromEntries(ROLES.map((r) => [r, signBlob(r, req.unsignedTx)])) as Record<Role, string>;
    w.ledger.nextSubmit = () => validated();
    const order: Role[] = ['lawyerB', 'alice', 'alice', 'bob', 'lawyerB', 'lawyerA', 'bob', 'alice'];
    const results = await Promise.all(order.map((r) => submit(id, req.requestId, r, blobs[r])));
    expect(results.every((r) => r.status === 200)).toBe(true);
    expect(results.filter((r) => r.body.submitted).length).toBe(1);
    expect(results.filter((r) => r.body.status === 'duplicate').length).toBe(4);
    expect(w.ledger.submitted).toHaveLength(1);
    expect(
      verifyMultisigned(
        w.ledger.submitted[0] as string,
        ROLES.map((r) => account(w, r)),
      ).ok,
    ).toBe(true);
    const v = await stateOf(id);
    expect(v.state).toBe('PAID_OUT');
    // A late retry of an already finished request returns the first answer and submits nothing.
    const again = await submit(id, req.requestId, 'alice', blobs.alice);
    expect(again.body.status).toBe('duplicate');
    expect(w.ledger.submitted).toHaveLength(1);
  });

  it('a role signs only for itself', async () => {
    const id = await funded();
    const req = await createReq(id, 'pay_bob');
    const r = await call(w, holderOf(w, 'bob'), 'POST', sigUrl(id, req.requestId), {
      dealId: id,
      requestId: req.requestId,
      role: 'alice',
      signerBlob: signBlob('alice', req.unsignedTx),
    });
    expect(r.status).toBe(403);
  });
});

describe('P3.2-06 a blob that signs a different transaction', () => {
  it('is rejected; the other blobs stay valid and the request completes', async () => {
    const id = await funded();
    const req = await createReq(id, 'pay_bob');
    const evil = signBlob('bob', { ...req.unsignedTx, Amount: '1' });
    const bad = await submit(id, req.requestId, 'bob', evil);
    expect(bad.status).toBe(422);
    expect(bad.body.error).toBe('blob_differs');
    const wrongAccount = await submit(id, req.requestId, 'bob', signBlob('alice', req.unsignedTx));
    expect(wrongAccount.status).toBe(422);
    expect(wrongAccount.body.error).toBe('bad_signer_blob');
    expect((await submit(id, req.requestId, 'alice', signBlob('alice', req.unsignedTx))).body.signedRoles).toEqual([
      'alice',
    ]);
    w.ledger.nextSubmit = () => validated();
    for (const r of ['lawyerA', 'bob', 'lawyerB'] as Role[])
      await submit(id, req.requestId, r, signBlob(r, req.unsignedTx));
    expect((await stateOf(id)).state).toBe('PAID_OUT');
  });
});

describe('P3.2-07 a request that expires', () => {
  it('is marked expired, a new request is built, and the old blobs are refused', async () => {
    const id = await funded();
    const old = await createReq(id, 'refund_alice');
    await submit(id, old.requestId, 'alice', signBlob('alice', old.unsignedTx));
    w.ledger.advance(1801);
    const late = await submit(id, old.requestId, 'bob', signBlob('bob', old.unsignedTx));
    expect(late.status).toBe(409);
    expect(late.body.error).toBe('request_expired');
    expect((await w.db.repos.signatureRequests.get(old.requestId))?.status).toBe('expired');
    const fresh = await createReq(id, 'refund_alice');
    expect(fresh.requestId).not.toBe(old.requestId);
    expect(fresh.lastLedger).toBe(w.ledger.index + 1800);
    expect(fresh.unsignedTx).toMatchObject({ Destination: PAY_A.split(':')[0], DestinationTag: 7, Sequence: 41 });
    // The old request's blobs do not fit the new one.
    const stale = await submit(id, fresh.requestId, 'alice', signBlob('alice', old.unsignedTx));
    expect(stale.status).toBe(422);
  });
});

describe('P3.2-08 slot S', () => {
  it('is recorded at funding; both candidates use it; the first validated one voids the other', async () => {
    const id = await funded();
    expect((await stateOf(id)).exitSlot).toBe(41);
    const pay = await createReq(id, 'pay_bob');
    const refund = await createReq(id, 'refund_alice');
    expect([pay.unsignedTx.Sequence, refund.unsignedTx.Sequence]).toEqual([41, 41]);
    w.ledger.nextSubmit = () => validated();
    for (const r of ROLES) await submit(id, pay.requestId, r, signBlob(r, pay.unsignedTx));
    expect((await stateOf(id)).state).toBe('PAID_OUT');
    expect((await w.db.repos.signatureRequests.get(refund.requestId))?.status).toBe('void');
    const late = await submit(id, refund.requestId, 'alice', signBlob('alice', refund.unsignedTx));
    expect(late.status).toBe(409);
  });

  it('a tec result uses S up: both candidates void, S+1 recorded, signatures are collected again; no money moved', async () => {
    const id = await funded();
    const pay = await createReq(id, 'pay_bob');
    const refund = await createReq(id, 'refund_alice');
    w.ledger.nextSubmit = () => ({
      status: 'validated',
      result: 'tecDST_TAG_NEEDED',
      hash: txHash() as never,
      ledgerIndex: w.ledger.index,
      meta: { TransactionResult: 'tecDST_TAG_NEEDED' },
    });
    for (const r of ROLES) await submit(id, pay.requestId, r, signBlob(r, pay.unsignedTx));
    const v = await stateOf(id);
    expect(v.state).toBe('FUNDED');
    expect(v.exitSlot).toBe(42);
    for (const r of [pay, refund]) expect((await w.db.repos.signatureRequests.get(r.requestId))?.status).toBe('void');
    const again = await createReq(id, 'pay_bob');
    expect(again.requestId).not.toBe(pay.requestId);
    expect(again.unsignedTx.Sequence).toBe(42);
  });
});

describe('P3.2-03 every state change is stored with its evidence event and outbox row, or not at all', () => {
  it('a failure after the state write rolls everything back', async () => {
    const id = await newDeal(w);
    const before = {
      events: (await w.db.repos.evidenceEvents.listAfter(id, -1)).length,
      outbox: (await w.db.repos.outbox.listAfter(id, -1)).length,
    };
    const { joinAll } = await import('./support/lifecycle.ts');
    await joinAll(w, id);
    const sealed = (await w.db.repos.evidenceEvents.listAfter(id, -1)).length;
    expect(sealed).toBeGreaterThan(before.events);
    // Every stored event has exactly one `deal.event` and one `deal.state` row (OD-9, I-W-5), in the same transaction,
    // and the feed's seq runs gap-free across both.
    const outbox = await w.db.repos.outbox.listAfter(id, -1);
    expect(outbox.map((o) => o.seq)).toEqual(outbox.map((_, i) => i));
    expect(outbox.filter((o) => o.topic === 'deal.event')).toHaveLength(
      (await w.db.repos.evidenceEvents.listAfter(id, -1)).length,
    );
    expect(outbox.filter((o) => o.topic === 'deal.state')).toHaveLength(
      (await w.db.repos.evidenceEvents.listAfter(id, -1)).length,
    );
    const state = (await stateOf(id)).state;
    w.crash.fn = (p) => {
      if (p === 'deal.afterStateWrite') throw new Error('injected');
    };
    const { post } = await import('./support/world.ts');
    const { addTx, OPS_A } = await import('./support/world.ts');
    const r = await post(w, id, 'alice', 'shell.opened', {
      wallet_address: SHELL,
      funding_tx_hash: addTx(w, 'Payment', account(w, 'alice')),
    });
    w.crash.fn = undefined;
    expect(r.status).toBe(500);
    expect((await stateOf(id)).state).toBe(state);
    expect((await w.db.repos.evidenceEvents.listAfter(id, -1)).length).toBe(sealed);
    expect((await w.db.repos.outbox.listAfter(id, -1)).length).toBe(sealed * 2);
    expect(OPS_A).toBeTruthy();
    // The retry after the failure succeeds with the same seq: the failed attempt left no gap.
    const retry = await post(w, id, 'alice', 'shell.opened', {
      wallet_address: SHELL,
      funding_tx_hash: addTx(w, 'Payment', account(w, 'alice')),
    });
    expect(retry.status).toBe(200);
    expect(retry.body.seq).toBe(sealed);
  });
});
