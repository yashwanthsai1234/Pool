// P3.2-10: restart in the middle of every step. A "kill" is an exception from the `crash` hook between two awaited
// calls; a "restart" is a fresh Fastify app over the same database; the client then retries what it did not see answered.
// The deal must resume, and nothing may be signed or submitted twice (DESIGN M3).

import { verifyMultisigned } from '@legx/core/verify';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { parseStored } from '../src/log.ts';
import { recoverDeal } from '../src/signatures.ts';
import { AMOUNT, account, ok, toFunded } from './support/lifecycle.ts';
import {
  call,
  holderOf,
  makeWorld,
  newDeal,
  OPS_A,
  OPS_B,
  PAY_A,
  PAY_B,
  ROLES,
  type Role,
  txHash,
  type World,
} from './support/world.ts';

vi.setConfig({ testTimeout: 600_000 });
let w: World;
beforeAll(async () => {
  w = await makeWorld();
});
afterAll(async () => w.close());

/** seq 0..n-1 with no gap, every prev_hash the previous leaf, one outbox row per event, all leaf hashes distinct. */
async function assertChain(id: string) {
  const events = await w.db.repos.evidenceEvents.listAfter(id, -1);
  let prev = '00'.repeat(32);
  events.forEach((e, i) => {
    expect(e.seq).toBe(i);
    expect(e.prev_hash).toBe(prev);
    prev = e.leaf_hash;
  });
  expect(new Set(events.map((e) => e.leaf_hash)).size).toBe(events.length);
  const outbox = await w.db.repos.outbox.listAfter(id, -1);
  expect(outbox.map((o) => o.seq)).toEqual(outbox.map((_, i) => i)); // one gap-free feed sequence (I-W-5)
  expect(outbox.filter((o) => o.topic === 'deal.event')).toHaveLength(events.length);
  return events.map((e) => parseStored(e.seq, e.leaf_hash, e.envelope)?.kind as string);
}

const signBlob = (role: Role, unsigned: Record<string, unknown>) =>
  w.parties[role].wallet.sign(unsigned as never, true).tx_blob;
const sigUrl = (id: string, req?: string) => `/deals/${id}/signature-requests${req ? `/${req}/signatures` : ''}`;
const submit = (id: string, req: string, role: Role, blob: string) =>
  call(w, holderOf(w, role), 'POST', sigUrl(id, req), { dealId: id, requestId: req, role, signerBlob: blob });

describe('P3.2-10 kill at every state write of the whole setup, then retry', () => {
  it('every step is killed once between the state write and the commit; the retry after a restart succeeds, with no gap and no duplicate', async () => {
    const id = await newDeal(w);
    w.killEveryStep = true;
    await toFunded(w, id);
    w.killEveryStep = false;
    const kinds = await assertChain(id);
    expect(kinds[0]).toBe('deal.created');
    expect(kinds.filter((k) => k === 'release.gate.passed')).toHaveLength(1);
    expect(kinds.filter((k) => k === 'release.performed')).toHaveLength(1);
    const v = ok(await call(w, holderOf(w, 'alice'), 'GET', `/deals/${id}`));
    expect([v.state, v.exitSlot]).toEqual(['FUNDED', 41]);
    expect(await w.db.repos.releaseGates.list(id)).toHaveLength(1);
  });

  it('a kill while creating a deal leaves no row and no event; the retry creates it', async () => {
    const count = async () =>
      Number(
        (
          await w.db.kysely
            .selectFrom('deal')
            .select((eb) => eb.fn.countAll<string>().as('n'))
            .executeTakeFirst()
        )?.n,
      );
    const before = await count();
    const body = {
      network: 'standalone',
      identityPolicy: 'zk',
      amountDrops: '1000',
      payoutA: PAY_A,
      payoutB: PAY_B,
      lawyerOpsA: OPS_A,
      lawyerOpsB: OPS_B,
    };
    w.crash.fn = (p) => {
      if (p === 'deal.afterStateWrite') throw new Error('KILLED');
    };
    expect((await call(w, w.lawyerCreator, 'POST', '/deals', body)).status).toBe(500);
    w.crash.fn = undefined;
    expect(await count()).toBe(before);
    w.rebuild();
    const r = await call(w, w.lawyerCreator, 'POST', '/deals', body);
    expect(r.status).toBe(200);
    expect(await count()).toBe(before + 1);
    expect(await assertChain(r.body.dealId)).toEqual(['deal.created']);
  });
});

describe('P3.2-10 kill at each point of an exit', () => {
  it.each(['sig.afterInsert', 'submit.before', 'submit.after', 'finalize.afterState'])(
    'killed at %s: the deal resumes, one transaction is submitted, one result is recorded',
    async (point) => {
      const id = await newDeal(w);
      await toFunded(w, id);
      const req = ok(await call(w, holderOf(w, 'alice'), 'POST', sigUrl(id), { dealId: id, purpose: 'pay_bob' }));
      w.ledger.submitted.length = 0;
      w.ledger.nextSubmit = () => ({
        status: 'validated',
        result: 'tesSUCCESS',
        hash: txHash() as never,
        ledgerIndex: w.ledger.index,
        meta: { TransactionResult: 'tesSUCCESS', delivered_amount: AMOUNT, TransactionIndex: 0 },
      });
      for (const r of ['alice', 'lawyerA', 'bob'] as Role[])
        expect((await submit(id, req.requestId, r, signBlob(r, req.unsignedTx))).status).toBe(200);
      // The fourth signature arrives and the process dies at `point`.
      w.crash.fn = (p) => {
        if (p === point) throw new Error('KILLED');
      };
      const fourth = signBlob('lawyerB', req.unsignedTx);
      expect((await submit(id, req.requestId, 'lawyerB', fourth)).status).toBe(500);
      w.crash.fn = undefined;
      w.rebuild();
      // Restart: the repair is the same call a phone makes again (or the startup scan).
      if (point === 'submit.before') await recoverDeal(w.deps, id);
      else expect((await submit(id, req.requestId, 'lawyerB', fourth)).status).toBe(200);
      expect(ok(await call(w, holderOf(w, 'alice'), 'GET', `/deals/${id}`)).state).toBe('PAID_OUT');
      expect(new Set(w.ledger.submitted).size).toBe(1);
      expect(w.ledger.submitted).toHaveLength(1);
      expect(
        verifyMultisigned(
          w.ledger.submitted[0] as string,
          ROLES.map((r) => account(w, r)),
        ).ok,
      ).toBe(true);
      const kinds = await assertChain(id);
      expect(kinds.filter((k) => k === 'exit.signed')).toHaveLength(1);
      expect(kinds.filter((k) => k === 'exit.validated')).toHaveLength(1);
      expect((await w.db.repos.signatureRequests.get(req.requestId))?.status).toBe('complete');
    },
  );

  it('two processes racing the same fourth blob submit the same bytes: the ledger sees one transaction', async () => {
    const id = await newDeal(w);
    await toFunded(w, id);
    const req = ok(await call(w, holderOf(w, 'alice'), 'POST', sigUrl(id), { dealId: id, purpose: 'refund_alice' }));
    w.ledger.submitted.length = 0;
    w.ledger.nextSubmit = () => ({
      status: 'validated',
      result: 'tesSUCCESS',
      hash: txHash() as never,
      ledgerIndex: w.ledger.index,
      meta: { TransactionResult: 'tesSUCCESS', delivered_amount: AMOUNT, TransactionIndex: 0 },
    });
    const blobs = Object.fromEntries(ROLES.map((r) => [r, signBlob(r, req.unsignedTx)])) as Record<Role, string>;
    await Promise.all(ROLES.map((r) => submit(id, req.requestId, r, blobs[r])));
    expect(new Set(w.ledger.submitted).size).toBe(1);
    expect(ok(await call(w, holderOf(w, 'alice'), 'GET', `/deals/${id}`)).state).toBe('REFUNDED');
  });
});
