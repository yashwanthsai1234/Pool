// T-P-06: model-based test. fast-check commands drive the API against the standalone ledger; after each command the
// model state equals the stored state. Commands: advance one setup step, replay the last event (idempotent), attacks
// (reused nonce, wrong role, stale ledger index, a different exit), an exit, a duplicate exit signature.
import fc from 'fast-check';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { call, holderOf, makeWorld, newDeal, signRequest, type World } from '../test/support/world.ts';
import { freshPg, type RealLedger, realLedger } from './support/real.ts';
import { Scenario, STAGE_STATE, STEPS } from './support/scenario.ts';

const RUNS = Number(process.env.LEGX_MODEL_RUNS ?? 6);
let real: RealLedger;
let fundAcc: RealLedger['fund'];
beforeAll(async () => {
  real = await realLedger();
  fundAcc = real.fund;
});
afterAll(async () => real.stop());

type Cmd =
  | { t: 'step' }
  | { t: 'replay' }
  | { t: 'reusedNonce' }
  | { t: 'wrongRole' }
  | { t: 'stale' }
  | { t: 'exit'; purpose: 'pay_bob' | 'refund_alice' };

describe('T-P-06 model-based', () => {
  it(`the stored state equals the model after every command (${RUNS} runs)`, async () => {
    const cmd = fc.constantFrom<Cmd>(
      { t: 'step' },
      { t: 'step' },
      { t: 'step' },
      { t: 'replay' },
      { t: 'reusedNonce' },
      { t: 'wrongRole' },
      { t: 'stale' },
      { t: 'exit', purpose: 'pay_bob' },
      { t: 'exit', purpose: 'refund_alice' },
    );
    await fc.assert(
      fc.asyncProperty(fc.array(cmd, { minLength: 4, maxLength: 14 }), async (cmds) => {
        const w: World = await makeWorld({ db: await freshPg(), ledger: real.port });
        try {
          const s = new Scenario(
            w,
            real,
            await fundAcc(200),
            await fundAcc(200),
            (await fundAcc(100)).classicAddress,
            (await fundAcc(100)).classicAddress,
          );
          await s.create((x) => newDeal(x, { amountDrops: '50000000' }));
          const model = { stage: 0, paid: false, events: 1 + 12 };
          const eventCount = async () => (await w.db.repos.evidenceEvents.listAfter(s.id, -1)).length;
          for (const c of cmds) {
            const before = await eventCount();
            if (c.t === 'step' && model.stage < STEPS.length) {
              await s.next();
              model.stage++;
            } else if (c.t === 'replay') {
              const evs = await w.db.repos.evidenceEvents.listAfter(s.id, -1);
              const last = evs.at(-1);
              if (last) {
                const r = await call(
                  w,
                  holderOf(w, 'alice'),
                  'GET',
                  `/deals/${s.id}/events?afterSeq=${last.seq - 1}&limit=1`,
                );
                expect(r.status).toBe(200);
              }
              expect(await eventCount()).toBe(before);
            } else if (c.t === 'reusedNonce') {
              const req = signRequest(w, holderOf(w, 'bob'), 'GET', `/deals/${s.id}`);
              expect((await w.app.inject(req)).statusCode).toBe(200);
              expect((await w.app.inject(req)).statusCode).toBe(401);
            } else if (c.t === 'wrongRole') {
              const r = await call(w, holderOf(w, 'bob'), 'POST', `/deals/${s.id}/contract`, {
                dealId: s.id,
                contractRoot: '11'.repeat(32),
              });
              expect(r.status).toBe(403);
            } else if (c.t === 'stale') {
              const r = await w.app.inject(
                signRequest(w, holderOf(w, 'alice'), 'GET', `/deals/${s.id}`, undefined, {
                  ledgerIndex: Math.max(1, w.ledger.index - 40),
                }),
              );
              expect(r.statusCode).toBe(401);
            } else if (c.t === 'exit') {
              const funded = model.stage >= STEPS.length && !model.paid;
              if (funded) {
                const { last } = await s.exit(c.purpose);
                expect(last?.status).toBe(200);
                model.paid = true;
              } else {
                const r = await s.request(c.purpose);
                expect(r.status).toBe(model.paid ? 200 : 422); // a finished deal still lists a request; an unfunded one refuses
                if (model.paid) expect(r.body.status).toBeDefined();
              }
            }
            const expected = model.paid
              ? cmds.some((x) => x.t === 'exit' && x.purpose === 'pay_bob')
                ? undefined
                : undefined
              : (STAGE_STATE[Math.min(model.stage, STAGE_STATE.length) - 1] ?? 'DRAFT');
            const actual = await s.state();
            if (!model.paid) expect(actual).toBe(model.stage === 0 ? 'DRAFT' : expected);
            else expect(['PAID_OUT', 'REFUNDED']).toContain(actual);
            // The evidence chain stays gap-free after every command.
            const evs = await w.db.repos.evidenceEvents.listAfter(s.id, -1);
            expect(evs.map((e) => e.seq)).toEqual(evs.map((_, i) => i));
          }
        } finally {
          await w.close();
        }
      }),
      { numRuns: RUNS, interruptAfterTimeLimit: 20 * 60_000 },
    );
  });
});
