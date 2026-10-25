// T-A-11 (IMPLEMENTATION 2.6; DESIGN 11, "CancelAfter is compared with the parent ledger's close time"): finish and
// cancel in the ledgers whose parent closed at T-1, T and T+1, where T is CancelAfter. Expected:
//   parent T-1: finish works, cancel fails       parent T: finish works, cancel fails (the compare is "after")
//   parent T+1: finish fails, cancel works
// The closer is paused so each transaction lands in a ledger whose parent close time is exact; every transaction of one
// step is placed in the open ledger before it closes, so they share the parent. Each case that succeeds uses its own
// escrow (a success removes it), all with the same CancelAfter.
// Run before the lock (any account may finish) and after the lock (only the sealed releaser may).
// Source: https://github.com/XRPLF/rippled/blob/develop/src/xrpld/app/tx/detail/Escrow.cpp (EscrowFinish::preclaim, EscrowCancel::doApply)
import { makeCondition } from '@legx/core/dealcore';
import { randomBytes } from '@noble/hashes/utils.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { build3, buildEscrowCancel } from '../../src/builders/index.ts';
import { newDeal, type Stage } from '../deal.ts';
import { type Chain, openChain } from '../roles.ts';
import { escrowsWith, place, stranger } from './util.ts';

let c: Chain;
beforeAll(async () => {
  c = await openChain();
});
afterAll(async () => {
  c.resume();
  await c.close();
});

describe('T-A-11 finish and cancel around CancelAfter', () => {
  it.each<Stage>(['funded', 'locked'])('phase %s', async (phase) => {
    const d = await newDeal(c, phase);
    const alice = d.aliceBase.wallet;
    const canceller = await stranger(c);
    const finisher = phase === 'locked' ? d.lawyerB.ops : await stranger(c);
    expect(phase === 'locked' ? await d.lockOk() : d.reached('keys')).toBe(phase === 'locked'); // setup state

    await c.pause();
    try {
      const start = await c.lcl();
      const T = start.closeTime + 12;
      // four escrows to the shell, all with CancelAfter = T
      const names = ['a', 'b', 'c', 'd'] as const;
      const esc = Object.fromEntries(
        await Promise.all(names.map(async (n) => [n, { ...makeCondition(randomBytes(32)), hash: '', sequence: 0 }])),
      ) as Record<(typeof names)[number], { condition: string; fulfillment: string; hash: string; sequence: number }>;
      for (const n of names) {
        const tx = build3(
          {
            alice: alice.classicAddress,
            shell: d.wallet,
            amount: '1000000',
            condition: esc[n].condition,
            closeTime: start.closeTime,
            days: 1,
          },
          c.ctx,
        );
        tx.CancelAfter = T;
        esc[n].hash = await place(c, alice, tx);
      }
      await c.accept();
      for (const n of names) {
        const p = await c.placed(esc[n].hash);
        expect(p.result, `create ${n}`).toBe('tesSUCCESS');
        esc[n].sequence = Number(
          (await c.client.request({ command: 'tx', transaction: esc[n].hash })).result.tx_json.Sequence,
        );
        expect(await escrowsWith(c, d.wallet, esc[n].condition)).toHaveLength(1);
      }
      // close ledgers until the last closed ledger is T-1 (each close adds exactly one second once ledger time leads the clock)
      for (let h = await c.lcl(); h.closeTime < T - 1; h = await c.accept()) {
        /* closing */
      }
      expect((await c.lcl()).closeTime).toBe(T - 1);

      const finish = (n: (typeof names)[number]) =>
        place(
          c,
          finisher,
          d.finishTx({
            from: finisher.classicAddress,
            condition: esc[n].condition,
            fulfillment: esc[n].fulfillment,
            sequence: esc[n].sequence,
          }),
        );
      const cancel = (n: (typeof names)[number]) =>
        place(
          c,
          canceller,
          buildEscrowCancel(
            { account: canceller.classicAddress, owner: alice.classicAddress, offerSequence: esc[n].sequence },
            c.ctx,
          ),
        );

      // parent T-1
      const t1 = { cancel: await cancel('a'), finish: await finish('c') };
      expect((await c.accept()).closeTime).toBe(T);
      // parent T
      const t0 = { cancel: await cancel('a'), finish: await finish('d') };
      expect((await c.accept()).closeTime).toBe(T + 1);
      // parent T+1
      const t2 = { finish: await finish('a'), cancel: await cancel('b') };
      await c.accept();

      const got = async (h: string, parent: number) => {
        const p = await c.placed(h);
        expect(p.parentCloseTime).toBe(parent);
        return p.result;
      };
      expect(await got(t1.finish, T - 1)).toBe('tesSUCCESS');
      expect(await got(t1.cancel, T - 1)).toBe('tecNO_PERMISSION');
      expect(await got(t0.finish, T)).toBe('tesSUCCESS');
      expect(await got(t0.cancel, T)).toBe('tecNO_PERMISSION');
      expect(await got(t2.finish, T + 1)).toBe('tecNO_PERMISSION');
      expect(await got(t2.cancel, T + 1)).toBe('tesSUCCESS');

      // the end state: c and d are finished, b is cancelled, a is untouched
      for (const [n, left] of [
        ['a', 1],
        ['b', 0],
        ['c', 0],
        ['d', 0],
      ] as const)
        expect(await escrowsWith(c, d.wallet, esc[n].condition), n).toHaveLength(left);
    } finally {
      c.resume();
    }
  });
});
