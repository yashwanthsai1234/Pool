// T-I-06 (IMPLEMENTATION 2.6; DESIGN 5.1, 5.4, 8.1): dispute and award. After the release (FUNDED) a party opens a
// dispute; an arbitrator's award names the exit; all four slots sign exactly that exit. With three of four the machine
// refuses (quorum) and the ledger refuses (tefBAD_QUORUM). The exit the award names validates, and `exit.validated`
// carries delivered_amount. Both awards are run: pay Bob, and refund Alice.
// Source: DESIGN 5.1 (DISPUTED), 8.1 events dispute.opened, award.recorded, exit.validated
import { sha256, utf8ToBytes } from '@legx/core/dealcore';
import { type Deal as MachineDeal, step, transition } from '@legx/core/machine';
import { bytesToHex } from '@noble/hashes/utils.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { build8 } from '../../src/builders/index.ts';
import { nextSlot } from '../../src/multisig.ts';
import { deliveredAmount } from '../../src/read.ts';
import { ESCROW_DROPS, newDeal } from '../deal.ts';
import { type Chain, openChain } from '../roles.ts';

let c: Chain;
beforeAll(async () => {
  c = await openChain();
});
afterAll(async () => {
  await c.close();
});

describe('T-I-06 dispute and award', () => {
  it.each(['pay_bob', 'refund_alice'] as const)('award %s: the exit it names validates', async (outcome) => {
    const d = await newDeal(c, 'locked');
    expect(await d.lockOk()).toBe(true); // setup state
    await d.release();
    let deal: MachineDeal = { state: 'FUNDED', wasLocked: true };

    // a dispute is opened and recorded; the award is recorded naming the exit
    deal = step(deal, { t: 'OPEN_DISPUTE' });
    expect(deal.state).toBe('DISPUTED');
    const notice = sha256(utf8ToBytes('notice of dispute'));
    const dispute = await d.ev.event('dispute.opened', { notice_sha256: bytesToHex(notice) }, d.alice.slot, 'alice');
    const award = sha256(utf8ToBytes(`award: ${outcome}`));
    const awarded = await d.ev.event(
      'award.recorded',
      { award_sha256: bytesToHex(award), outcome },
      d.lawyerA.slot,
      'lawyerA',
    );
    expect(dispute.length).toBeGreaterThan(0);
    expect(awarded.length).toBeGreaterThan(0);

    // while disputed the exit needs the award and all four signatures
    const to = outcome === 'pay_bob' ? 'BOB' : 'ALICE';
    expect(transition(deal, { t: 'AWARD', to, sigs: 3 })).toMatchObject({ ok: false, refusal: 'quorum' });
    const payout = outcome === 'pay_bob' ? d.data.payoutB : d.data.payoutA;
    const receiver = (outcome === 'pay_bob' ? d.bob : d.alice).wallet.classicAddress;
    const slot = await nextSlot(c.rpc, d.wallet);
    const tx = build8({ shell: d.wallet, payout, amount: ESCROW_DROPS, slot }, c.ctx);
    const three = await c.attemptMulti(tx, d.slots().slice(0, 3), 5);
    expect(three).toMatchObject({ status: 'rejected', result: 'tefBAD_QUORUM' });
    expect((await nextSlot(c.rpc, d.wallet)).sequence).toBe(slot.sequence); // slot S is not spent

    const before = await d.balance(receiver);
    const exit = await c.multisend(tx, d.slots(), 5);
    deal = step(deal, { t: 'AWARD', to, sigs: 4 });
    expect(deal.state).toBe(outcome === 'pay_bob' ? 'PAID_OUT' : 'REFUNDED');
    expect(deliveredAmount(exit.meta as never)).toBe(ESCROW_DROPS);
    expect((await d.balance(receiver)) - before).toBe(BigInt(ESCROW_DROPS));
    expect(exit.tx.Destination).toBe(receiver);
    // exit.validated would carry: purpose, tx_hash, destination, delivered_drops from meta.delivered_amount
    expect(
      await d.ev.event(
        'exit.validated',
        {
          purpose: outcome,
          tx_hash: exit.hash,
          destination: payout,
          delivered_drops: deliveredAmount(exit.meta as never) as string,
        },
        d.lawyerB.slot,
        'lawyerB',
      ),
    ).toBeInstanceOf(Uint8Array);
  });
});
