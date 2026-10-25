// T-A-15 (IMPLEMENTATION 2.6; DESIGN 7.5): LastLedgerSequence passes before the blob is submitted. The ledger answers
// tefMAX_LEDGER; `submitReliable` reports `expired` (the caller rebuilds); and the exit slot S is NOT used up, so the
// rebuilt exit on the same slot validates. Run on a single-signed blob before the lock and on a 4-of-4 exit after it.
// Source: https://xrpl.org/docs/concepts/transactions/reliable-transaction-submission (LastLedgerSequence)
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { build8 } from '../../src/builders/index.ts';
import { advanceLedgers } from '../../src/ledger.ts';
import { combine, exitOutcome, nextSlot } from '../../src/multisig.ts';
import { prepare } from '../../src/prepare.ts';
import { newDeal } from '../deal.ts';
import type { Json } from '../roles.ts';
import { type Chain, openChain } from '../roles.ts';
import { stranger } from './util.ts';

let c: Chain;
beforeAll(async () => {
  c = await openChain();
});
afterAll(async () => {
  await c.close();
});

describe('T-A-15 LastLedgerSequence passes before submit', () => {
  it('a single-signed payment before the lock', async () => {
    const d = await newDeal(c, 'funded');
    const to = await stranger(c, 25);
    const alice = d.aliceBase.wallet;
    const tx = {
      TransactionType: 'Payment' as const,
      Account: alice.classicAddress,
      Destination: to.classicAddress,
      Amount: '1000000',
    };
    const blob = alice.sign(await prepare(tx, { client: c.client, lastLedgerOffset: 2 })).tx_blob;
    await advanceLedgers(c.client, 6); // the ledger is now past LastLedgerSequence
    const sequenceBefore = (
      await c.client.request({ command: 'account_info', account: alice.classicAddress, ledger_index: 'validated' })
    ).result.account_data.Sequence;
    expect(await c.rawSubmit(blob)).toBe('tefMAX_LEDGER');
    expect(await c.submitBlob(blob)).toMatchObject({ status: 'expired' });
    expect(await d.balance(to.classicAddress)).toBe(25_000_000n);
    // rebuild: the same sequence is still free
    const again = await c.send(alice, tx);
    expect(Number(again.tx.Sequence)).toBe(sequenceBefore);
    expect(await d.balance(to.classicAddress)).toBe(26_000_000n);
  });

  it('a 4-of-4 exit after the lock leaves slot S free', async () => {
    const d = await newDeal(c, 'locked');
    expect(await d.lockOk()).toBe(true);
    await d.release();
    const slot = await nextSlot(c.rpc, d.wallet);
    const exitTx = build8({ shell: d.wallet, payout: d.data.payoutB, amount: '50000000', slot }, c.ctx);
    const prepared = await prepare(exitTx, { client: c.client, signers: 4, lastLedgerOffset: 2, feeMultiplier: 5 });
    const blob = combine(
      d.slots().map((s) => s.signTx(prepared as unknown as Json)),
      d.slots().map((s) => s.address),
    );
    await advanceLedgers(c.client, 6);
    const bobBefore = await d.balance(d.bob.wallet.classicAddress);
    expect(await c.rawSubmit(blob)).toBe('tefMAX_LEDGER');
    const r = await c.submitBlob(blob);
    expect(r).toMatchObject({ status: 'expired' });
    // slot S is unused and Bob has not been paid; the caller rebuilds on the same slot
    expect(await exitOutcome(c.rpc, d.wallet, slot, r)).toEqual({ done: false, slotUsed: false, next: slot });
    expect(await d.balance(d.bob.wallet.classicAddress)).toBe(bobBefore);
    const rebuilt = await c.multisend(
      build8({ shell: d.wallet, payout: d.data.payoutB, amount: '50000000', slot }, c.ctx),
      d.slots(),
      5,
    );
    expect(Number(rebuilt.tx.Sequence)).toBe(slot.sequence);
    expect((await d.balance(d.bob.wallet.classicAddress)) - bobBefore).toBe(50_000_000n);
  });
});
