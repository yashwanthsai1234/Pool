// T-A-14 (IMPLEMENTATION 2.6; DESIGN D9, 7.5): resubmit an old blob. A signed blob works once: its Sequence is spent, so the
// ledger answers tefPAST_SEQ and nothing moves again. `submitReliable` is idempotent for the very same blob: it reports the
// original validated result, it does not apply it twice. Run on a single-signed blob before the lock, and on a 4-of-4 blob
// and on the exit payment after the lock (a replayed exit must not pay Bob twice).
// Source: https://xrpl.org/docs/concepts/transactions/reliable-transaction-submission ; tefPAST_SEQ in transaction-results
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { build8, buildAnchor } from '../../src/builders/index.ts';
import { nextSlot } from '../../src/multisig.ts';
import { newDeal } from '../deal.ts';
import { type Chain, openChain } from '../roles.ts';
import { outcome, stranger } from './util.ts';

let c: Chain;
beforeAll(async () => {
  c = await openChain();
});
afterAll(async () => {
  await c.close();
});

describe('T-A-14 resubmit an old blob', () => {
  it('a single-signed payment before the lock', async () => {
    const d = await newDeal(c, 'funded');
    const to = await stranger(c, 25);
    const first = await c.send(d.aliceBase.wallet, {
      TransactionType: 'Payment',
      Account: d.aliceBase.wallet.classicAddress,
      Destination: to.classicAddress,
      Amount: '1000000',
    });
    const paid = await d.balance(to.classicAddress);
    expect(paid).toBe(26_000_000n); // setup state: the payment happened exactly once
    expect(await c.rawSubmit(first.blob)).toBe('tefPAST_SEQ');
    const again = await c.submitBlob(first.blob);
    expect(again).toMatchObject({ status: 'validated', result: 'tesSUCCESS', hash: first.hash });
    expect(await d.balance(to.classicAddress)).toBe(paid);
  });

  it('a 4-of-4 blob and the exit payment after the lock', async () => {
    const d = await newDeal(c, 'locked');
    expect(await d.lockOk()).toBe(true);
    const anchor = await d.multi4(
      buildAnchor(
        { anchorAccount: d.wallet, originHash: new Uint8Array(32), treeSize: 1n, root: new Uint8Array(32) },
        c.ctx,
      ) as never,
    );
    expect(await c.rawSubmit(anchor.blob)).toBe('tefPAST_SEQ');
    expect(outcome(await c.submitBlob(anchor.blob))).toBe('validated:tesSUCCESS');

    await d.release();
    const bobBefore = await d.balance(d.bob.wallet.classicAddress);
    const slot = await nextSlot(c.rpc, d.wallet);
    const exit = await c.multisend(
      build8({ shell: d.wallet, payout: d.data.payoutB, amount: '50000000', slot }, c.ctx),
      d.slots(),
      5,
    );
    const bobPaid = await d.balance(d.bob.wallet.classicAddress);
    expect(bobPaid - bobBefore).toBe(50_000_000n); // setup state: paid once
    const shell = await d.balance(d.wallet);
    expect(await c.rawSubmit(exit.blob)).toBe('tefPAST_SEQ');
    expect(await c.submitBlob(exit.blob)).toMatchObject({ status: 'validated', result: 'tesSUCCESS', hash: exit.hash });
    expect(await d.balance(d.bob.wallet.classicAddress)).toBe(bobPaid);
    expect(await d.balance(d.wallet)).toBe(shell);
  });
});
