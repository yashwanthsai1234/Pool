// T-I-03 (IMPLEMENTATION 2.6; DESIGN 5.4): expiry. The gate never passes, so the release code is never used. Before
// CancelAfter nobody can cancel the escrow; after it, anyone sends EscrowCancel and the money goes back to Alice, and
// the releaser's finish no longer works. The locked shell then closes with all four signatures.
// CancelAfter is set 900 ledger seconds after step 3 instead of 3 days (a standalone ledger cannot jump days), so the
// lock check's CANCEL_AFTER_MARGIN is the one finding that fails in the setup (the deal helper asserts exactly that).
// Source: https://xrpl.org/docs/references/protocol/transactions/types/escrowcancel
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildEscrowCancel } from '../../src/builders/index.ts';
import { advanceCloseTime } from '../../src/ledger.ts';
import { escrowsWith, outcome, stranger } from '../attacks/util.ts';
import { ESCROW_DROPS, newDeal } from '../deal.ts';
import { type Chain, openChain } from '../roles.ts';

let c: Chain;
beforeAll(async () => {
  c = await openChain();
});
afterAll(async () => {
  await c.close();
});

describe('T-I-03 expiry', () => {
  it('no cancel before CancelAfter; after it the money returns to Alice and the shell closes', async () => {
    const d = await newDeal(c, 'locked', { cancelAfterSeconds: 900 });
    const alice = d.aliceBase.wallet.classicAddress;
    const anyone = await stranger(c);
    const cancel = () =>
      c.attempt(
        anyone,
        buildEscrowCancel({ account: anyone.classicAddress, owner: alice, offerSequence: d.escrowSequence }, c.ctx),
      );
    expect(await escrowsWith(c, d.wallet, d.condition)).toHaveLength(1); // setup state
    expect((await c.lcl()).closeTime).toBeLessThan(d.cancelAfter);

    expect(outcome(await cancel())).toBe('validated:tecNO_PERMISSION'); // too early
    expect(await escrowsWith(c, d.wallet, d.condition)).toHaveLength(1);

    await advanceCloseTime(c.client, d.cancelAfter); // the validated close time is now past CancelAfter
    expect(outcome(await c.attempt(d.lawyerB.ops, d.finishTx()))).toBe('validated:tecNO_PERMISSION'); // no release any more
    const aliceBefore = await d.balance(alice);
    expect(outcome(await cancel())).toBe('validated:tesSUCCESS');
    expect(await escrowsWith(c, d.wallet, d.condition)).toHaveLength(0);
    expect((await d.balance(alice)) - aliceBefore).toBe(BigInt(ESCROW_DROPS)); // the anyone-account paid the fee, not Alice

    // the shell holds only its own funding and closes: 4-of-4, AccountDelete to Alice
    const shellBalance = await d.balance(d.wallet);
    const close = await d.closeShell();
    expect((await c.client.request({ command: 'tx', transaction: close.hash })).result.meta).toMatchObject({
      TransactionResult: 'tesSUCCESS',
    });
    expect((await d.balance(alice)) - aliceBefore).toBe(
      BigInt(ESCROW_DROPS) + shellBalance - BigInt(c.fees.ownerReserveDrops),
    );
  });
});
