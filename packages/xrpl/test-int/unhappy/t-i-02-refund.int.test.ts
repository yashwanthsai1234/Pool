// T-I-02 (IMPLEMENTATION 2.6; DESIGN 5.1, 5.4): the refund path. The release passed and funded the shell, then the deal is
// off: the four slots sign a Payment from the shell to Alice's sealed payout (`rAlice:7`, with its destination tag), and
// the shell closes with AccountDelete. Alice is paid exactly the escrow amount (from delivered_amount) and the close succeeds.
// Source: DESIGN 5.1 (FUNDED to REFUNDED to CLOSED), 7.5 ; https://xrpl.org/docs/references/protocol/transactions/types/accountdelete
import { step } from '@legx/core/machine';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { deliveredAmount } from '../../src/read.ts';
import { escrowsWith } from '../attacks/util.ts';
import { ESCROW_DROPS, newDeal } from '../deal.ts';
import { type Chain, openChain } from '../roles.ts';

let c: Chain;
beforeAll(async () => {
  c = await openChain();
});
afterAll(async () => {
  await c.close();
});

describe('T-I-02 the refund path', () => {
  it('Alice is paid her sealed payout, and the shell closes', async () => {
    const d = await newDeal(c, 'locked');
    expect(await d.lockOk()).toBe(true); // setup state: locked, escrow pending, no money in the shell beyond its funding
    expect(await escrowsWith(c, d.wallet, d.condition)).toHaveLength(1);
    await d.release();
    expect(await escrowsWith(c, d.wallet, d.condition)).toHaveLength(0);
    let deal = { state: 'FUNDED' as const, wasLocked: true };

    const exit = await d.exit('alice');
    deal = step(deal, { t: 'REFUND_ALICE', sigs: 4 }) as never;
    const tx = (await c.client.request({ command: 'tx', transaction: exit.hash })).result as unknown as {
      tx_json: Record<string, unknown>;
      meta: Record<string, unknown>;
      validated: boolean;
    };
    expect(tx.validated).toBe(true);
    expect(tx.tx_json.Destination).toBe(d.aliceBase.wallet.classicAddress);
    expect(tx.tx_json.DestinationTag).toBe(7); // payoutA = "rAlice:7"
    expect(tx.meta.TransactionResult).toBe('tesSUCCESS');
    expect(deliveredAmount(tx.meta as never)).toBe(ESCROW_DROPS);
    expect(exit.receiverAfter - exit.receiverBefore).toBe(BigInt(ESCROW_DROPS));

    const aliceBefore = await d.balance(d.aliceBase.wallet.classicAddress);
    const close = await d.closeShell();
    deal = step(deal, { t: 'CLOSE', sigs: 4 }) as never;
    expect(deal.state).toBe('CLOSED');
    expect((await c.client.request({ command: 'tx', transaction: close.hash })).result.meta).toMatchObject({
      TransactionResult: 'tesSUCCESS',
    });
    await expect(
      c.client.request({ command: 'account_info', account: d.wallet, ledger_index: 'validated' }),
    ).rejects.toMatchObject({ data: { error: 'actNotFound' } });
    expect(await d.balance(d.aliceBase.wallet.classicAddress)).toBeGreaterThan(aliceBefore);
  });
});
