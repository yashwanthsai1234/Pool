// T-A-13 (IMPLEMENTATION 2.6; DESIGN 7.5): a partial payment into the deal wallet. The wallet credits what the ledger
// delivered (`meta.delivered_amount`), never the transaction's `Amount`.
//   XRP to XRP: rippled refuses a partial payment (temBAD_SEND_XRP_PARTIAL), in every phase.
//   An IOU: while the wallet still has a trust line (before 5c, set by the setup key) a partial payment delivers LESS than
//   `Amount`; `deliveredAmount` reads the real figure. After the lock the wallet takes neither a trust line nor an IOU.
//   After the lock a stranger's plain XRP payment is refused by DepositAuth (tecNO_PERMISSION).
// Source: https://xrpl.org/docs/concepts/payment-types/partial-payments ; DESIGN 7.5
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { deliveredAmount } from '../../src/read.ts';
import { newDeal } from '../deal.ts';
import { type Chain, openChain } from '../roles.ts';
import { outcome, stranger } from './util.ts';

const PARTIAL = 0x00020000;
let c: Chain;
beforeAll(async () => {
  c = await openChain();
});
afterAll(async () => {
  await c.close();
});

describe('T-A-13 a partial payment into the wallet', () => {
  it('before the lock: XRP partial is refused; an IOU partial delivers less than Amount and only delivered_amount counts', async () => {
    const d = await newDeal(c, 'keys');
    const issuer = await stranger(c);
    const before = await d.balance(d.wallet);
    expect(d.setupKey).toBeDefined(); // setup state: the setup key is still live, so the shell can hold a trust line

    // XRP to XRP
    const xrp = await c.attempt(issuer, {
      TransactionType: 'Payment',
      Account: issuer.classicAddress,
      Destination: d.wallet,
      Amount: '10000000',
      Flags: PARTIAL,
    });
    expect(outcome(xrp)).toBe('rejected:temBAD_SEND_XRP_PARTIAL');
    expect(await d.balance(d.wallet)).toBe(before);

    // IOU: the shell trusts the issuer for 1000, the issuer pays Amount 100 with SendMax 40 as a partial payment
    await d.setup({
      TransactionType: 'TrustSet',
      Account: d.wallet,
      LimitAmount: { currency: 'USD', issuer: issuer.classicAddress, value: '1000' },
    });
    const iou = (value: string) => ({ currency: 'USD', issuer: issuer.classicAddress, value });
    const paid = await c.send(issuer, {
      TransactionType: 'Payment',
      Account: issuer.classicAddress,
      Destination: d.wallet,
      Amount: iou('100'),
      SendMax: iou('40'),
      Flags: PARTIAL,
    });
    expect((paid.tx as { Amount: { value: string } }).Amount.value).toBe('100'); // what the sender wrote
    expect(deliveredAmount(paid.meta)).toEqual(iou('40')); // what the ledger delivered
    const lines = (await c.client.request({ command: 'account_lines', account: d.wallet, ledger_index: 'validated' }))
      .result.lines;
    expect(lines.map((l) => [l.currency, l.balance])).toEqual([['USD', '40']]);
  });

  it('after the lock: partial XRP, a plain stranger payment and an IOU all fail; no balance moves', async () => {
    const d = await newDeal(c, 'locked');
    expect(await d.lockOk()).toBe(true); // setup state
    const s = await stranger(c);
    const before = await d.balance(d.wallet);

    // the sealed releaser is preauthorized, but a partial XRP payment is still refused
    const partial = await c.attempt(d.lawyerB.ops, {
      TransactionType: 'Payment',
      Account: d.lawyerB.ops.classicAddress,
      Destination: d.wallet,
      Amount: '10000000',
      Flags: PARTIAL,
    });
    expect(outcome(partial)).toBe('rejected:temBAD_SEND_XRP_PARTIAL');
    // a stranger: DepositAuth
    const plain = await c.attempt(s, {
      TransactionType: 'Payment',
      Account: s.classicAddress,
      Destination: d.wallet,
      Amount: '10000000',
    });
    expect(outcome(plain)).toBe('validated:tecNO_PERMISSION');
    const strangerPartial = await c.attempt(s, {
      TransactionType: 'Payment',
      Account: s.classicAddress,
      Destination: d.wallet,
      Amount: '10000000',
      Flags: PARTIAL,
    });
    expect(outcome(strangerPartial)).toBe('rejected:temBAD_SEND_XRP_PARTIAL');
    // an IOU: no trust line can exist (DisallowIncomingTrustline), and DepositAuth refuses the payment
    const trust = await c.attempt(s, {
      TransactionType: 'TrustSet',
      Account: s.classicAddress,
      LimitAmount: { currency: 'USD', issuer: d.wallet, value: '100' },
    });
    expect(outcome(trust)).toBe('validated:tecNO_PERMISSION');
    const usd = { currency: 'USD', issuer: s.classicAddress, value: '100' };
    const iou = await c.attempt(s, {
      TransactionType: 'Payment',
      Account: s.classicAddress,
      Destination: d.wallet,
      Amount: usd,
      SendMax: { ...usd, value: '40' },
      Flags: PARTIAL,
    });
    expect(outcome(iou)).toBe('validated:tecNO_PERMISSION');
    expect(await d.balance(d.wallet)).toBe(before);
    expect(
      (await c.client.request({ command: 'account_lines', account: d.wallet, ledger_index: 'validated' })).result.lines,
    ).toEqual([]);
    expect(await d.lockOk()).toBe(true);
  });
});
