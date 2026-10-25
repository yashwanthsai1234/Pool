// T-A-17 (IMPLEMENTATION 2.6): a second EscrowFinish. Once the escrow is finished (or cancelled) it is gone, so a repeat
// finish, by the releaser or by anyone else, cannot move money again: tecNO_TARGET. Run before the lock (a stranger's
// finish, then the repeat), after the lock and release, and after an expiry cancel.
// Source: https://xrpl.org/docs/references/protocol/transactions/types/escrowfinish

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildEscrowCancel } from '../../src/builders/index.ts';
import { advanceCloseTime } from '../../src/ledger.ts';
import { newDeal } from '../deal.ts';
import { type Chain, openChain } from '../roles.ts';
import { escrowsWith, outcome, stranger } from './util.ts';

let c: Chain;
beforeAll(async () => {
  c = await openChain();
});
afterAll(async () => {
  await c.close();
});

describe('T-A-17 a second EscrowFinish', () => {
  it('before the lock: a stranger finishes, then the repeat fails', async () => {
    const d = await newDeal(c, 'funded');
    const s = await stranger(c);
    expect(await escrowsWith(c, d.wallet, d.condition)).toHaveLength(1); // setup state
    expect(outcome(await c.attempt(s, d.finishTx({ from: s.classicAddress })))).toBe('validated:tesSUCCESS');
    const after = await d.balance(d.wallet);
    expect(outcome(await c.attempt(s, d.finishTx({ from: s.classicAddress })))).toBe('validated:tecNO_TARGET');
    expect(outcome(await c.attempt(d.lawyerB.ops, d.finishTx()))).toBe('validated:tecNO_TARGET');
    expect(await d.balance(d.wallet)).toBe(after);
  });

  it('after the lock and the release: the releaser and a stranger both get tecNO_TARGET, no money moves', async () => {
    const d = await newDeal(c, 'locked');
    expect(await d.lockOk()).toBe(true); // setup state
    await d.release();
    expect(await escrowsWith(c, d.wallet, d.condition)).toHaveLength(0);
    const after = await d.balance(d.wallet);
    expect(outcome(await c.attempt(d.lawyerB.ops, d.finishTx()))).toBe('validated:tecNO_TARGET');
    const s = await stranger(c);
    expect(outcome(await c.attempt(s, d.finishTx({ from: s.classicAddress })))).toBe('validated:tecNO_TARGET');
    expect(await d.balance(d.wallet)).toBe(after);
  });

  it('after an expiry cancel: finish and a second cancel both fail with tecNO_TARGET', async () => {
    const d = await newDeal(c, 'locked', { cancelAfterSeconds: 900 });
    await advanceCloseTime(c.client, d.cancelAfter + 1);
    const s = await stranger(c);
    const owner = d.aliceBase.wallet.classicAddress;
    const cancel = () =>
      c.attempt(s, buildEscrowCancel({ account: s.classicAddress, owner, offerSequence: d.escrowSequence }, c.ctx));
    expect(outcome(await cancel())).toBe('validated:tesSUCCESS');
    expect(await escrowsWith(c, d.wallet, d.condition)).toHaveLength(0);
    expect(outcome(await c.attempt(d.lawyerB.ops, d.finishTx()))).toBe('validated:tecNO_TARGET');
    expect(outcome(await cancel())).toBe('validated:tecNO_TARGET');
  });
});
