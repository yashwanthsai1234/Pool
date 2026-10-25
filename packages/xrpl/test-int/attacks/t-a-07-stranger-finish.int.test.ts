// T-A-07 (IMPLEMENTATION 2.6; DESIGN D4, 7.3): a stranger's EscrowFinish with the right release code. DepositAuth is the
// only thing that stops it, because the release code is a bearer secret. Run in every phase of the lock: with no lock
// at all the finish works (which is why the code never leaves lawyer B before the lock check); once DepositAuth is on it
// fails with tecNO_PERMISSION whoever sends it, before and after the one DepositPreauth entry exists. The releaser's
// own finish is the positive control: the setup is not what stopped the stranger.
// Source: https://xrpl.org/docs/references/protocol/transactions/types/escrowfinish ; DESIGN 5.2 steps 5b and 5d
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { newDeal, type Stage } from '../deal.ts';
import { type Chain, openChain } from '../roles.ts';
import { escrowsWith, outcome, stranger } from './util.ts';

const DEPOSIT_AUTH = 0x01000000;
let c: Chain;
beforeAll(async () => {
  c = await openChain();
});
afterAll(async () => {
  await c.close();
});

describe('T-A-07 a stranger finishes the escrow with the right code', () => {
  it.each<[Stage, boolean]>([
    ['funded', false],
    ['domain', true],
    ['preauth', true],
    ['locked', true],
  ])('phase %s (DepositAuth on: %s)', async (phase, depositAuth) => {
    const d = await newDeal(c, phase);
    // setup state: the quarantine escrow exists and the DepositAuth flag is what the phase says
    expect(await escrowsWith(c, d.wallet, d.condition)).toHaveLength(1);
    expect(((await d.accountFlags()) & DEPOSIT_AUTH) !== 0).toBe(depositAuth);
    expect(await d.objects('deposit_preauth')).toHaveLength(d.reached('preauth') ? 1 : 0);

    const strangers = [await stranger(c), d.aliceBase.wallet, d.lawyerA.ops, d.bobBase.wallet];
    if (!depositAuth) {
      // no lock yet: anyone holding the code can finish, and the money lands in the shell
      const before = await d.balance(d.wallet);
      const [first] = strangers;
      if (!first) throw new Error('no stranger');
      const r = await c.attempt(first, d.finishTx({ from: first.classicAddress }));
      expect(outcome(r)).toBe('validated:tesSUCCESS');
      expect((await d.balance(d.wallet)) - before).toBe(50_000_000n);
      return;
    }
    const before = await d.balance(d.wallet);
    for (const s of strangers) {
      const r = await c.attempt(s, d.finishTx({ from: s.classicAddress }));
      expect(outcome(r), s.classicAddress).toBe('validated:tecNO_PERMISSION');
    }
    // nothing moved and the escrow is still there
    expect(await d.balance(d.wallet)).toBe(before);
    expect(await escrowsWith(c, d.wallet, d.condition)).toHaveLength(1);

    if (d.reached('preauth')) {
      // a stranger with a wrong code fails on the code, not the permission; the sealed releaser succeeds with the right one
      const bad = await c.attempt(d.lawyerB.ops, d.finishTx({ fulfillment: `A0228020${'00'.repeat(32)}` }));
      expect(outcome(bad)).toBe('validated:tecCRYPTOCONDITION_ERROR');
      const ok = await c.attempt(d.lawyerB.ops, d.finishTx());
      expect(outcome(ok)).toBe('validated:tesSUCCESS');
      expect((await d.balance(d.wallet)) - before).toBe(50_000_000n);
    } else {
      // DepositAuth on but no preauthorized account yet: even lawyer B cannot finish
      const r = await c.attempt(d.lawyerB.ops, d.finishTx());
      expect(outcome(r)).toBe('validated:tecNO_PERMISSION');
    }
  });
});
