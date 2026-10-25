// P2.6-01 (IMPLEMENTATION 2.6, review finding 3, DQ-3): a stranger opens a trust line to the shell after step 2 and before
// step 5c (DisallowIncomingTrustline). The line costs the shell no reserve (the stranger's side holds it), so the shell's
// OwnerCount does not change, but the line is a RippleState in the shell's objects: the lock checker blocks
// (UNEXPECTED_OWNED_RIPPLESTATE and OWNER_COUNT_MATCHES) and the release gate refuses. Only the stranger can remove it: a
// 4-of-4 TrustSet from the shell leaves it in place, and the stranger needs limit 0 together with tfSetNoRipple. After step 5c the same TrustSet is refused (tecNO_PERMISSION).
// Source: https://xrpl.org/docs/references/protocol/transactions/types/trustset ; IMPLEMENTATION Appendix B, DQ-3
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { newDeal, type Stage } from '../deal.ts';
import { type Chain, openChain } from '../roles.ts';
import { outcome, stranger } from './util.ts';

let c: Chain;
beforeAll(async () => {
  c = await openChain();
});
afterAll(async () => {
  await c.close();
});

const TF_SET_NO_RIPPLE = 0x00020000;
const line = (issuer: string) => ({ currency: 'USD', issuer, value: '100' });

describe('P2.6-01 a stranger opens a trust line before step 5c', () => {
  it.each<Stage>(['funded', 'domain'])(
    'opened after stage %s: the checker blocks, only the stranger can remove it',
    async (phase) => {
      const d = await newDeal(c, phase);
      const s = await stranger(c);
      const ownerCount = async () =>
        (await c.client.request({ command: 'account_info', account: d.wallet, ledger_index: 'validated' })).result
          .account_data.OwnerCount;
      const countBefore = await ownerCount();
      expect(await d.objects('state')).toEqual([]); // setup state

      expect(
        outcome(
          await c.attempt(s, { TransactionType: 'TrustSet', Account: s.classicAddress, LimitAmount: line(d.wallet) }),
        ),
      ).toBe('validated:tesSUCCESS');
      expect(await d.objects('state')).toHaveLength(1);
      expect(await ownerCount()).toBe(countBefore); // DQ-3: the line holds no reserve for the wallet

      expect((await d.lockFlagged()).sort()).toEqual(['OWNER_COUNT_MATCHES', 'UNEXPECTED_OWNED_RIPPLESTATE']);
      expect((await d.gate()).failing).toEqual(['LOCK_OK']);

      // The shell cannot remove it: its 4-of-4 TrustSet with limit 0 leaves the stranger's side in place.
      await d.multi4({
        TransactionType: 'TrustSet',
        Account: d.wallet,
        LimitAmount: { ...line(s.classicAddress), value: '0' },
      });
      expect(await d.objects('state')).toHaveLength(1);
      expect(await d.lockOk()).toBe(false);

      // The stranger's limit 0 alone does not delete it either: an account without DefaultRipple must also SET NoRipple
      // (that is its default state), or its side still counts as non-default and keeps the line.
      const zero = (flags: number) =>
        c.attempt(s, {
          TransactionType: 'TrustSet',
          Account: s.classicAddress,
          LimitAmount: { ...line(d.wallet), value: '0' },
          Flags: flags,
        });
      expect(outcome(await zero(0))).toBe('validated:tesSUCCESS');
      expect(await d.objects('state')).toHaveLength(1);
      expect(outcome(await zero(TF_SET_NO_RIPPLE))).toBe('validated:tesSUCCESS');
      expect(await d.objects('state')).toEqual([]);
      expect(await d.lockOk()).toBe(true);
      expect((await d.gate()).failing).toEqual([]);
    },
  );

  it('opened after step 5c: DisallowIncomingTrustline refuses it', async () => {
    const d = await newDeal(c, 'disallow');
    const s = await stranger(c);
    expect(((await d.accountFlags()) & 0x20000000) !== 0).toBe(true); // setup state: the flag is on
    expect(
      outcome(
        await c.attempt(s, { TransactionType: 'TrustSet', Account: s.classicAddress, LimitAmount: line(d.wallet) }),
      ),
    ).toBe('validated:tecNO_PERMISSION');
    expect(await d.objects('state')).toEqual([]);
  });

  it.todo(
    'DQ: DQ-3 proposes to set the DisallowIncoming flags right after step 2 and to warn on a trust line that holds no reserve for the wallet; the design has not decided it',
  );
});
