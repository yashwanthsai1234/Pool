// P2.6-02 (IMPLEMENTATION 2.6; DESIGN 6.4, 5.4): rotating the slot key on the ledger is the ONLY revocation. Before the
// rotation the old group key of slot LB signs valid 4-of-4 transactions with ANY pair of its three shares (so a share
// refresh, which keeps the group key and the signer-list entry, would not stop a thief who holds two old shares). After the
// rotation (new DKG, 4-of-4 SignerListSet) a transaction signed by the old group key is refused by the ledger: the key is no
// longer in the signer list (tefBAD_SIGNATURE), alone or together with three honest slots, and nothing moves.
// Source: https://xrpl.org/docs/concepts/accounts/multi-signing ; DESIGN 6.4
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildAnchor } from '../../src/builders/index.ts';
import { nextSlot } from '../../src/multisig.ts';
import { newDeal } from '../deal.ts';
import { type Chain, openChain } from '../roles.ts';
import { outcome } from './util.ts';

let c: Chain;
beforeAll(async () => {
  c = await openChain();
});
afterAll(async () => {
  await c.close();
});

describe('P2.6-02 the old group key after a rotation', () => {
  it('signs before the rotation with every pair of shares, and is refused after it', async () => {
    const d = await newDeal(c, 'locked');
    expect(await d.lockOk()).toBe(true); // setup state
    const noop = () =>
      buildAnchor(
        { anchorAccount: d.wallet, originHash: new Uint8Array(32), treeSize: 1n, root: new Uint8Array(32) },
        c.ctx,
      );
    const oldLB = d.lawyerB.slot;
    const sequence = async () => (await nextSlot(c.rpc, d.wallet)).sequence;

    // before: three transactions, each signed by a different pair of the old LB shares (the pair rotates per signature)
    const s0 = await sequence();
    for (let i = 0; i < 3; i++) await d.multi4(noop() as never);
    expect(await sequence()).toBe(s0 + 3);

    const { fresh, oldFour } = await d.swapLawyer('LB');
    expect(oldFour).toContain(oldLB);
    expect(d.slots()).not.toContain(oldLB);
    const s1 = await sequence();

    // after: the old LB key with the three other slots, and the old four together, are refused
    const withOld = [d.alice.slot, d.lawyerA.slot, d.bob.slot, oldLB];
    for (const signers of [withOld, oldFour]) {
      const r = await c.attemptMulti({ ...noop(), Fee: String((c.ctx.baseFeeDrops as number) * 5) } as never, signers);
      expect(outcome(r)).toBe('rejected:tefBAD_SIGNATURE');
    }
    expect(await sequence()).toBe(s1); // refused: no sequence spent, nothing changed
    // the new four sign the same transaction
    const ok = await c.attemptMulti({ ...noop(), Fee: String((c.ctx.baseFeeDrops as number) * 5) } as never, d.slots());
    expect(outcome(ok)).toBe('validated:tesSUCCESS');
    expect(d.lawyerB.slot.address).toBe(fresh.slot.address);
    expect(d.lawyerB.slot.address).not.toBe(oldLB.address);
    expect(await d.lockOk()).toBe(true);
  });
});
