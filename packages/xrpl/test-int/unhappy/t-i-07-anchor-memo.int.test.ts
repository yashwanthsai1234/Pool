// T-I-07 (IMPLEMENTATION 2.6; DESIGN 8.3, 11.2): the anchor memo. A flagless AccountSet that carries a checkpoint memo
// validates at the base fee, set by hand (xrpl.js autofill adds a margin to the fee). One drop less is refused with
// telINSUF_FEE_P. The memo reads back from the validated ledger. The hand-written transaction equals the builder's.
// Source: https://xrpl.org/docs/references/protocol/transactions/types/accountset ; DESIGN 11.2
import { utf8ToBytes } from '@legx/core/dealcore';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import xrpl from 'xrpl';
import { buildAnchor } from '../../src/builders/index.ts';
import { prepare } from '../../src/prepare.ts';
import { newDeal } from '../deal.ts';
import { type Chain, openChain, up } from '../roles.ts';

let c: Chain;
beforeAll(async () => {
  c = await openChain();
});
afterAll(async () => {
  await c.close();
});

describe('T-I-07 anchor memo on a flagless AccountSet', () => {
  it('tesSUCCESS at the base fee, the memo reads back, one drop less is refused', async () => {
    const d = await newDeal(c, 'onboarded');
    const anchor = d.baseA.ops; // lawyer A's operations account, funded in P0
    const base = c.ctx.baseFeeDrops as number;
    expect(await d.balance(anchor.classicAddress)).toBeGreaterThan(0n); // setup state: the anchor account is funded
    expect(base).toBe(c.fees.baseFeeDrops);

    const origin = new Uint8Array(32).fill(0xa5);
    const root = new Uint8Array(32).fill(0x5a);
    const data = new Uint8Array(72);
    data.set(origin, 0);
    new DataView(data.buffer).setBigUint64(32, 1234n);
    data.set(root, 40);
    const byHand = {
      TransactionType: 'AccountSet' as const,
      Account: anchor.classicAddress,
      Memos: [{ Memo: { MemoType: up(utf8ToBytes('legx/ckpt/v1')), MemoData: up(data) } }],
      Fee: String(base),
    };
    expect(byHand).toEqual(
      buildAnchor({ anchorAccount: anchor.classicAddress, originHash: origin, treeSize: 1234n, root }, c.ctx),
    );

    // one drop under the base fee is refused before it enters a ledger
    const cheap = anchor.sign(await prepare({ ...byHand, Fee: String(base - 1) }, { client: c.client })).tx_blob;
    expect(await c.rawSubmit(cheap)).toBe('telINSUF_FEE_P');

    const r = await c.send(anchor, byHand);
    expect(r.meta.TransactionResult).toBe('tesSUCCESS');
    const tx = (await c.client.request({ command: 'tx', transaction: r.hash })).result as unknown as {
      tx_json: { Fee: string; Memos: unknown[]; Flags?: number; SetFlag?: number };
      validated: boolean;
    };
    expect(tx.validated).toBe(true);
    expect(tx.tx_json.Fee).toBe(String(base)); // set by hand: no autofill margin
    expect(tx.tx_json.SetFlag).toBeUndefined();
    expect(tx.tx_json.Memos).toEqual(byHand.Memos);
    expect(xrpl.convertHexToString(byHand.Memos[0]?.Memo.MemoType as string)).toBe('legx/ckpt/v1');

    // an autofilled copy carries a fee margin; the hand-set fee avoids it
    const auto = await c.client.autofill({ TransactionType: 'AccountSet', Account: anchor.classicAddress });
    expect(Number((auto as { Fee?: string }).Fee)).toBeGreaterThan(base);
  });
});
