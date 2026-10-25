// T-I-09 (IMPLEMENTATION 2.6; DESIGN 11.2): AccountDelete with four signers is charged one owner reserve (5 XRP on the
// standalone config), and rippled does not add the per-signer fee. One drop under the reserve is refused with
// telINSUF_FEE_P; the reserve exactly validates. The fee is burned: the shell's balance falls by it.
// Source: https://xrpl.org/docs/references/protocol/transactions/types/accountdelete ; DESIGN 11.2 (AccountDelete::calculateBaseFee)
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { build9 } from '../../src/builders/index.ts';
import { advanceLedgers } from '../../src/ledger.ts';
import { combine, nextSlot } from '../../src/multisig.ts';
import { prepare } from '../../src/prepare.ts';
import { newDeal } from '../deal.ts';
import { type Chain, type Json, ledgerRef, openChain } from '../roles.ts';

let c: Chain;
beforeAll(async () => {
  c = await openChain();
});
afterAll(async () => {
  await c.close();
});

describe('T-I-09 AccountDelete with 4 signers', () => {
  it('is charged exactly one owner reserve', async () => {
    const d = await newDeal(c, 'locked');
    expect(await d.lockOk()).toBe(true); // setup state
    await d.release();
    await d.exit('bob');
    const seq = (await nextSlot(c.rpc, d.wallet)).sequence;
    await advanceLedgers(c.client, Math.max(0, seq + 256 - (await ledgerRef(c)).index));

    const reserve = c.fees.ownerReserveDrops;
    expect(reserve).toBe(5_000_000); // setup state: the standalone owner reserve
    const signed = async (fee: number) => {
      const tx = build9(
        { shell: d.wallet, destination: d.aliceBase.wallet.classicAddress, ownerReserveDrops: String(fee) },
        c.ctx,
      );
      const prepared = await prepare(tx, { client: c.client, signers: 4, lastLedgerOffset: 1800 });
      expect(prepared.Fee).toBe(String(fee)); // prepare did not change it
      return combine(
        d.slots().map((s) => s.signTx(prepared as unknown as Json)),
        d.slots().map((s) => s.address),
      );
    };
    expect(await c.rawSubmit(await signed(reserve - 1))).toBe('telINSUF_FEE_P');
    expect(await d.balance(d.wallet)).toBeGreaterThan(0n); // still open

    const shellBefore = await d.balance(d.wallet);
    const aliceBefore = await d.balance(d.aliceBase.wallet.classicAddress);
    const r = await c.submitBlob(await signed(reserve));
    expect(r).toMatchObject({ status: 'validated', result: 'tesSUCCESS' });
    const tx = (await c.client.request({ command: 'tx', transaction: (r as { hash: string }).hash }))
      .result as unknown as { tx_json: { Fee: string; Signers: unknown[] } };
    expect(tx.tx_json.Signers).toHaveLength(4);
    expect(tx.tx_json.Fee).toBe(String(reserve));
    // the fee is burned: Alice receives the shell's whole balance minus exactly one owner reserve
    expect((await d.balance(d.aliceBase.wallet.classicAddress)) - aliceBefore).toBe(shellBefore - BigInt(reserve));
  });
});
