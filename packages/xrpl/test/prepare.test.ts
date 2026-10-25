// Task 2.3: prepare() adds Sequence, LastLedgerSequence and fee headroom; it never autofills a Fee the builder set.
import { describe, expect, it } from 'vitest';
import { build2, build8, build9 } from '../src/builders/index.ts';
import { EXIT_FEE_MULTIPLIER, LAST_LEDGER_OFFSET, prepare } from '../src/prepare.ts';
import { A, CTX } from './builders/fixtures.ts';

// Mirrors xrpl.js 5.3.0 Client.autofill: only absent fields are filled (client/index.ts, autofill).
const client = {
  async getLedgerIndex() {
    return 1000;
  },
  async autofill<T extends { Sequence?: number; Fee?: string; LastLedgerSequence?: number }>(tx: T) {
    return { ...tx, Sequence: tx.Sequence ?? 5, Fee: tx.Fee ?? '12' };
  },
};

describe('prepare', () => {
  const tx = build2({ alice: A.alice, shell: A.shell, amount: '1' }, CTX);
  it('LastLedgerSequence: +20 single-signed, +1800 for signature collection', async () => {
    expect((await prepare(tx, { client })).LastLedgerSequence).toBe(1000 + LAST_LEDGER_OFFSET.single);
    expect((await prepare(tx, { client, lastLedgerOffset: LAST_LEDGER_OFFSET.collection })).LastLedgerSequence).toBe(
      2800,
    );
  });
  it('keeps the builder Fee exactly (no 1.2x margin) and fills Sequence', async () => {
    const out = await prepare(tx, { client });
    expect(out).toMatchObject({ Fee: '10', Sequence: 5 });
  });
  it('exits get 5 to 10 times the fee', async () => {
    const exit = build8({ shell: A.shell, payout: A.payout, amount: '1', slot: { sequence: 9 } }, CTX);
    expect((await prepare(exit, { client, signers: 4, feeMultiplier: EXIT_FEE_MULTIPLIER.min })).Fee).toBe('250');
    expect((await prepare(exit, { client, signers: 4, feeMultiplier: EXIT_FEE_MULTIPLIER.max })).Fee).toBe('500');
    expect((await prepare(exit, { client })).Sequence).toBe(9);
  });
  it('rejects a silly multiplier or offset, and headroom on AccountDelete (the fee is burned)', async () => {
    await expect(prepare(tx, { client, feeMultiplier: 11 })).rejects.toThrow();
    await expect(prepare(tx, { client, feeMultiplier: 0 })).rejects.toThrow();
    await expect(prepare(tx, { client, lastLedgerOffset: 0 })).rejects.toThrow();
    const del = build9({ shell: A.shell, destination: A.alice, ownerReserveDrops: '200000' }, CTX);
    await expect(prepare(del, { client, feeMultiplier: 5 })).rejects.toThrow(/AccountDelete/);
    expect((await prepare(del, { client })).Fee).toBe('200000');
  });
  it('does not mutate its input', async () => {
    const copy = structuredClone(tx);
    await prepare(tx, { client, feeMultiplier: 5 });
    expect(tx).toEqual(copy);
  });
});
