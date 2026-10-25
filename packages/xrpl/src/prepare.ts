// Autofill with headroom (DESIGN 7.5). Builders set the minimum Fee; this adds Sequence and LastLedgerSequence and
// scales the Fee. xrpl.js autofill only fills fields that are absent, and its own 1.2x fee cushion applies only to a
// missing Fee, so a builder's exact Fee is never silently raised unless the caller asks for headroom here.
// Source: https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/src/client/index.ts (autofill)
// Source: https://xrpl.org/docs/concepts/transactions/reliable-transaction-submission
import type { SubmittableTransaction } from 'xrpl';

/** Ledgers to wait: single-signed, and a multi-hour signature collection (about 2 hours). DESIGN 7.5. */
export const LAST_LEDGER_OFFSET = { single: 20, collection: 1800 } as const;
/** Exits get 5 to 10 times the fee so a busy network does not drop them (DESIGN 7.5, step 7). */
export const EXIT_FEE_MULTIPLIER = { min: 5, max: 10 } as const;

export interface Preparer {
  getLedgerIndex(): Promise<number>;
  autofill<T extends SubmittableTransaction>(tx: T, signersCount?: number): Promise<T>;
}

export interface PrepareOptions {
  client: Preparer;
  /** Number of signers, for the fee xrpl.js computes when the builder left Fee out. */
  signers?: number;
  lastLedgerOffset?: number;
  /** Multiplies the builder's Fee. 1 keeps it exact (T-I-07); exits use 5 to 10. */
  feeMultiplier?: number;
}

export async function prepare<T extends SubmittableTransaction>(tx: T, o: PrepareOptions): Promise<T> {
  const offset = o.lastLedgerOffset ?? LAST_LEDGER_OFFSET.single;
  const mult = o.feeMultiplier ?? 1;
  if (!Number.isInteger(offset) || offset < 1) throw new Error('lastLedgerOffset must be a positive integer');
  if (!Number.isInteger(mult) || mult < 1 || mult > EXIT_FEE_MULTIPLIER.max) {
    throw new Error(`feeMultiplier must be an integer from 1 to ${EXIT_FEE_MULTIPLIER.max}`);
  }
  // AccountDelete's fee is burned (one owner reserve), so extra headroom would be real money lost.
  if (tx.TransactionType === 'AccountDelete' && mult !== 1) throw new Error('AccountDelete takes no fee headroom');
  const base: T = { ...tx, LastLedgerSequence: (await o.client.getLedgerIndex()) + offset };
  if (base.Fee !== undefined) base.Fee = (BigInt(base.Fee) * BigInt(mult)).toString();
  return o.client.autofill(base, o.signers);
}
