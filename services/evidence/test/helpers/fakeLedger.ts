import { createHash } from 'node:crypto';
import type { LedgerHeader, LedgerPort, SubmitResult, ValidatedTx, XrplJson } from '@legx/contracts/ports';
import type { RippleTime, XrplHash } from '@legx/contracts/values';

export const ANCHOR_ACCOUNT = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';

/** An in-memory ledger for the anchor module: "blobs" are JSON, every submit validates in the next ledger. */
export function fakeLedger(opts: { results?: SubmitResult[]; fail?: () => Error | undefined } = {}) {
  let index = 100;
  const txs = new Map<string, ValidatedTx>();
  const submitted: XrplJson[] = [];
  const script = [...(opts.results ?? [])];
  const header = (i: number): LedgerHeader => ({
    ledgerIndex: i,
    ledgerHash: createHash('sha256').update(`ledger ${i}`).digest('hex').toUpperCase() as XrplHash,
    closeTime: (800_000_000 + i) as RippleTime,
  });
  const port: LedgerPort = {
    network: 'standalone',
    validatedLedger: async () => header(index),
    ledgerHeader: async (i) => header(i),
    snapshot: async () => {
      throw new Error('not used');
    },
    tx: async (hash) => txs.get(hash),
    autofill: async (tx) => ({ ...tx, Sequence: submitted.length + 1, LastLedgerSequence: index + 20 }),
    fees: async () => ({ baseFee: '10' as never, reserveBase: '1' as never, reserveInc: '1' as never }),
    async submitReliable(blob): Promise<SubmitResult> {
      const failure = opts.fail?.();
      if (failure) throw failure;
      const scripted = script.shift();
      if (scripted) return scripted;
      const tx = JSON.parse(blob) as XrplJson;
      submitted.push(tx);
      index += 1;
      const hash = createHash('sha256').update(blob).digest('hex').toUpperCase() as XrplHash;
      const h = header(index);
      txs.set(hash, {
        hash,
        ledgerIndex: index,
        closeTime: h.closeTime,
        tx: { ...tx, hash },
        meta: { TransactionResult: 'tesSUCCESS' },
      });
      return { status: 'validated', result: 'tesSUCCESS', hash, ledgerIndex: index, meta: {} };
    },
  };
  return { port, submitted, txs };
}
