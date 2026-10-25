// T-Z-02: 10,000 random transactions of every type our builders make. xrpl.js (ripple-binary-codec) and xrpl-py 5.2.0
// must encode them byte for byte the same: plain, for single signing and for multi-signing.

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { encode, encodeForMultiSigning, encodeForSigning } from 'xrpl';
import { BUILDER_COUNT, CASES, Prng, PyRef, randomTx, seedsToRun } from '../src/index.ts';

type Tx = Parameters<typeof encodeForSigning>[0];
let py: PyRef;
beforeAll(() => {
  py = new PyRef();
});
afterAll(() => py.close());

describe('T-Z-02 xrpl.js against xrpl-py', () => {
  for (const seed of seedsToRun()) {
    it(`seed ${seed}: ${CASES} transactions, ${BUILDER_COUNT} builder types`, async () => {
      const r = new Prng(seed);
      const txs = Array.from({ length: CASES }, (_, i) => randomTx(r, i));
      const got = await py.call<{ encode: string; signing: string; multisign: string } | 'ERR'>('xrpl', txs);
      const diffs: string[] = [];
      txs.forEach((tx, i) => {
        const want = {
          encode: encode(tx as unknown as Tx),
          signing: encodeForSigning(tx as unknown as Tx),
          multisign: encodeForMultiSigning(tx as unknown as Tx, tx.Account as string),
        };
        if (JSON.stringify(got[i]) !== JSON.stringify(want))
          diffs.push(`#${i} ${tx.TransactionType}: ${JSON.stringify(tx)}`);
      });
      expect(diffs.slice(0, 3), `seed ${seed}: ${diffs.length} of ${CASES} differ`).toEqual([]);
    }, 600_000);
  }
});
