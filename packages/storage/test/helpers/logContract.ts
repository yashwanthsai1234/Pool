// The one TransparencyLogPort contract suite (P3.6-05 sibling for the log): every implementation runs it. Roots and proofs
// are checked by the independent reference in refTree.ts, notes by core's `verifyCheckpoint`.
import type { TransparencyLogPort } from '@legx/contracts/ports';
import { type CheckpointKeys, verifyCheckpoint } from '@legx/core/pqCheckpoint';
import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { H0, naiveRoot, verifyConsistency, verifyInclusion } from './refTree.ts';

export interface LogUnderTest {
  readonly log: TransparencyLogPort;
  readonly origin: string;
  readonly keys: CheckpointKeys;
  close?(): Promise<void>;
}

const leaf = (i: number) => new TextEncoder().encode(`leaf-${i}`);
const rootOf = (n: number) => bytesToHex(naiveRoot(Array.from({ length: n }, (_, i) => H0(leaf(i)))));

export function logContract(name: string, make: () => Promise<LogUnderTest>, opts: { sizes?: number[] } = {}): void {
  describe(`TransparencyLogPort contract: ${name}`, () => {
    const sizes = opts.sizes ?? [1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 31];

    it('assigns sequential indexes and publishes a hybrid checkpoint whose root is the RFC 9162 root', async () => {
      const t = await make();
      try {
        for (let i = 0; i < 9; i++) expect(await t.log.add(leaf(i))).toEqual({ index: i });
        const cp = await t.log.checkpoint();
        expect(cp.origin).toBe(t.origin);
        expect(cp.treeSize).toBe(9);
        expect(cp.rootHash).toBe(rootOf(9));
        expect(verifyCheckpoint(cp.note, t.origin, t.keys)).toMatchObject({ ok: true, treeSize: 9 });
      } finally {
        await t.close?.();
      }
    });

    it('proves inclusion of every leaf for every tree size, checked by the independent verifier', async () => {
      const t = await make();
      try {
        const total = Math.max(...sizes);
        for (let i = 0; i < total; i++) await t.log.add(leaf(i));
        for (const size of sizes) {
          const root = rootOf(size);
          for (let i = 0; i < size; i++) {
            const path = await t.log.inclusionProof(i, size);
            expect(verifyInclusion(i, size, H0(leaf(i)), path, root), `inclusion ${i} in ${size}`).toBe(true);
          }
        }
      } finally {
        await t.close?.();
      }
    });

    it('proves consistency between every pair of sizes, checked by the independent verifier', async () => {
      const t = await make();
      try {
        const total = Math.max(...sizes);
        for (let i = 0; i < total; i++) await t.log.add(leaf(i));
        for (const from of sizes) {
          for (const to of sizes.filter((s) => s >= from)) {
            const proof = await t.log.consistencyProof(from, to);
            expect(verifyConsistency(from, to, rootOf(from), rootOf(to), proof), `consistency ${from}..${to}`).toBe(
              true,
            );
          }
        }
      } finally {
        await t.close?.();
      }
    });

    it('rejects a proof for the wrong leaf or the wrong root (the verifier is not vacuous)', async () => {
      const t = await make();
      try {
        for (let i = 0; i < 6; i++) await t.log.add(leaf(i));
        const path = await t.log.inclusionProof(2, 6);
        expect(verifyInclusion(2, 6, H0(leaf(3)), path, rootOf(6))).toBe(false);
        expect(verifyInclusion(2, 6, H0(leaf(2)), path, rootOf(5))).toBe(false);
      } finally {
        await t.close?.();
      }
    });

    it('refuses proofs outside the log', async () => {
      const t = await make();
      try {
        for (let i = 0; i < 3; i++) await t.log.add(leaf(i));
        await expect(t.log.inclusionProof(3, 3)).rejects.toThrow();
        await expect(t.log.inclusionProof(0, 4)).rejects.toThrow();
        await expect(t.log.inclusionProof(-1, 3)).rejects.toThrow();
        await expect(t.log.consistencyProof(0, 3)).rejects.toThrow();
        await expect(t.log.consistencyProof(3, 2)).rejects.toThrow();
        await expect(t.log.consistencyProof(2, 4)).rejects.toThrow();
      } finally {
        await t.close?.();
      }
    });

    it('gives concurrent adds distinct indexes and loses none', async () => {
      const t = await make();
      try {
        const results = await Promise.all(Array.from({ length: 25 }, (_, i) => t.log.add(leaf(i))));
        expect(new Set(results.map((r) => r.index)).size).toBe(25);
        expect((await t.log.checkpoint()).treeSize).toBe(25);
      } finally {
        await t.close?.();
      }
    });
  });
}
