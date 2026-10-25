// The proof algorithm against published vectors and against the textbook recursion.
// Source: https://github.com/google/certificate-transparency/blob/master/python/ct/crypto/merkle_test.py (RFC 6962 vectors)
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { consistencyPath, inclusionPath, leafHash, type SubtreeHash, treeRoot } from '../src/merkle.ts';
import { H0, H1, naiveRoot, verifyConsistency, verifyInclusion } from './helpers/refTree.ts';

const VECTOR_LEAVES = [
  '',
  '00',
  '10',
  '2021',
  '3031',
  '40414243',
  '5051525354555657',
  '606162636465666768696a6b6c6d6e6f',
].map((h) => hexToBytes(h));
const VECTOR_ROOTS = [
  '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
  'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
  'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
  'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
  '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
  '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
  'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
  '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
];

const memoSub = (leaves: Uint8Array[]): SubtreeHash => {
  const hashes = leaves.map(leafHash);
  const sub: SubtreeHash = async (level, index) =>
    level === 0
      ? (hashes[index] as Uint8Array)
      : H1(await sub(level - 1, 2 * index), await sub(level - 1, 2 * index + 1));
  return sub;
};

describe('RFC 6962 test vectors', () => {
  it.each(VECTOR_ROOTS.map((r, i) => [i + 1, r] as const))('root of the first %d leaves', async (n, root) => {
    expect(bytesToHex(await treeRoot(memoSub(VECTOR_LEAVES), n))).toBe(root);
  });

  it('inclusion proof for leaf 0 of 8 starts with the hash of leaf 1 (known vector)', async () => {
    const path = await inclusionPath(memoSub(VECTOR_LEAVES), 0, 8);
    expect(path.map(bytesToHex)).toEqual([
      '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7',
      '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e',
      '6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4',
    ]);
  });
});

describe('proofs agree with the textbook recursion and verify', () => {
  it('for random trees', async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 1, max: 70 }), fc.integer({ min: 0, max: 1_000_000 }), async (size, pick) => {
        const leaves = Array.from({ length: size }, (_, i) => Uint8Array.of(i, size));
        const sub = memoSub(leaves);
        const hashes = leaves.map(H0);
        const root = bytesToHex(naiveRoot(hashes));
        expect(bytesToHex(await treeRoot(sub, size))).toBe(root);
        const index = pick % size;
        expect(
          verifyInclusion(
            index,
            size,
            hashes[index] as Uint8Array,
            (await inclusionPath(sub, index, size)).map(bytesToHex),
            root,
          ),
        ).toBe(true);
        const from = 1 + (pick % size);
        const fromRoot = bytesToHex(naiveRoot(hashes.slice(0, from)));
        expect(
          verifyConsistency(from, size, fromRoot, root, (await consistencyPath(sub, from, size)).map(bytesToHex)),
        ).toBe(true);
      }),
      { numRuns: 150 },
    );
  });

  it('a flipped bit anywhere in a proof makes verification fail', async () => {
    const leaves = Array.from({ length: 13 }, (_, i) => Uint8Array.of(i));
    const sub = memoSub(leaves);
    const hashes = leaves.map(H0);
    const root = bytesToHex(naiveRoot(hashes));
    const path = (await inclusionPath(sub, 5, 13)).map(bytesToHex);
    for (let i = 0; i < path.length; i++) {
      const bad = [...path];
      bad[i] = (bad[i] as string).replace(/^./, (c) => (c === '0' ? '1' : '0'));
      expect(verifyInclusion(5, 13, hashes[5] as Uint8Array, bad, root)).toBe(false);
    }
  });

  it.each([
    ['index past the end', () => inclusionPath(memoSub([]), 0, 0)],
    ['negative index', () => inclusionPath(memoSub([new Uint8Array(1)]), -1, 1)],
    ['fractional size', () => inclusionPath(memoSub([new Uint8Array(1)]), 0, 1.5)],
    ['from zero', () => consistencyPath(memoSub([new Uint8Array(1)]), 0, 1)],
    ['from past to', () => consistencyPath(memoSub([new Uint8Array(1)]), 2, 1)],
  ])('refuses %s', async (_n, run) => {
    await expect(run()).rejects.toThrow(RangeError);
  });
});
