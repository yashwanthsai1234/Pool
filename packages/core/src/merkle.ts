// RFC 9162 consistency proofs. The tree hash, inclusion path and inclusion check live in dealcore.ts.
// Source: https://www.rfc-editor.org/rfc/rfc9162#section-2.1.4 (generation 2.1.4.1, verification 2.1.4.2)
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes } from '@noble/hashes/utils.js';
import { mth } from './dealcore.ts';

const nodeHash = (l: Uint8Array, r: Uint8Array) => sha256(concatBytes(new Uint8Array([1]), l, r));
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
const split = (n: number) => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};

// Hashes that show the tree of the first `size1` leaves is a prefix of the tree of all `leaves`.
export function consistencyProof(size1: number, leaves: Uint8Array[]): Uint8Array[] {
  const n = leaves.length;
  if (!Number.isInteger(size1) || size1 < 0 || size1 > n)
    throw new Error('consistency proof needs 0 <= size1 <= size2');
  if (size1 === 0 || size1 === n) return [];
  const sub = (m: number, d: Uint8Array[], complete: boolean): Uint8Array[] => {
    if (m === d.length) return complete ? [] : [mth(d)];
    const k = split(d.length);
    return m <= k
      ? [...sub(m, d.slice(0, k), complete), mth(d.slice(k))]
      : [...sub(m - k, d.slice(k), false), mth(d.slice(0, k))];
  };
  return sub(size1, leaves, true);
}

// Checks that `root2` (tree of `size2` leaves) extends `root1` (first `size1` leaves). Never throws.
export function verifyConsistency(
  size1: number,
  size2: number,
  root1: Uint8Array,
  root2: Uint8Array,
  proof: Uint8Array[],
): boolean {
  if (!Number.isInteger(size1) || !Number.isInteger(size2) || size1 < 1 || size1 > size2) return false; // size 0 has no proof (transparency-dev vectors size1-is-zero, sizes-are-equal-zero)
  if (size1 === size2) return proof.length === 0 && same(root1, root2);
  const path = (size1 & (size1 - 1)) === 0 ? [root1, ...proof] : proof;
  if (path.length === 0) return false;
  let fn = size1 - 1;
  let sn = size2 - 1;
  while (fn & 1) {
    fn >>= 1;
    sn >>= 1;
  }
  let fr = path[0]!;
  let sr = path[0]!;
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if (fn & 1 || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      while (!(fn & 1) && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && same(fr, root1) && same(sr, root2);
}
