// An independent reference for the tests: naive RFC 9162 hashing and the two proof VERIFIERS (sections 2.1.3.2, 2.1.4.2).
// Nothing here shares code with src/merkle.ts.
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils.js';

export const H0 = (d: Uint8Array) => sha256(concatBytes(Uint8Array.of(0), d));
export const H1 = (a: Uint8Array, b: Uint8Array) => sha256(concatBytes(Uint8Array.of(1), a, b));

/** MTH over already-hashed leaves, by the textbook recursion. */
export function naiveRoot(hashes: readonly Uint8Array[]): Uint8Array {
  if (hashes.length === 0) return sha256(new Uint8Array(0));
  if (hashes.length === 1) return hashes[0] as Uint8Array;
  let k = 1;
  while (k * 2 < hashes.length) k *= 2;
  return H1(naiveRoot(hashes.slice(0, k)), naiveRoot(hashes.slice(k)));
}

export function verifyInclusion(
  index: number,
  size: number,
  leaf: Uint8Array,
  path: readonly string[],
  root: string,
): boolean {
  if (index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const hex of path) {
    const p = hexToBytes(hex);
    if (sn === 0) return false;
    if (fn & 1 || fn === sn) {
      r = H1(p, r);
      if (!(fn & 1)) {
        while (!(fn & 1) && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      r = H1(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && bytesToHex(r) === root;
}

export function verifyConsistency(
  first: number,
  second: number,
  firstRoot: string,
  secondRoot: string,
  proofHex: readonly string[],
): boolean {
  if (first === second) return proofHex.length === 0 && firstRoot === secondRoot;
  if (first === 0 || first > second) return false;
  const proof = proofHex.map((h) => hexToBytes(h));
  if ((first & (first - 1)) === 0) proof.unshift(hexToBytes(firstRoot));
  if (proof.length === 0) return false;
  let fn = first - 1;
  let sn = second - 1;
  while (fn & 1) {
    fn >>= 1;
    sn >>= 1;
  }
  let fr = proof[0] as Uint8Array;
  let sr = fr;
  for (const c of proof.slice(1)) {
    if (sn === 0) return false;
    if (fn & 1 || fn === sn) {
      fr = H1(c, fr);
      sr = H1(c, sr);
      if (!(fn & 1)) {
        while (!(fn & 1) && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      sr = H1(sr, c);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && bytesToHex(fr) === firstRoot && bytesToHex(sr) === secondRoot;
}
