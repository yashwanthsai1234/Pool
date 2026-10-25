// Small RFC 9162 and C2SP helpers the bundle needs and core does not export: the root a leaf's inclusion path leads to,
// and the C2SP `tlog-proof` text.
// Source: https://www.rfc-editor.org/rfc/rfc9162#section-2.1.3.2 (inclusion proof verification, which yields the root)
// Source: https://github.com/C2SP/C2SP/blob/main/tlog-proof.md (c2sp.org/tlog-proof@v1)
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes } from '@noble/hashes/utils.js';

const hashLeaf = (leaf: Uint8Array) => sha256(concatBytes(Uint8Array.of(0), leaf));
const hashNode = (l: Uint8Array, r: Uint8Array) => sha256(concatBytes(Uint8Array.of(1), l, r));

/** The root of the tree of `size` leaves that `path` proves `leaf` (at `index`) belongs to, or undefined if malformed. */
export function rootFromInclusion(
  leaf: Uint8Array,
  index: number,
  size: number,
  path: readonly Uint8Array[],
): Uint8Array | undefined {
  if (!Number.isInteger(index) || !Number.isInteger(size) || index < 0 || index >= size) return undefined;
  let fn = index;
  let sn = size - 1;
  let r = hashLeaf(leaf);
  for (const p of path) {
    if (sn === 0) return undefined;
    if ((fn & 1) === 1 || fn === sn) {
      r = hashNode(p, r);
      while ((fn & 1) === 0 && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else r = hashNode(r, p);
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 ? r : undefined;
}

/** A `.tlog-proof` file: index, the inclusion path, and the signed checkpoint note (both lines). */
export function tlogProof(index: number, pathHashes: readonly Uint8Array[], note: string): string {
  const path = pathHashes.map((h) => `${Buffer.from(h).toString('base64')}\n`).join('');
  return `c2sp.org/tlog-proof@v1\nindex ${index}\n${path}\n${note}`;
}
