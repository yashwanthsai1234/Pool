// RFC 9162 Merkle tree hashes and proofs, written once over an abstract "perfect subtree hash" function so that the
// in-process tree (hashes from memory) and the Tessera adapter (hashes from tiles) share the same proof algorithm.
// Local copy: replace with the tree in `@legx/core` when task 1.13 lands (status file, "Requests").
// Source: https://www.rfc-editor.org/rfc/rfc9162#section-2.1 (MTH, PATH, SUBPROOF)
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes } from '@noble/hashes/utils.js';

export type Hash = Uint8Array;

/** Hash of the perfect subtree at tree `level` and `index`: it covers leaves `[index * 2^level, (index + 1) * 2^level)`. */
export type SubtreeHash = (level: number, index: number) => Promise<Hash>;

export const leafHash = (data: Uint8Array): Hash => sha256(concatBytes(Uint8Array.of(0), data));
export const nodeHash = (left: Hash, right: Hash): Hash => sha256(concatBytes(Uint8Array.of(1), left, right));
export const EMPTY_ROOT: Hash = sha256(new Uint8Array(0));

const isPow2 = (n: number) => n > 0 && (n & (n - 1)) === 0;
/** Largest power of two strictly less than `n` (n >= 2). */
const split = (n: number) => 2 ** (Math.ceil(Math.log2(n)) - 1);

/** MTH over leaves `[start, end)`. */
async function mth(sub: SubtreeHash, start: number, end: number): Promise<Hash> {
  const n = end - start;
  if (n === 0) return EMPTY_ROOT;
  if (isPow2(n) && start % n === 0) return sub(Math.log2(n), start / n);
  const k = split(n);
  return nodeHash(await mth(sub, start, start + k), await mth(sub, start + k, end));
}

export const treeRoot = (sub: SubtreeHash, size: number): Promise<Hash> => mth(sub, 0, size);

const check = (ok: boolean, what: string) => {
  if (!ok) throw new RangeError(what);
};

/** RFC 9162 section 2.1.3.1: the audit path of leaf `index` in the tree of `size` leaves. */
export async function inclusionPath(sub: SubtreeHash, index: number, size: number): Promise<Hash[]> {
  check(
    Number.isSafeInteger(index) && Number.isSafeInteger(size) && index >= 0 && index < size,
    'index outside the tree',
  );
  const path = async (m: number, start: number, end: number): Promise<Hash[]> => {
    const n = end - start;
    if (n === 1) return [];
    const k = split(n);
    return m < k
      ? [...(await path(m, start, start + k)), await mth(sub, start + k, end)]
      : [...(await path(m - k, start + k, end)), await mth(sub, start, start + k)];
  };
  return path(index, 0, size);
}

/** RFC 9162 section 2.1.4.1: the consistency proof between the trees of `from` and `to` leaves (0 < from <= to). */
export async function consistencyPath(sub: SubtreeHash, from: number, to: number): Promise<Hash[]> {
  check(Number.isSafeInteger(from) && Number.isSafeInteger(to) && from > 0 && from <= to, 'invalid tree sizes');
  const subproof = async (m: number, start: number, end: number, whole: boolean): Promise<Hash[]> => {
    const n = end - start;
    if (m === n) return whole ? [] : [await mth(sub, start, end)];
    const k = split(n);
    return m <= k
      ? [...(await subproof(m, start, start + k, whole)), await mth(sub, start + k, end)]
      : [...(await subproof(m - k, start + k, end, false)), await mth(sub, start, start + k)];
  };
  return subproof(from, 0, to, true);
}
