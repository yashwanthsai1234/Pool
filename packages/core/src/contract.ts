import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { mth, inclusionPath, verifyInclusion } from './dealcore.ts';

const lp = (b: Uint8Array) => { const h = new Uint8Array(4); new DataView(h.buffer).setUint32(0, b.length); return concatBytes(h, b); };
const u32 = (n: number) => { const h = new Uint8Array(4); new DataView(h.buffer).setUint32(0, n); return h; };
const TAG = utf8ToBytes('legx/clause/v1');

/**
 * The bytes of one clause (DESIGN 6.1, encoding rules of 6): one leading byte-order mark removed, Unicode NFC, CRLF
 * to LF; a lone CR, or a lone surrogate that has no UTF-8 form, is refused with a RangeError. Every client must
 * normalize this way, or the same text gives another contract root (I-E1).
 * Source: https://www.unicode.org/reports/tr15/ (NFC); https://www.rfc-editor.org/rfc/rfc3629 (UTF-8, no surrogates)
 */
export function clauseBytes(text: string): Uint8Array {
  const t = (text.startsWith('\uFEFF') ? text.slice(1) : text).normalize('NFC').replaceAll('\r\n', '\n');
  if (t.includes('\r')) throw new RangeError('LONE_CR');
  if (/\p{Cs}/u.test(t)) throw new RangeError('LONE_SURROGATE');
  return utf8ToBytes(t);
}

// Leaf data for clause i. mth() adds the RFC 9162 0x00 leaf prefix.
export function clauseLeaf(i: number, salt: Uint8Array, clause: Uint8Array): Uint8Array {
  if (salt.length !== 32) throw new Error('salt must be 32 bytes');
  return concatBytes(lp(TAG), u32(i), lp(salt), lp(clause));
}
export function contractRoot(clauses: Uint8Array[], salts: Uint8Array[]): Uint8Array {
  return mth(clauses.map((c, i) => clauseLeaf(i, salts[i]!, c)));
}
export function proveClause(i: number, clauses: Uint8Array[], salts: Uint8Array[]) {
  const leaves = clauses.map((c, j) => clauseLeaf(j, salts[j]!, c));
  return { index: i, size: leaves.length, salt: salts[i]!, clause: clauses[i]!, path: inclusionPath(i, leaves) };
}
export function verifyClause(p: ReturnType<typeof proveClause>, root: Uint8Array): boolean {
  return verifyInclusion(clauseLeaf(p.index, p.salt, p.clause), p.index, p.size, p.path, root);
}
