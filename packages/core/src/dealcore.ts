import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes, concatBytes, utf8ToBytes, randomBytes } from '@noble/hashes/utils.js';
import { Wallet } from 'xrpl';
import type { PublicDealData } from '@legx/contracts/deal';

// ---------- length-prefixed tuple hashing (unambiguous) ----------
const u32 = (n: number) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };
export function tupleHash(tag: string, parts: Uint8Array[]): Uint8Array {
  const t = utf8ToBytes(tag);
  const chunks: Uint8Array[] = [u32(t.length), t];
  for (const p of parts) chunks.push(u32(p.length), p);
  return sha256(concatBytes(...chunks));
}

// ---------- PREIMAGE-SHA-256 crypto-condition (XRPL escrow) ----------
export function makeCondition(preimage: Uint8Array) {
  if (preimage.length !== 32) throw new Error('preimage must be 32 bytes');
  const fp = sha256(preimage);
  // condition: A0 25 | 80 20 <fingerprint> | 81 01 <cost=len>
  const condition = 'A0258020' + bytesToHex(fp).toUpperCase() + '810120';
  // fulfillment: A0 22 | 80 20 <preimage>
  const fulfillment = 'A0228020' + bytesToHex(preimage).toUpperCase();
  return { condition, fulfillment };
}

/**
 * Reads back what `makeCondition` writes, and nothing else: the PREIMAGE-SHA-256 condition of a 32-byte preimage
 * (its fingerprint) and its fulfillment (the preimage). Any other DER, type, length or cost gives undefined, so the
 * watcher never parses escrow conditions with a general decoder (I-25).
 * Source: https://datatracker.ietf.org/doc/html/draft-thomas-crypto-conditions-04#section-8.1 ;
 * https://xrpl.org/docs/references/protocol/transactions/types/escrowcreate (Condition), escrowfinish (Fulfillment)
 */
export function parseCondition(hex: string): Uint8Array | undefined {
  const m = /^A0258020([0-9A-F]{64})810120$/i.exec(hex);
  return m ? hexToBytes(m[1] as string) : undefined;
}
export function parseFulfillment(hex: string): Uint8Array | undefined {
  const m = /^A0228020([0-9A-F]{64})$/i.exec(hex);
  return m ? hexToBytes(m[1] as string) : undefined;
}

// ---------- passport commitment (hiding + binding) ----------
export function passportCommitment(record: Uint8Array, salt: Uint8Array): Uint8Array {
  if (salt.length !== 32) throw new Error('salt must be 32 bytes');
  return tupleHash('legx/passport-commit/v1', [salt, record]);
}

// ---------- public deal stamps (key1/key2) ----------
export function dealStamp(contractHash: Uint8Array, side: 'A' | 'B'): Uint8Array {
  return hkdf(sha256, contractHash, undefined, utf8ToBytes(`legx/deal-stamp/v1/${side}`), 32);
}

// ---------- x-key: deal-bound Ed25519 key born on the device ----------
// dealSecret: 32 random bytes made on the device for THIS deal, never leaves it (backed up encrypted).
export function deriveXKey(dealSecret: Uint8Array, stamp: Uint8Array, commitment: Uint8Array, side: 'A' | 'B') {
  const seed = hkdf(sha256, dealSecret, stamp, concatBytes(utf8ToBytes(`legx/xkey/v1/ed25519/${side}`), commitment), 32);
  const pub = ed25519.getPublicKey(seed);
  const wallet = new Wallet('ED' + bytesToHex(pub).toUpperCase(), 'ED' + bytesToHex(seed).toUpperCase());
  return { wallet, publicKeyHex: wallet.publicKey };
}

// ---------- binding statement: x-key signs (commitment, deal) ----------
// side: 'A' | 'B' for clients, 'LA' | 'LB' for lawyers (whose commitment is a bar-record commitment)
export function bindingMessage(contractHash: Uint8Array, commitment: Uint8Array, xPubHex: string, side: 'A'|'B'|'LA'|'LB') {
  return tupleHash('legx/binding/v1', [contractHash, commitment, hexToBytes(xPubHex), utf8ToBytes(side)]);
}
export function signBinding(seedHex: string, msg: Uint8Array) {
  return ed25519.sign(msg, hexToBytes(seedHex.slice(2)));
}
export function verifyBinding(xPubHex: string, msg: Uint8Array, sig: Uint8Array) {
  return ed25519.verify(sig, msg, hexToBytes(xPubHex.slice(2)), { zip215: false }); // strict RFC 8032
}

// ---------- deal seal and Domain (DESIGN 6.6, task 1.6) ----------
type SealField = keyof PublicDealData;
type Encode = (d: PublicDealData) => Uint8Array;

function bytesOf(d: PublicDealData, f: SealField, len: number): Uint8Array {
  const b = hexToBytes(String(d[f]));
  if (b.length !== len) throw new Error(`${f} must be ${len} bytes, got ${b.length}`);
  return b;
}
const b32 = (f: SealField): Encode => (d) => bytesOf(d, f, 32);
// Slot keys are FROST Ed25519 group keys in the 33-byte XRPL form (DESIGN 6.4, encoding rules in DESIGN 6).
const slotPub = (f: SealField): Encode => (d) => {
  const b = bytesOf(d, f, 33);
  if (b[0] !== 0xed) throw new Error(`${f} must be an ED-prefixed Ed25519 key`);
  return b;
};
const text = (f: SealField): Encode => (d) => utf8ToBytes(String(d[f]));
const oneOf = (f: SealField, allowed: readonly string[]): Encode => (d) => {
  if (!allowed.includes(String(d[f]))) throw new Error(`${f} must be one of ${allowed.join(', ')}`);
  return utf8ToBytes(String(d[f]));
};
// "rAddr" or "rAddr:tag"; a tag is base 10, 0 to 4294967295, no leading zeros (DESIGN 6 encoding rules, 6.6).
const payout = (f: SealField): Encode => (d) => {
  const s = String(d[f]);
  const m = /^(r[1-9A-HJ-NP-Za-km-z]+)(?::(0|[1-9][0-9]{0,9}))?$/.exec(s);
  if (!m || (m[2] !== undefined && Number(m[2]) > 0xffffffff)) throw new Error(`${f}: bad payout "${s}"`);
  return utf8ToBytes(s);
};
const quorum: Encode = (d) => {
  if (!Number.isInteger(d.quorum) || d.quorum < 0 || d.quorum > 0xffffffff) throw new Error('quorum must be a uint32');
  return u32(d.quorum);
};
// Plain string sort (UTF-16 code units; classic addresses are ASCII, so this is the UTF-8 byte order), not rippled's
// numeric AccountID sort for Signers (DESIGN 6.8).
const signerAccounts: Encode = (d) => utf8ToBytes([...d.signerAccounts].sort().join(','));

const ID_METHODS = ['zkpassport', 'nfc-chip'] as const;
// Which identity methods each identityPolicy allows (DESIGN 6.10, 6.15).
const POLICY_ALLOWS: Record<string, readonly string[]> = { zk: ['zkpassport'], 'zk-or-chip': ID_METHODS, chip: ['nfc-chip'] };

/** The 29 seal fields with their byte encodings, in DESIGN 6.6 order. Source: DESIGN 6.6 */
export const SEAL_FIELDS: readonly (readonly [SealField, Encode])[] = [
  ['contractRoot', b32('contractRoot')],
  ['signedContractSeal', b32('signedContractSeal')],
  ['walletAddress', text('walletAddress')],
  ['xPubA', slotPub('xPubA')],
  ['xPubB', slotPub('xPubB')],
  ['commitmentA', b32('commitmentA')], // C_A
  ['commitmentB', b32('commitmentB')], // C_B
  ['idMethodA', oneOf('idMethodA', ID_METHODS)],
  ['idMethodB', oneOf('idMethodB', ID_METHODS)],
  ['identityPolicy', oneOf('identityPolicy', Object.keys(POLICY_ALLOWS))],
  ['lawyerPubA', slotPub('lawyerPubA')],
  ['lawyerPubB', slotPub('lawyerPubB')],
  ['lawyerCommitmentA', b32('lawyerCommitmentA')], // LC_A
  ['lawyerCommitmentB', b32('lawyerCommitmentB')], // LC_B
  ['lawyerOpsA', text('lawyerOpsA')],
  ['lawyerOpsB', text('lawyerOpsB')],
  ['releaserAccount', text('releaserAccount')],
  ['slotPolicyA', b32('slotPolicyA')],
  ['slotPolicyLA', b32('slotPolicyLA')],
  ['slotPolicyB', b32('slotPolicyB')],
  ['slotPolicyLB', b32('slotPolicyLB')],
  ['pqKeyHashA', b32('pqKeyHashA')],
  ['pqKeyHashLA', b32('pqKeyHashLA')],
  ['pqKeyHashB', b32('pqKeyHashB')],
  ['pqKeyHashLB', b32('pqKeyHashLB')],
  ['signerAccounts', signerAccounts],
  ['quorum', quorum],
  ['payoutA', payout('payoutA')], // Alice's refund address
  ['payoutB', payout('payoutB')], // Bob's payment address
];

/** dealSeal = tupleHash("legx/dealseal/v1", the 29 fields). Throws on any input DESIGN 6.6 refuses. Source: DESIGN 6.6 */
export function dealSeal(d: PublicDealData): Uint8Array {
  if (d.releaserAccount !== d.lawyerOpsB) throw new Error('releaserAccount must equal lawyerOpsB');
  const parts = SEAL_FIELDS.map(([, encode]) => encode(d));
  for (const m of [d.idMethodA, d.idMethodB])
    if (!POLICY_ALLOWS[d.identityPolicy]?.includes(m)) throw new Error(`idMethod ${m} not allowed by ${d.identityPolicy}`);
  return tupleHash('legx/dealseal/v1', parts);
}

/** Domain on the deal wallet: 0x01 || contractRoot || dealSeal, 65 bytes (AccountSet Domain holds up to 256). */
export function domain(contractRoot: Uint8Array, seal: Uint8Array): Uint8Array {
  if (contractRoot.length !== 32 || seal.length !== 32) throw new Error('domain needs a 32-byte root and seal');
  return concatBytes(new Uint8Array([0x01]), contractRoot, seal);
}

// ---------- RFC 9162 Merkle tree hash ----------
const leafHash = (d: Uint8Array) => sha256(concatBytes(new Uint8Array([0]), d));
const nodeHash = (l: Uint8Array, r: Uint8Array) => sha256(concatBytes(new Uint8Array([1]), l, r));
const split = (n: number) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
export function mth(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) return sha256(new Uint8Array());
  if (leaves.length === 1) return leafHash(leaves[0]!);
  const k = split(leaves.length);
  return nodeHash(mth(leaves.slice(0, k)), mth(leaves.slice(k)));
}
export function inclusionPath(m: number, leaves: Uint8Array[]): Uint8Array[] {
  const n = leaves.length;
  if (n <= 1) return [];
  const k = split(n);
  return m < k ? [...inclusionPath(m, leaves.slice(0, k)), mth(leaves.slice(k))]
               : [...inclusionPath(m - k, leaves.slice(k)), mth(leaves.slice(0, k))];
}
export function verifyInclusion(leaf: Uint8Array, index: number, size: number, path: Uint8Array[], root: Uint8Array): boolean {
  // RFC 9162 section 2.1.3.2
  if (index >= size) return false;
  let fn = index, sn = size - 1, r = leafHash(leaf);
  for (const p of path) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      r = nodeHash(p, r);
      if ((fn & 1) === 0) { while ((fn & 1) === 0 && fn !== 0) { fn >>= 1; sn >>= 1; } }
    } else { r = nodeHash(r, p); }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && bytesToHex(r) === bytesToHex(root);
}

export { bytesToHex, hexToBytes, randomBytes, sha256, utf8ToBytes };
