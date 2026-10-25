// Active Authentication (ICAO 9303 Part 11, 6.1) for the chip path (DESIGN 6.15). The lawyer's console sends the chip
// an 8-byte challenge taken from presenceMsg, so the answer is bound to this deal, side, ledger and lawyer nonce; a
// relayed chip cannot answer for another session. Pure and synchronous; never throws on chip data.
import { sha1 } from '@noble/hashes/legacy.js';
import { sha224, sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { berExact, ecKeyOf, type Hash, nobleEcdsaVerify, unwrapTag } from './sod.ts';

/**
 * The AA challenge (RND.IFD): the first 8 bytes of presenceMsg (DESIGN 6.15). Part 11 6.1.2.1: "RND.IFD MUST be 8
 * bytes". Throws a RangeError if `presenceMsg` is not the 32-byte tuple hash.
 */
export function aaChallenge(presenceMsg: Uint8Array): Uint8Array {
  if (presenceMsg.length !== 32) throw new RangeError('presenceMsg must be 32 bytes');
  return presenceMsg.slice(0, 8);
}

export type AaCode =
  | 'CHALLENGE_LENGTH'
  | 'DG15_MALFORMED'
  | 'DG14_AA_INFO_MISSING'
  | 'AA_ALGORITHM_UNSUPPORTED'
  | 'CHIP_AUTH_INVALID';
export type AaResult =
  | { readonly ok: true; readonly alg: 'rsa' | 'ecdsa' }
  | { readonly ok: false; readonly code: AaCode };

export interface AaInput {
  /** EF.DG15 as read: 6F L SubjectPublicKeyInfo. */
  readonly dg15: Uint8Array;
  /** EF.DG14 as read; required for an EC key, because it names the hash (Part 11 9.2.4). */
  readonly dg14?: Uint8Array;
  readonly challenge: Uint8Array;
  /** The chip's answer to INTERNAL AUTHENTICATE. */
  readonly signature: Uint8Array;
}

/**
 * Verifies the chip's INTERNAL AUTHENTICATE answer against the DG15 key. The caller must already have checked DG15's
 * hash in the SOD (passive authentication), or the key proves nothing.
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p11_cons_en.pdf (6.1.2.2 RSA, 6.1.2.3 ECDSA)
 */
export function verifyActiveAuth({ dg15, dg14, challenge, signature }: AaInput): AaResult {
  if (challenge.length !== 8) return { ok: false, code: 'CHALLENGE_LENGTH' };
  const spki = parseSpki(dg15);
  if (!spki) return { ok: false, code: 'DG15_MALFORMED' };
  const fail = (code: AaCode) => ({ ok: false, code }) as const;
  if (spki.algorithm.algorithmId === '1.2.840.113549.1.1.1') {
    const key = rsaKeyOf(spki);
    if (!key) return fail('DG15_MALFORMED');
    return rsaAaVerify(key, challenge, signature) ? { ok: true, alg: 'rsa' } : fail('CHIP_AUTH_INVALID');
  }
  const ec = ecKeyOf(spki);
  if (!ec) return fail('AA_ALGORITHM_UNSUPPORTED');
  const hash = dg14 === undefined ? undefined : aaHashFromDg14(dg14);
  if (hash === undefined) return fail('DG14_AA_INFO_MISSING');
  if (hash === 'refused') return fail('AA_ALGORITHM_UNSUPPORTED');
  return nobleEcdsaVerify(ec, hash(challenge), signature, 'compact')
    ? { ok: true, alg: 'ecdsa' }
    : fail('CHIP_AUTH_INVALID');
}

function parseSpki(dg15: Uint8Array): pkijs.PublicKeyInfo | undefined {
  const inner = unwrapTag(dg15, [0x6f]);
  const asn = inner && berExact(inner);
  if (!asn) return undefined;
  try {
    return new pkijs.PublicKeyInfo({ schema: asn });
  } catch {
    return undefined;
  }
}

function rsaKeyOf(spki: pkijs.PublicKeyInfo): { n: bigint; e: bigint; len: number } | undefined {
  try {
    const key = pkijs.RSAPublicKey.fromBER(new Uint8Array(spki.subjectPublicKey.valueBlock.valueHexView));
    const hex = (i: asn1js.Integer) => bytesToHex(i.valueBlock.valueHexView);
    const n = BigInt(`0x${hex(key.modulus)}`);
    const e = BigInt(`0x${hex(key.publicExponent)}`);
    // Part 11 Appendix F uses 1024 bits; anything under 1024 is not a real chip key.
    return n.toString(2).length >= 1024 && e > 1n ? { n, e, len: Math.ceil(n.toString(2).length / 8) } : undefined;
  } catch {
    return undefined;
  }
}

const ID_AA = '2.23.136.1.1.5';
/** ecdsa-plain-SHA* (BSI TR-03111 5.2.1). SHA-1 (…4.1.1) and RIPEMD-160 (…4.1.6) are refused by Part 11 6.1.2.3. */
const PLAIN_ECDSA_HASH: Readonly<Record<string, Hash>> = {
  '0.4.0.127.0.7.1.1.4.1.2': sha224,
  '0.4.0.127.0.7.1.1.4.1.3': sha256,
  '0.4.0.127.0.7.1.1.4.1.4': sha384,
  '0.4.0.127.0.7.1.1.4.1.5': sha512,
};

/**
 * The hash named by DG14's ActiveAuthenticationInfo { protocol id-icao-mrtd-security-aaProtocolObject, version 1,
 * signatureAlgorithm }; 'refused' for an algorithm Part 11 does not allow, undefined if there is no such entry.
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p11_cons_en.pdf (9.2, 9.2.4)
 */
function aaHashFromDg14(dg14: Uint8Array): Hash | 'refused' | undefined {
  const inner = unwrapTag(dg14, [0x6e]);
  const set = inner && berExact(inner);
  if (!(set instanceof asn1js.Set)) return undefined;
  for (const info of set.valueBlock.value) {
    const [protocol, version, alg] = info instanceof asn1js.Sequence ? info.valueBlock.value : [];
    if (!(protocol instanceof asn1js.ObjectIdentifier) || protocol.valueBlock.toString() !== ID_AA) continue;
    if (!(version instanceof asn1js.Integer && version.valueBlock.valueDec === 1)) return undefined;
    if (!(alg instanceof asn1js.ObjectIdentifier)) return undefined;
    return PLAIN_ECDSA_HASH[alg.valueBlock.toString()] ?? 'refused';
  }
  return undefined;
}

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let r = 1n;
  let b = base % m;
  for (let e = exp; e > 0n; e >>= 1n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
  }
  return r;
}

/**
 * RSA Active Authentication: J = sigma^e mod n; if J does not end in the nibble C, use n - J (ISO/IEC 9796-2, the
 * recovery step that makes min(sigma, n - sigma) signatures verify); then check the representative.
 * Source: https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/crypto/signers/ISO9796d2Signer.java (verifySignature)
 */
function rsaAaVerify(key: { n: bigint; e: bigint; len: number }, m2: Uint8Array, signature: Uint8Array): boolean {
  if (signature.length !== key.len) return false;
  const s = BigInt(`0x${bytesToHex(signature) || '0'}`);
  if (s === 0n || s >= key.n) return false;
  let j = modPow(s, key.e, key.n);
  if ((j & 0xfn) !== 0xcn) j = key.n - j;
  const hex = j.toString(16);
  if (hex.length > key.len * 2) return false;
  return iso9796d2Recovers(hexToBytes(hex.padStart(key.len * 2, '0')), m2);
}

/** Part 11 6.1.2.2: trailer option 1 (BC) for SHA-1 only, option 2 (xxCC) for the SHA-2 family. */
const TRAILERS: readonly { trailer: readonly number[]; hash: Hash }[] = [
  { trailer: [0xbc], hash: sha1 },
  { trailer: [0x38, 0xcc], hash: sha224 },
  { trailer: [0x34, 0xcc], hash: sha256 },
  { trailer: [0x36, 0xcc], hash: sha384 },
  { trailer: [0x35, 0xcc], hash: sha512 },
];

/**
 * Checks an ISO/IEC 9796-2 scheme 1 message representative F = header || M1 || H(M1 || M2) || trailer with partial
 * recovery, where M2 (the challenge) is not in F. The header's first two bits are 01 and its third bit is 1 (partial
 * recovery); padding nibbles B end with the nibble A, after which M1 starts. The trailer names the hash.
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p11_cons_en.pdf (6.1.2.2, Appendix F steps 12 to 18)
 * Source: https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/crypto/signers/ISO9796d2Signer.java (verifySignature, header and padding)
 * Source: https://www.iso.org/standard/54788.html (ISO/IEC 9796-2:2010, digital signature scheme 1)
 */
export function iso9796d2Recovers(f: Uint8Array, m2: Uint8Array): boolean {
  const head = f[0] ?? 0;
  if ((head & 0xc0) !== 0x40 || (head & 0x20) === 0) return false;
  const t = TRAILERS.find(({ trailer }) => trailer.every((b, i) => f[f.length - trailer.length + i] === b));
  if (!t) return false;
  // The padding: the nibble after the header bits is B (padding) or A (the border); M1 starts after the A.
  let start = 0;
  while (start < f.length && ((f[start] ?? 0) & 0x0f) !== 0x0a) {
    if (start > 0 && f[start] !== 0xbb) return false;
    start++;
  }
  start++;
  const end = f.length - t.trailer.length - t.hash.outputLen;
  if (end <= start) return false;
  const m1 = f.subarray(start, end);
  const d = f.subarray(end, f.length - t.trailer.length);
  const dStar = t.hash(Uint8Array.from([...m1, ...m2]));
  let diff = 0;
  for (let i = 0; i < d.length; i++) diff |= (d[i] ?? 0) ^ (dStar[i] ?? 0);
  return diff === 0;
}
