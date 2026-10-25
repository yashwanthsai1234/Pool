import { sha1 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes } from '@noble/hashes/utils.js';
import { RSAPublicKey } from '@peculiar/asn1-rsa';
import { AsnConvert } from '@peculiar/asn1-schema';
import { AlgorithmIdentifier, SubjectPublicKeyInfo } from '@peculiar/asn1-x509';
import { deriveBytes, type Seed } from './seed.ts';

/** An RSA private key with its CRT parts. Fixture use only: generated from a seed, never from real randomness. */
export interface RsaKey {
  n: bigint;
  e: bigint;
  d: bigint;
  p: bigint;
  q: bigint;
  bits: number;
}

export const bytesToInt = (b: Uint8Array): bigint =>
  b.length === 0 ? 0n : BigInt(`0x${Buffer.from(b).toString('hex')}`);

export function intToBytes(x: bigint, length: number): Uint8Array<ArrayBuffer> {
  const hex = x.toString(16).padStart(length * 2, '0');
  if (hex.length > length * 2) throw new RangeError(`integer does not fit in ${length} bytes`);
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let r = 1n;
  let b = base % mod;
  for (let e = exp; e > 0n; e >>= 1n) {
    if (e & 1n) r = (r * b) % mod;
    b = (b * b) % mod;
  }
  return r;
}

function modInv(a: bigint, m: bigint): bigint {
  let [r0, r1, s0, s1] = [a % m, m, 1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1, s0, s1] = [r1, r0 - q * r1, s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new RangeError('not invertible');
  return ((s0 % m) + m) % m;
}

const SMALL_PRIMES: bigint[] = [];
for (let i = 3; i < 2000; i += 2) if (SMALL_PRIMES.every((p) => BigInt(i) % p !== 0n)) SMALL_PRIMES.push(BigInt(i));

/**
 * Miller-Rabin with fixed bases. The candidates come from a seed, not from an adversary, so fixed bases are enough
 * for fixtures (FIPS 186-5 B.3 asks for random bases when the candidate may be hostile).
 * Source: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf (Appendix B.3)
 */
function isProbablePrime(n: bigint): boolean {
  if (SMALL_PRIMES.some((p) => n % p === 0n)) return false;
  let d = n - 1n;
  let s = 0;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    s++;
  }
  outer: for (const a of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n]) {
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    for (let i = 1; i < s; i++) {
      x = (x * x) % n;
      if (x === n - 1n) continue outer;
    }
    return false;
  }
  return true;
}

/** A prime of exactly `bits` bits with the top two bits set (so p * q has exactly 2 * bits bits) and p mod e != 1. */
function primeFromSeed(seed: Seed, label: string, bits: number, e: bigint): bigint {
  const top = 3n << BigInt(bits - 2);
  let c = bytesToInt(deriveBytes(seed, label, bits / 8)) | top | 1n;
  while (!(c % e !== 1n && isProbablePrime(c))) c += 2n;
  if (c >> BigInt(bits) !== 0n) throw new RangeError('prime search overflowed; use another seed');
  return c;
}

/** A deterministic RSA key of `bits` bits (a multiple of 16) and e = 65537. */
export function rsaKeyFromSeed(seed: Seed, label: string, bits: number): RsaKey {
  const e = 65537n;
  const p = primeFromSeed(seed, `${label}/p`, bits / 2, e);
  const q = primeFromSeed(seed, `${label}/q`, bits / 2, e);
  const lambda = ((p - 1n) * (q - 1n)) / gcd(p - 1n, q - 1n);
  return { n: p * q, e, d: modInv(e, lambda), p, q, bits };
}

const gcd = (a: bigint, b: bigint): bigint => (b === 0n ? a : gcd(b, a % b));

/** Raw RSA private operation with the CRT. Source: https://www.rfc-editor.org/rfc/rfc8017#section-5.2.1 */
function rsaPrivate(k: RsaKey, m: bigint): Uint8Array<ArrayBuffer> {
  const m1 = modPow(m, k.d % (k.p - 1n), k.p);
  const m2 = modPow(m, k.d % (k.q - 1n), k.q);
  const h = (modInv(k.q, k.p) * (((m1 - m2) % k.p) + k.p)) % k.p;
  return intToBytes(m2 + h * k.q, k.bits / 8);
}

/** SubjectPublicKeyInfo with rsaEncryption (NULL parameters) and RSAPublicKey. */
export function rsaSpki(k: RsaKey): Uint8Array<ArrayBuffer> {
  const pub = new RSAPublicKey({
    modulus: intToBytes(k.n, k.bits / 8 + 1).buffer,
    publicExponent: intToBytes(k.e, 3).buffer,
  });
  return new Uint8Array(
    AsnConvert.serialize(
      new SubjectPublicKeyInfo({
        algorithm: new AlgorithmIdentifier({ algorithm: '1.2.840.113549.1.1.1', parameters: null }),
        subjectPublicKey: AsnConvert.serialize(pub),
      }),
    ),
  );
}

function mgf1(seed: Uint8Array, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0, off = 0; off < length; i++, off += 32) {
    out.set(sha256(concatBytes(seed, intToBytes(BigInt(i), 4))).subarray(0, length - off), off);
  }
  return out;
}

/**
 * RSASSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt given by the caller (deterministic fixtures).
 * Source: https://www.rfc-editor.org/rfc/rfc8017#section-9.1.1
 */
export function rsaPssSign(k: RsaKey, message: Uint8Array, salt: Uint8Array): Uint8Array<ArrayBuffer> {
  const emBits = k.bits - 1;
  const emLen = Math.ceil(emBits / 8);
  const h = sha256(concatBytes(new Uint8Array(8), sha256(message), salt));
  const db = new Uint8Array(emLen - 32 - 1);
  db[db.length - salt.length - 1] = 0x01;
  db.set(salt, db.length - salt.length);
  const mask = mgf1(h, db.length);
  for (let i = 0; i < db.length; i++) db[i] = (db[i] ?? 0) ^ (mask[i] ?? 0);
  db[0] = (db[0] ?? 0) & (0xff >> (8 * emLen - emBits));
  return rsaPrivate(k, bytesToInt(concatBytes(db, h, new Uint8Array([0xbc]))));
}

const AA_HASH = {
  'SHA-1': { fn: sha1, trailer: [0xbc] },
  'SHA-256': { fn: sha256, trailer: [0x34, 0xcc] },
} as const;
export type AaRsaHash = keyof typeof AA_HASH;

/**
 * ISO/IEC 9796-2 digital signature scheme 1 with partial message recovery, as an eMRTD chip computes it for Active
 * Authentication: F = 6A || M1 || H(M1 || M2) || trailer, sigma = F^d mod n. M1 must be exactly c - 4 bits long,
 * with c = k - Lh - 8t - 4 (ICAO 9303 Part 11, 6.1.2.2). The layout follows BouncyCastle's ISO9796d2Signer.
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p11_cons_en.pdf (6.1.2.2, Appendix F)
 * Source: https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/crypto/signers/ISO9796d2Signer.java
 */
export function iso9796d2Sign(k: RsaKey, m1: Uint8Array, m2: Uint8Array, hash: AaRsaHash): Uint8Array<ArrayBuffer> {
  const { fn, trailer } = AA_HASH[hash];
  const m1Len = k.bits / 8 - 1 - fn.outputLen - trailer.length;
  if (m1.length !== m1Len) throw new RangeError(`M1 must be ${m1Len} bytes for this key and hash`);
  const f = concatBytes(new Uint8Array([0x6a]), m1, fn(concatBytes(m1, m2)), new Uint8Array(trailer));
  return rsaPrivate(k, bytesToInt(f));
}
