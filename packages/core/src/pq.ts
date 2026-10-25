// Post-quantum primitives (DESIGN 6.13): the ML-DSA context wrapper, the KMS mu helper, the 2-of-3 post-quantum
// binding of a slot, and X-Wing HPKE packages with a suite tag.
//
// Honest limit (DESIGN 6.13, O17): the post-quantum binding proves which holders consented if Ed25519 is broken later.
// It does NOT protect the money: the ledger accepts only Ed25519 and secp256k1 today, so a quantum attacker who can
// break Ed25519 can move the funds until the ledger migrates. Evidence made and anchored before such a break stays
// trustworthy.
//
// @noble/post-quantum is not audited and not constant-time: browser and tests only. Servers sign with Node's built-in
// ML-DSA or KMS (task 3.12) and use `muFor` for KMS EXTERNAL_MU.

import { Aes256Gcm, CipherSuite, HkdfSha256 } from '@hpke/core';
import { XWing } from '@hpke/hybridkem-x-wing';
import type { HybridSignature, MlDsaContext, SignerPort } from '@legx/contracts/ports';
import type { KeyId } from '@legx/contracts/values';
import { shake256 } from '@noble/hashes/sha3.js';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ml_dsa44, ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { tupleHash } from './dealcore.ts';

/** The empty ML-DSA context of the C2SP 0x06 checkpoint cosignature (only `pqCheckpoint.ts` uses it, P1.16-13). */
export const C2SP_0X06_CONTEXT = '';
type AnyContext = MlDsaContext | typeof C2SP_0X06_CONTEXT;

const ALGS = { 'ml-dsa-65': ml_dsa65, 'ml-dsa-44': ml_dsa44 } as const;
const MLDSA65_PUBLIC_KEY = 1952; // FIPS 204 table 2
type MlDsaAlg = keyof typeof ALGS;

// ---------- Canonical base64 (RFC 4648 section 4, with padding), for envelopes and signed notes ----------
// Source: https://www.rfc-editor.org/rfc/rfc4648#section-3.5 (canonical encoding); https://c2sp.org/signed-note
// (decoders MUST reject non-canonical encodings). btoa and atob exist in browsers and in Node.

export function toBase64(b: Uint8Array): string {
  let bin = '';
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin);
}

/** Decodes only the canonical encoding (the one `toBase64` makes); anything else gives `undefined`. */
export function fromBase64Strict(s: string): Uint8Array | undefined {
  // After this check atob cannot throw: only the alphabet, at most two '=' at the end, and a length that is a multiple of 4.
  if (s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return undefined;
  const out = Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  return toBase64(out) === s ? out : undefined;
}

// ---------- The context wrapper: every ML-DSA sign and verify in core goes through these two (P1.16-15) ----------
// There is no default context. Node and noble both default to the EMPTY context, so a forgotten option would sign
// something any other use accepts. Source: https://csrc.nist.gov/pubs/fips/204/final (Algorithms 2 and 3, ctx)

/** Signs `msg` under `ctx` (hedged, FIPS 204 default). Throws on a malformed secret key: signing is not a verifier. */
export function mldsaSign(alg: MlDsaAlg, secretKey: Uint8Array, msg: Uint8Array, ctx: AnyContext): Uint8Array {
  return ALGS[alg].sign(msg, secretKey, { context: utf8ToBytes(ctx) });
}

/** Verifies under exactly `ctx`. Wrong lengths or a malformed key give `false`; it never throws. */
export function mldsaVerify(
  alg: MlDsaAlg,
  publicKey: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array,
  ctx: AnyContext,
): boolean {
  const a = ALGS[alg];
  if (publicKey.length !== a.lengths.publicKey || sig.length !== a.lengths.signature) return false;
  try {
    return a.verify(sig, msg, publicKey, { context: utf8ToBytes(ctx) });
  } catch {
    return false;
  }
}

/** An ML-DSA-65 enrollment key pair from a 32-byte seed (FIPS 204 ML-DSA.KeyGen_internal), or a random one. */
export function pqKeygen(seed?: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array } {
  return ml_dsa65.keygen(seed);
}

/** An ML-DSA-65 signer that names its key by key ID. In core the only one is noble (browser and tests). */
export interface MlDsaSigner {
  readonly keyId: string;
  sign(msg: Uint8Array, ctx: MlDsaContext): Promise<Uint8Array>;
}

export function nobleMlDsaSigner(keyId: string, secretKey: Uint8Array): MlDsaSigner {
  return { keyId, sign: async (msg, ctx) => mldsaSign('ml-dsa-65', secretKey, msg, ctx) };
}

/** A hybrid `SignerPort` (contracts) from an Ed25519 signer and a noble ML-DSA-65 key: for browsers and tests. */
export function nobleHybridSigner(
  ed: { keyId: KeyId; publicKey: Uint8Array; sign(msg: Uint8Array): Promise<Uint8Array> },
  pq: { keyId: KeyId; secretKey: Uint8Array },
): SignerPort {
  const keyIds = { ed25519: ed.keyId, mlDsa65: pq.keyId };
  const mlDsa65 = ml_dsa65.getPublicKey(pq.secretKey);
  return {
    async signHybrid(msg, ctx): Promise<HybridSignature> {
      const [edSig, pqSig] = await Promise.all([ed.sign(msg), mldsaSign('ml-dsa-65', pq.secretKey, msg, ctx)]);
      return { ed25519: edSig, mlDsa65: pqSig, keyIds };
    },
    publicKeys: async () => ({ ed25519: ed.publicKey, mlDsa65, keyIds }),
  };
}

// ---------- mu for KMS EXTERNAL_MU ----------

/**
 * mu = SHAKE256(tr || 0x00 || len(ctx) || ctx || msg, 64) with tr = SHAKE256(pk, 64): the pure (not pre-hash) ML-DSA
 * message representative. KMS signs mu (EXTERNAL_MU) and the result is an ordinary signature over `msg` under `ctx`.
 * Source: https://csrc.nist.gov/pubs/fips/204/final (Algorithm 2 line 10, Algorithm 7 lines 1 and 6)
 * Source: https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html (MessageType EXTERNAL_MU)
 */
export function muFor(publicKey: Uint8Array, ctx: MlDsaContext, msg: Uint8Array): Uint8Array {
  if (publicKey.length !== MLDSA65_PUBLIC_KEY) throw new Error('muFor: ML-DSA-65 public key must be 1952 bytes');
  const c = utf8ToBytes(ctx);
  const tr = shake256(publicKey, { dkLen: 64 });
  return shake256(concatBytes(tr, Uint8Array.of(0, c.length), c, msg), { dkLen: 64 });
}

// ---------- The 2-of-3 post-quantum binding of a slot ----------

const need = (b: Uint8Array, n: number, what: string) => {
  if (b.length !== n) throw new Error(`${what} must be ${n} bytes`);
};

/**
 * pqKeyHash_slot = tupleHash("legx/pq-keyset/v1", [pqPub_1, pqPub_2, pqPub_3]): the three holder ML-DSA-65 keys (raw
 * FIPS 204 encoding) in role order. It goes into the deal seal. Source: DESIGN 6 encoding rules and 6.13.
 */
export function pqKeyHash(pubs: readonly [Uint8Array, Uint8Array, Uint8Array]): Uint8Array {
  for (const p of pubs) need(p, MLDSA65_PUBLIC_KEY, 'ML-DSA-65 public key');
  return tupleHash('legx/pq-keyset/v1', [...pubs]);
}

/** pqBindMsg = tupleHash("legx/pq-binding/v1", [dealSeal, slotPub, pqKeyHash_slot]), slotPub in the 33-byte XRPL form. */
export function pqBindMsg(dealSeal: Uint8Array, slotPub: Uint8Array, keyHash: Uint8Array): Uint8Array {
  need(dealSeal, 32, 'dealSeal');
  need(slotPub, 33, 'slotPub');
  need(keyHash, 32, 'pqKeyHash');
  return tupleHash('legx/pq-binding/v1', [dealSeal, slotPub, keyHash]);
}

export interface HolderSig {
  readonly keyId: string;
  readonly sig: Uint8Array;
}
export interface HolderKey {
  readonly keyId: string;
  readonly mlDsa65: Uint8Array;
}

/** One holder's ML-DSA-65 signature over pqBindMsg, under the context `legx/pq-binding/v1`. */
export async function signPqBinding(msg: Uint8Array, signer: MlDsaSigner): Promise<HolderSig> {
  return { keyId: signer.keyId, sig: await signer.sign(msg, 'legx/pq-binding/v1') };
}

export interface PqBindingInput {
  readonly dealSeal: Uint8Array;
  readonly slotPub: Uint8Array;
  readonly pqKeyHash: Uint8Array;
  readonly holderSigs: readonly HolderSig[];
  readonly crossSig?: Uint8Array;
}
export type PqBindingCode =
  | 'MALFORMED'
  | 'SEAL_MISMATCH'
  | 'SLOT_PUB_MISMATCH'
  | 'PQ_KEY_HASH_MISMATCH'
  | 'BELOW_TWO_HOLDERS'
  | 'TOO_MANY_HOLDERS'
  | 'DUPLICATE_HOLDER'
  | 'HOLDER_KEY_UNKNOWN'
  | 'HOLDER_SIG_INVALID'
  | 'CROSS_SIG_MISSING'
  | 'CROSS_SIG_INVALID';
export type PqResult<C extends string> = { readonly ok: true } | { readonly ok: false; readonly code: C };

const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * Two distinct holders of the slot's three signed pqBindMsg, and the slot's Ed25519 group key cross-signed it.
 * `expected` holds the sealed values. `verifySlotSig` checks the cross-signature (a FROST aggregate is a standard
 * Ed25519 signature; the caller passes a strict verifier, so core does not depend on the FROST module).
 */
export function verifyPqBinding(
  b: PqBindingInput,
  expected: { readonly dealSeal: Uint8Array; readonly slotPub: Uint8Array; readonly pqKeyHash: Uint8Array },
  holders: readonly [HolderKey, HolderKey, HolderKey],
  verifySlotSig: (slotPub: Uint8Array, msg: Uint8Array, sig: Uint8Array) => boolean,
): PqResult<PqBindingCode> {
  const fail = (code: PqBindingCode) => ({ ok: false, code }) as const;
  let msg: Uint8Array;
  let keyHash: Uint8Array;
  try {
    keyHash = pqKeyHash([holders[0].mlDsa65, holders[1].mlDsa65, holders[2].mlDsa65]);
    msg = pqBindMsg(b.dealSeal, b.slotPub, b.pqKeyHash);
  } catch {
    return fail('MALFORMED');
  }
  if (!same(b.dealSeal, expected.dealSeal)) return fail('SEAL_MISMATCH');
  if (!same(b.slotPub, expected.slotPub)) return fail('SLOT_PUB_MISMATCH');
  if (!same(b.pqKeyHash, expected.pqKeyHash) || !same(keyHash, expected.pqKeyHash)) return fail('PQ_KEY_HASH_MISMATCH');
  if (b.holderSigs.length < 2) return fail('BELOW_TWO_HOLDERS');
  if (b.holderSigs.length > 2) return fail('TOO_MANY_HOLDERS');
  if (b.holderSigs[0]?.keyId === b.holderSigs[1]?.keyId) return fail('DUPLICATE_HOLDER');
  for (const s of b.holderSigs) {
    const h = holders.find((k) => k.keyId === s.keyId);
    if (!h) return fail('HOLDER_KEY_UNKNOWN');
    if (!mldsaVerify('ml-dsa-65', h.mlDsa65, msg, s.sig, 'legx/pq-binding/v1')) return fail('HOLDER_SIG_INVALID');
  }
  if (!b.crossSig) return fail('CROSS_SIG_MISSING');
  let crossOk = false;
  try {
    crossOk = verifySlotSig(b.slotPub, msg, b.crossSig);
  } catch {
    // a throwing verifier counts as a failed signature
  }
  return crossOk ? { ok: true } : fail('CROSS_SIG_INVALID');
}

// ---------- X-Wing HPKE packages (backups and share transport) ----------
// Source: https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/ (draft-11, section 5.6 "Use in HPKE",
// KEM ID 0x647a); https://www.rfc-editor.org/rfc/rfc9180.html (single-shot Seal and Open, mode_base)

/** The `info` of each package kind, fixed in code: a backup never opens as a share-transport package. */
// zk-salt and zk-disclosure: the identity-salt and identity-disclosure boxes, sealed to the client's own lawyer
// (DESIGN 6.2, 6.10; task 1.17).
const PACKAGE_INFO = {
  backup: 'legx/hpke/backup/v1',
  share: 'legx/hpke/share/v1',
  'zk-salt': 'legx/hpke/zk-salt/v1',
  'zk-disclosure': 'legx/hpke/zk-disclosure/v1',
  // OD-28: the old lawyer B hands the release code to the new lawyer B (logged as `release_code.handed_over`).
  'release-code-handover': 'legx/hpke/release-code-handover/v1',
  // The chip-link transfer to the console's one-time QR key (DESIGN 6.15; task 4.6 kept this info string).
  'chip-link': 'legx/chip-link/v1',
} as const;
export type PackageKind = keyof typeof PACKAGE_INFO;

/** X-Wing is a draft, so every package names its suite: a swap is a data change, not a code change. */
export const XWING_SUITE = 'hpke-xwing-v1';

export interface SealedPackage {
  readonly suite: string;
  readonly enc: Uint8Array;
  readonly ct: Uint8Array;
}

export interface PackageSuite {
  keygen(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }>;
  seal(pk: Uint8Array, pt: Uint8Array, info: Uint8Array, aad: Uint8Array): Promise<{ enc: Uint8Array; ct: Uint8Array }>;
  open(sk: Uint8Array, enc: Uint8Array, ct: Uint8Array, info: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
}

/** An RFC 9180 suite from `@hpke/core` parts (the AEAD and KDF instances must be passed in). */
export function hpkeSuite(suite: CipherSuite): PackageSuite {
  const kem = suite.kem;
  return {
    async keygen() {
      const kp = await kem.generateKeyPair();
      return {
        publicKey: new Uint8Array(await kem.serializePublicKey(kp.publicKey)),
        secretKey: new Uint8Array(await kem.serializePrivateKey(kp.privateKey)),
      };
    },
    async seal(pk, pt, info, aad) {
      const recipientPublicKey = await kem.deserializePublicKey(pk);
      const r = await suite.seal({ recipientPublicKey, info }, pt, aad);
      return { enc: new Uint8Array(r.enc), ct: new Uint8Array(r.ct) };
    },
    async open(sk, enc, ct, info, aad) {
      const recipientKey = await kem.deserializePrivateKey(sk);
      return new Uint8Array(await suite.open({ recipientKey, enc, info }, ct, aad));
    },
  };
}

/** The suites this build knows. A test may pass a larger table to `openPackage` to show a suite swap (P1.16-07). */
export const PACKAGE_SUITES: Readonly<Record<string, PackageSuite>> = {
  [XWING_SUITE]: hpkeSuite(new CipherSuite({ kem: new XWing(), kdf: new HkdfSha256(), aead: new Aes256Gcm() })),
};

export async function sealPackage(
  kind: PackageKind,
  recipientPublicKey: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
  suite: string = XWING_SUITE,
  suites: Readonly<Record<string, PackageSuite>> = PACKAGE_SUITES,
): Promise<SealedPackage> {
  const s = suites[suite];
  if (!s) throw new Error('SUITE_UNKNOWN');
  return { suite, ...(await s.seal(recipientPublicKey, plaintext, utf8ToBytes(PACKAGE_INFO[kind]), aad)) };
}

export type OpenResult =
  | { readonly ok: true; readonly plaintext: Uint8Array }
  | { readonly ok: false; readonly code: 'SUITE_UNKNOWN' | 'OPEN_FAILED' };

/** Opens a package, or fails as a whole: a tampered key, ciphertext, tag or associated data gives no output. */
export async function openPackage(
  kind: PackageKind,
  pkg: SealedPackage,
  recipientSecretKey: Uint8Array,
  aad: Uint8Array,
  suites: Readonly<Record<string, PackageSuite>> = PACKAGE_SUITES,
): Promise<OpenResult> {
  const s = Object.hasOwn(suites, pkg.suite) ? suites[pkg.suite] : undefined;
  if (!s) return { ok: false, code: 'SUITE_UNKNOWN' };
  try {
    return {
      ok: true,
      plaintext: await s.open(recipientSecretKey, pkg.enc, pkg.ct, utf8ToBytes(PACKAGE_INFO[kind]), aad),
    };
  } catch {
    return { ok: false, code: 'OPEN_FAILED' };
  }
}
