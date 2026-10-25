// Hybrid DSSE envelopes (DESIGN 6.13, 8.1): two independent signatures, Ed25519 then ML-DSA-65 (context
// `legx/dsse/v1`), over the same PAE bytes. No composite format: DSSE allows several signatures, and each one stays
// verifiable by standard tools. Both are required. The required algorithms come from SIG_POLICY (per record type and
// format version, in code); the `sig_algs` list inside the signed payload is only a second check, so stripping one
// signature and rewriting the list breaks the other signature.
// Source: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md (v1.0.2, PAE, multiple signatures)
// Source: https://csrc.nist.gov/pubs/fips/204/final (ML-DSA with a context string)
import type { MlDsaContext, SignerPort } from '@legx/contracts/ports';
import { ed25519 } from '@noble/curves/ed25519.js';
import { type Envelope, pae } from './evidence.ts';
import { fromBase64Strict, mldsaVerify, toBase64 } from './pq.ts';

export const DSSE_CONTEXT = 'legx/dsse/v1' satisfies MlDsaContext;

export type SigAlg = 'ed25519' | 'ml-dsa-65';
/** The only algorithm list a policy can hold. A classical-only policy does not type-check. */
export type HybridAlgs = readonly ['ed25519', 'ml-dsa-65'];
const HYBRID: HybridAlgs = ['ed25519', 'ml-dsa-65'];

export interface SigPolicy {
  readonly algs: HybridAlgs;
  /** Where this record type keeps `sig_algs` in its payload. */
  sigAlgsOf(payload: unknown): unknown;
}

const field = (x: unknown, k: string): unknown =>
  typeof x === 'object' && x !== null && Object.hasOwn(x, k) ? (x as Record<string, unknown>)[k] : undefined;

/** Required algorithms per payload type (record type and format version). Events keep `sig_algs` in the predicate. */
export const SIG_POLICY = {
  'application/vnd.legx.event+json;v=1': { algs: HYBRID, sigAlgsOf: (p) => field(field(p, 'predicate'), 'sig_algs') },
  'application/vnd.legx.attest+json;v=1': { algs: HYBRID, sigAlgsOf: (p) => field(p, 'sig_algs') },
} as const satisfies Record<string, SigPolicy>;
export type RecordType = keyof typeof SIG_POLICY;

/** One row of the append-only key registry (`enrollment_key`, DESIGN 6.3, 9), as the verifier needs it. */
export interface RegisteredKey {
  readonly alg: SigAlg;
  readonly publicKey: Uint8Array; // raw: 32 bytes (Ed25519) or 1,952 bytes (ML-DSA-65)
  readonly validFrom: number; // Ripple epoch seconds
  readonly validTo?: number;
  /** The key's hash is in the evidence log, so in a ledger checkpoint (DESIGN 6.3). */
  readonly logged: boolean;
  /**
   * The holder's enrollment key pair this key belongs to: one `enrollment_key` row holds both keys (DESIGN 6.3, 9),
   * so its key_id names the pair. Both halves of an envelope must come from one pair (I-S-P1).
   */
  readonly pair: string;
}
export type KeyRegistry = (keyId: string) => RegisteredKey | undefined;

export type HybridCode =
  | 'MALFORMED'
  | 'PAYLOAD_TYPE_UNKNOWN'
  | 'KEY_UNKNOWN'
  | 'DUPLICATE_SIGNATURE'
  | 'ED_SIGNATURE_MISSING'
  | 'PQ_SIGNATURE_MISSING'
  | 'SIGNATURE_ORDER'
  | 'PAIR_MISMATCH'
  | 'KEY_EXPIRED'
  | 'KEY_NOT_LOGGED'
  | 'SIG_ALGS_MISMATCH'
  | 'ED_SIGNATURE_INVALID'
  | 'PQ_SIGNATURE_INVALID';
export type HybridResult =
  | { readonly ok: true; readonly payload: Uint8Array; readonly keyIds: { ed25519: string; mlDsa65: string } }
  | { readonly ok: false; readonly code: HybridCode };

function parsePayload(body: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
  } catch {
    return undefined;
  }
}
const sigAlgsMatch = (policy: SigPolicy, payload: unknown): boolean => {
  const listed = policy.sigAlgsOf(payload);
  return Array.isArray(listed) && listed.length === policy.algs.length && listed.every((a, i) => a === policy.algs[i]);
};

/** Signs with both keys through one `SignerPort` call. Refuses a payload whose `sig_algs` differs from the table. */
export async function signHybrid(payloadType: RecordType, body: Uint8Array, signer: SignerPort): Promise<Envelope> {
  if (!sigAlgsMatch(SIG_POLICY[payloadType], parsePayload(body))) throw new Error('SIG_ALGS_MISMATCH');
  const h = await signer.signHybrid(pae(payloadType, body), DSSE_CONTEXT);
  return {
    payloadType,
    payload: toBase64(body),
    signatures: [
      { keyid: h.keyIds.ed25519, sig: toBase64(h.ed25519) },
      { keyid: h.keyIds.mlDsa65, sig: toBase64(h.mlDsa65) },
    ],
  };
}

/**
 * Verifies a hybrid envelope at `at`, the validated ledger close_time the caller trusts for this record. Returns a
 * typed error and never throws. There is no classical-only mode.
 */
export function verifyHybrid(env: Envelope, registry: KeyRegistry, at: number): HybridResult {
  try {
    return check(env, registry, at);
  } catch {
    return { ok: false, code: 'MALFORMED' };
  }
}

function check(env: Envelope, registry: KeyRegistry, at: number): HybridResult {
  const fail = (code: HybridCode) => ({ ok: false, code }) as const;
  const { payloadType, payload, signatures } = (env ?? {}) as Partial<Envelope>;
  if (typeof payloadType !== 'string' || typeof payload !== 'string' || !Array.isArray(signatures))
    return fail('MALFORMED');
  if (!Object.hasOwn(SIG_POLICY, payloadType)) return fail('PAYLOAD_TYPE_UNKNOWN');
  const policy: SigPolicy = SIG_POLICY[payloadType as RecordType];

  const sigs: { keyid: string; key: RegisteredKey; sig: Uint8Array }[] = [];
  for (const s of signatures as unknown[]) {
    const keyid = field(s, 'keyid');
    const sig = field(s, 'sig');
    if (typeof keyid !== 'string' || typeof sig !== 'string') return fail('MALFORMED');
    const key = registry(keyid);
    if (!key) return fail('KEY_UNKNOWN');
    const bytes = fromBase64Strict(sig);
    if (!bytes) return fail('MALFORMED');
    sigs.push({ keyid, key, sig: bytes });
  }
  // One valid signature of each required algorithm, in the table's order, and nothing else.
  const count = (alg: SigAlg) => sigs.filter((s) => s.key.alg === alg).length;
  if (policy.algs.some((a) => count(a) > 1)) return fail('DUPLICATE_SIGNATURE');
  if (count('ed25519') === 0) return fail('ED_SIGNATURE_MISSING');
  if (count('ml-dsa-65') === 0) return fail('PQ_SIGNATURE_MISSING');
  if (sigs.length !== policy.algs.length || sigs.some((s, i) => s.key.alg !== policy.algs[i])) {
    return fail('SIGNATURE_ORDER');
  }
  // Both halves from one holder's pair, or a classical forgery next to another holder's honest ML-DSA signature
  // would pass, and the post-quantum half would protect nothing (I-S-P1).
  // Source: https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/ (component keys bound as one key);
  // https://www.rfc-editor.org/rfc/rfc9794 (hybrid terminology)
  const [ed, pq] = sigs as [(typeof sigs)[0], (typeof sigs)[0]];
  if (typeof ed.key.pair !== 'string' || ed.key.pair === '' || ed.key.pair !== pq.key.pair) {
    return fail('PAIR_MISMATCH');
  }
  for (const { key } of sigs) {
    if (!(at >= key.validFrom && (key.validTo === undefined || at <= key.validTo))) return fail('KEY_EXPIRED');
    if (!key.logged) return fail('KEY_NOT_LOGGED');
  }

  const body = fromBase64Strict(payload);
  if (!body) return fail('MALFORMED');
  const parsed = parsePayload(body);
  if (parsed === undefined) return fail('MALFORMED');
  if (!sigAlgsMatch(policy, parsed)) return fail('SIG_ALGS_MISMATCH');

  const m = pae(payloadType, body);
  // Strict RFC 8032 verification (zip215: false), a hard rule (IMPLEMENTATION 1.3).
  const edOk =
    ed.sig.length === 64 &&
    ed.key.publicKey.length === 32 &&
    ed25519.verify(ed.sig, m, ed.key.publicKey, { zip215: false });
  if (!edOk) return fail('ED_SIGNATURE_INVALID');
  if (!mldsaVerify('ml-dsa-65', pq.key.publicKey, m, pq.sig, DSSE_CONTEXT)) return fail('PQ_SIGNATURE_INVALID');
  return { ok: true, payload: body, keyIds: { ed25519: ed.keyid, mlDsa65: pq.keyid } };
}
