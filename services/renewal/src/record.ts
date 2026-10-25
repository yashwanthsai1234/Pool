// The renewal record (DESIGN 8.4, 6.13): RFC 4998 style "timestamp renewal". Each record covers the evidence head
// (the latest checkpoint note) and the previous record, is signed with a fresh hybrid signature set (Ed25519 and ML-DSA-65,
// message `legx/renewal/v1`, context `legx/checkpoint/v1`), and is time-stamped by an RFC 3161 authority over a digest
// that includes the previous time stamp, so a renewal never replaces the old evidence, it wraps it:
//   RFC 4998 section 5.2: "the content of the timeStamp field of the old Archive Timestamp has to be hashed and timestamped".
// The statement chain (prevHash, checkpointHash, pqSig) is core's `renewalStatement`; this file adds the Ed25519 half, the
// time stamp, the stored form, and the offline verifier. Source: https://www.rfc-editor.org/rfc/rfc4998#section-5.2
// Source: https://www.rfc-editor.org/rfc/rfc3161 (the token covers the digest we send)
import type { MlDsaContext } from '@legx/contracts/ports';
import { tupleHash } from '@legx/core/dealcore';
import { mldsaVerify } from '@legx/core/pq';
import { renewalMsg, renewalStatement } from '@legx/core/pqCheckpoint';
import { verifyTimestampToken } from '@legx/evidence/tsa';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import canonicalize from 'canonicalize';
import { z } from 'zod';

/** The context of the ML-DSA-65 half of a renewal (core's `verifyRenewalChain` uses the same). */
export const RENEWAL_CONTEXT = 'legx/checkpoint/v1' satisfies MlDsaContext;
/** Tag of the digest that is time-stamped: the statement hash plus the hash of the previous time stamp token. */
export const TIMESTAMP_TAG = 'legx/renewal-timestamp/v1';

const ZERO = new Uint8Array(32);
const utf8 = new TextEncoder();
const strict = new TextDecoder('utf-8', { fatal: true });

const Hex32 = z.string().regex(/^[0-9a-f]{64}$/);
const B64 = z.string().regex(/^[A-Za-z0-9+/]+={0,2}$/);

export const RenewalRecord = z.strictObject({
  v: z.literal(1),
  seq: z.int().min(0),
  period: z.string().min(1).max(64),
  prev_hash: Hex32,
  checkpoint: z.string().min(1).max(4096), // the signed checkpoint note being renewed, verbatim
  statement_hash: Hex32,
  keys: z.strictObject({ ed25519: z.string().min(1), ml_dsa_65: z.string().min(1) }),
  sig: z.strictObject({ ed25519: B64, ml_dsa_65: B64 }),
  tsa: z.strictObject({ authority: z.string().min(1), token: B64 }),
});
export type RenewalRecord = z.infer<typeof RenewalRecord>;

export const renewalKey = (seq: number) => `renewals/${String(seq).padStart(16, '0')}`;

const unb64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));

/** Canonical JSON bytes: what goes to the WORM store. */
export const encodeRecord = (r: RenewalRecord): Uint8Array => utf8.encode(canonicalize(r) as string);

export function decodeRecord(bytes: Uint8Array): RenewalRecord {
  return RenewalRecord.parse(JSON.parse(strict.decode(bytes)));
}

/** The 32 bytes the authority time-stamps: binds this statement to the previous token (zeros for the first). */
export function timestampDigest(statementHash: Uint8Array, prevToken: Uint8Array | undefined): Uint8Array {
  return tupleHash(TIMESTAMP_TAG, [statementHash, prevToken ? sha256(prevToken) : ZERO]);
}

export { renewalMsg, renewalStatement };

export type VerifyCode =
  | 'MALFORMED'
  | 'SEQ_GAP'
  | 'CHAIN_BROKEN'
  | 'STATEMENT_MISMATCH'
  | 'KEY_UNKNOWN'
  | 'ED_SIGNATURE_INVALID'
  | 'PQ_SIGNATURE_INVALID'
  | 'TIMESTAMP_INVALID'
  | 'TIME_WENT_BACKWARDS'
  | 'CHECKPOINT_INVALID';
export type VerifyResult =
  | { readonly ok: true; readonly count: number; readonly lastGenTime?: Date }
  | { readonly ok: false; readonly seq: number; readonly code: VerifyCode; readonly detail?: string };

export interface VerifyOptions {
  /** Public keys by key ID, one entry per generation (a rotated service key keeps verifying its old records). */
  readonly keys: (
    keyId: string,
  ) => { readonly alg: 'ed25519' | 'ml-dsa-65'; readonly publicKey: Uint8Array } | undefined;
  readonly trustedRoots: readonly Uint8Array[];
  /** Optional extra check of each embedded checkpoint note (both lines), e.g. `verifyCheckpoint` bound to the log keys. */
  readonly checkpointOk?: (note: string) => boolean;
}

/**
 * Offline: needs the records (in order) and keys, nothing else. Checks the chain, both signatures of every record, the
 * time stamp of every record (chain to a trusted root, imprint, EKU) and that authority time never goes backwards.
 * Never throws. Old and new records are all required: a missing one is `SEQ_GAP`.
 */
export async function verifyRenewals(records: readonly Uint8Array[], o: VerifyOptions): Promise<VerifyResult> {
  let prevHash: Uint8Array = ZERO;
  let prevToken: Uint8Array | undefined;
  let prevTime: Date | undefined;
  for (const [i, bytes] of records.entries()) {
    const fail = (code: VerifyCode, detail?: string) =>
      ({ ok: false, seq: i, code, ...(detail ? { detail } : {}) }) as const;
    let r: RenewalRecord;
    try {
      r = decodeRecord(bytes);
    } catch {
      return fail('MALFORMED');
    }
    if (r.seq !== i) return fail('SEQ_GAP');
    if (r.prev_hash !== bytesToHex(prevHash)) return fail('CHAIN_BROKEN');
    const pqSig = unb64(r.sig.ml_dsa_65);
    let statement: ReturnType<typeof renewalStatement>;
    try {
      statement = renewalStatement(prevHash, r.checkpoint, pqSig);
    } catch {
      return fail('MALFORMED');
    }
    if (bytesToHex(statement.hash) !== r.statement_hash) return fail('STATEMENT_MISMATCH');

    const edKey = o.keys(r.keys.ed25519);
    const pqKey = o.keys(r.keys.ml_dsa_65);
    if (edKey?.alg !== 'ed25519' || pqKey?.alg !== 'ml-dsa-65') return fail('KEY_UNKNOWN');
    const msg = renewalMsg(prevHash, r.checkpoint);
    const edSig = unb64(r.sig.ed25519);
    if (edSig.length !== 64 || !ed25519.verify(edSig, msg, edKey.publicKey, { zip215: false })) {
      return fail('ED_SIGNATURE_INVALID');
    }
    if (!mldsaVerify('ml-dsa-65', pqKey.publicKey, msg, pqSig, RENEWAL_CONTEXT)) return fail('PQ_SIGNATURE_INVALID');
    if (o.checkpointOk && !o.checkpointOk(r.checkpoint)) return fail('CHECKPOINT_INVALID');

    const token = unb64(r.tsa.token);
    const stamped = await verifyTimestampToken(token, timestampDigest(statement.hash, prevToken), o.trustedRoots);
    if (!stamped.ok) return fail('TIMESTAMP_INVALID', stamped.code);
    if (prevTime && stamped.genTime < prevTime) return fail('TIME_WENT_BACKWARDS');
    prevHash = statement.hash;
    prevToken = token;
    prevTime = stamped.genTime;
  }
  return { ok: true, count: records.length, ...(prevTime ? { lastGenTime: prevTime } : {}) };
}
