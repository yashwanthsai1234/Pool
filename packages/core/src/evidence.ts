// Evidence envelopes (DESIGN 8.1, 8.2): DSSE v1 with two payload types that share one code path, and the per-deal
// hash chain. The Ed25519-only functions here are the classical half; the hybrid envelope (Ed25519 plus ML-DSA-65) is
// `hybridEnvelope.ts`, which builds on `Envelope` and `pae`. Leaf hashes are over the stored bytes, never over a
// re-serialized envelope.
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { fromBase64Strict, toBase64 } from './pq.ts';

// DSSE v1 pre-authentication encoding: "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
// Source: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md (v1.0.2)
export function pae(type: string, body: Uint8Array): Uint8Array {
  const t = utf8ToBytes(type);
  return concatBytes(utf8ToBytes(`DSSEv1 ${t.length} `), t, utf8ToBytes(` ${body.length} `), body);
}
export interface Envelope {
  payloadType: string;
  payload: string;
  signatures: { keyid: string; sig: string }[];
}
export const PAYLOAD_TYPE = 'application/vnd.legx.event+json;v=1';
export const ATTEST_PAYLOAD_TYPE = 'application/vnd.legx.attest+json;v=1';
export type EvidencePayloadType = typeof PAYLOAD_TYPE | typeof ATTEST_PAYLOAD_TYPE;

function signAs(type: EvidencePayloadType, body: Uint8Array, seed: Uint8Array, keyid: string): Envelope {
  const sig = ed25519.sign(pae(type, body), seed);
  return { payloadType: type, payload: toBase64(body), signatures: [{ keyid, sig: toBase64(sig) }] };
}
// Strict RFC 8032 verification (zip215: false), a hard rule. Canonical base64 only, and the payload type must match.
function verifyAs(type: EvidencePayloadType, env: Envelope, pub: Uint8Array): boolean {
  if (env.payloadType !== type || typeof env.payload !== 'string' || !Array.isArray(env.signatures)) return false;
  const body = fromBase64Strict(env.payload);
  if (!body) return false;
  const msg = pae(type, body);
  return env.signatures.some((s) => {
    const sig = typeof s?.sig === 'string' ? fromBase64Strict(s.sig) : undefined;
    return sig !== undefined && sig.length === 64 && ed25519.verify(sig, msg, pub, { zip215: false });
  });
}

export const signEnvelope = (body: Uint8Array, seed: Uint8Array, keyid: string) =>
  signAs(PAYLOAD_TYPE, body, seed, keyid);
export const verifyEnvelope = (env: Envelope, pub: Uint8Array) => verifyAs(PAYLOAD_TYPE, env, pub);
export const signAttestation = (body: Uint8Array, seed: Uint8Array, keyid: string) =>
  signAs(ATTEST_PAYLOAD_TYPE, body, seed, keyid);
export const verifyAttestationEnvelope = (env: Envelope, pub: Uint8Array) => verifyAs(ATTEST_PAYLOAD_TYPE, env, pub);

// Per-deal hash chain. seq and prev_hash live INSIDE the signed payload, so a dropped or
// reordered event cannot be hidden by recomputing hashes. Leaf hash = sha256(exact envelope bytes).
// Source: DESIGN 8.2 layer 1; Merkle leaf hashing https://www.rfc-editor.org/rfc/rfc9162#section-2.1.1
export interface ChainEntry {
  envelopeBytes: Uint8Array;
  leafHash: string;
}
export const ZERO = '00'.repeat(32);
export const leafHashOf = (b: Uint8Array) => bytesToHex(sha256(b));

export type EnvelopeCheck = (env: Envelope) => boolean;
/** The classical signature check: the first signature's key ID picks the public key. */
export const ed25519Check =
  (keyFor: (keyid: string) => Uint8Array | undefined, type: EvidencePayloadType = PAYLOAD_TYPE): EnvelopeCheck =>
  (env) => {
    const pub = keyFor(env.signatures[0]?.keyid as string);
    return pub !== undefined && verifyAs(type, env, pub);
  };

/** The stored envelope and the `seq` and `prev_hash` signed inside it; undefined if the leaf hash or the JSON is wrong. */
export function entryLink(
  entry: ChainEntry,
): { env: Envelope; predicate: Record<string, unknown>; seq: unknown; prevHash: unknown } | undefined {
  if (entry.leafHash !== leafHashOf(entry.envelopeBytes)) return undefined;
  try {
    const env: Envelope = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(entry.envelopeBytes));
    if (!Array.isArray(env.signatures)) return undefined;
    const pred = JSON.parse(new TextDecoder().decode(fromBase64Strict(env.payload))).predicate;
    return { env, predicate: pred, seq: pred.seq, prevHash: pred.prev_hash };
  } catch {
    return undefined;
  }
}

export function verifyChainWith(entries: ChainEntry[], check: EnvelopeCheck): boolean {
  let prev = ZERO;
  for (let i = 0; i < entries.length; i++) {
    const link = entryLink(entries[i]!);
    if (!link || !check(link.env) || link.seq !== i || link.prevHash !== prev) return false;
    prev = entries[i]!.leafHash;
  }
  return true;
}
export const verifyChain = (
  entries: ChainEntry[],
  keyFor: (keyid: string) => Uint8Array | undefined,
  type: EvidencePayloadType = PAYLOAD_TYPE,
) => verifyChainWith(entries, ed25519Check(keyFor, type));
