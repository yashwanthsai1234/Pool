// Hybrid log checkpoints (DESIGN 6.13, 8.2): a C2SP signed note with an Ed25519 log signature (type 0x01) and a
// timestamped ML-DSA-44 checkpoint cosignature (type 0x06). Standard signed-note verifiers ignore unknown keys, so a
// stripped line passes them; this verifier requires BOTH lines and has no setting that allows one.
// Task 1.13 (`checkpoint.ts`) builds the tree and calls `signCheckpoint` and `verifyCheckpoint`.
// Also: RFC 4998 style renewal statements that re-sign each anchored checkpoint with ML-DSA-65.
// Source: https://c2sp.org/signed-note@v1.1.0, https://c2sp.org/tlog-checkpoint@v1.1.0,
// https://c2sp.org/tlog-cosignature@v1.1.0
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { tupleHash } from './dealcore.ts';
import { fromRipple } from './fees.ts';
import { C2SP_0X06_CONTEXT, fromBase64Strict, mldsaSign, mldsaVerify, type PqResult, toBase64 } from './pq.ts';

/** Signed-note signature types: 0x01 Ed25519 over the note text, 0x06 timestamped ML-DSA-44 cosignature. */
export type NoteSigType = 0x01 | 0x06;
const ED = 0x01;
const PQ = 0x06;
const MLDSA44_SIG = 2420;
const MAX_SIG_LINES = 32; // the spec asks verifiers to accept at least 16

/** key ID = SHA-256(key name || 0x0A || signature type || public key)[:4]. Source: https://c2sp.org/signed-note */
export function noteKeyId(name: string, type: NoteSigType, publicKey: Uint8Array): Uint8Array {
  return sha256(concatBytes(utf8ToBytes(name), Uint8Array.of(0x0a, type), publicKey)).subarray(0, 4);
}

/** Verifier key text `<name>+<hex key ID>+<base64(type || public key)>`. Source: https://c2sp.org/signed-note#verifier-keys */
export function vkey(name: string, type: NoteSigType, publicKey: Uint8Array): string {
  return `${name}+${bytesToHex(noteKeyId(name, type, publicKey))}+${toBase64(concatBytes(Uint8Array.of(type), publicKey))}`;
}

const u64 = (n: bigint) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n);
  return b;
};
// opaque <1..2^8-1> of RFC 9846 section 3: a one-byte length, then the bytes.
const opaque8 = (s: string) => {
  const b = utf8ToBytes(s);
  if (b.length < 1 || b.length > 255) throw new Error('name must be 1 to 255 bytes');
  return concatBytes(Uint8Array.of(b.length), b);
};

/**
 * The binary `CosignedSubtree` that a 0x06 signature covers (not the note text, not extension lines).
 * Source: https://c2sp.org/tlog-cosignature@v1.1.0#ml-dsa-44
 */
export function cosignedSubtree(
  cosignerName: string,
  timestamp: bigint,
  origin: string,
  start: bigint,
  end: bigint,
  hash: Uint8Array,
): Uint8Array {
  if (hash.length !== 32) throw new Error('hash must be 32 bytes');
  return concatBytes(
    utf8ToBytes('subtree/v1\n\0'),
    opaque8(cosignerName),
    u64(timestamp),
    opaque8(origin),
    u64(start),
    u64(end),
    hash,
  );
}

export interface CheckpointBody {
  readonly origin: string;
  readonly treeSize: number;
  readonly rootHash: Uint8Array;
}

/** origin, tree size and base64 root, each ending in a newline. Source: https://c2sp.org/tlog-checkpoint#note-text */
export function checkpointText(cp: CheckpointBody): string {
  return `${cp.origin}\n${cp.treeSize}\n${toBase64(cp.rootHash)}\n`;
}

const sigLine = (name: string, blob: Uint8Array) => `— ${name} ${toBase64(blob)}\n`;

/**
 * Signs a checkpoint with both lines. `ledgerCloseTime` is the validated ledger close_time (Ripple epoch); the 0x06
 * timestamp is that time in POSIX seconds, never the wall clock. The 0x06 line uses the empty ML-DSA context: the
 * spec names none, and the Go (filippo.io/mldsa) and Rust (cloudflare/azul) implementations use the empty one.
 */
export function signCheckpoint(
  cp: CheckpointBody,
  ed: { readonly name: string; readonly seed: Uint8Array },
  pq: { readonly name: string; readonly secretKey: Uint8Array },
  ledgerCloseTime: number,
): string {
  if (!Number.isSafeInteger(ledgerCloseTime) || ledgerCloseTime < 0)
    throw new Error('ledgerCloseTime must be an integer');
  const text = checkpointText(cp);
  const ts = BigInt(fromRipple(ledgerCloseTime));
  const edSig = ed25519.sign(utf8ToBytes(text), ed.seed);
  const m = cosignedSubtree(pq.name, ts, cp.origin, 0n, BigInt(cp.treeSize), cp.rootHash);
  const pqSig = mldsaSign('ml-dsa-44', pq.secretKey, m, C2SP_0X06_CONTEXT);
  const pqPub = ml_dsa44.getPublicKey(pq.secretKey);
  return `${text}\n${sigLine(ed.name, concatBytes(noteKeyId(ed.name, ED, ed25519.getPublicKey(ed.seed)), edSig))}${sigLine(
    pq.name,
    concatBytes(noteKeyId(pq.name, PQ, pqPub), u64(ts), pqSig),
  )}`;
}

export interface CheckpointKeys {
  readonly ed: { readonly name: string; readonly publicKey: Uint8Array }; // 32-byte Ed25519 log key
  readonly pq: { readonly name: string; readonly publicKey: Uint8Array }; // 1,312-byte ML-DSA-44 cosigner key
}
export type CheckpointCode =
  | 'MALFORMED'
  | 'ORIGIN_MISMATCH'
  | 'EXTENSION_LINES'
  | 'DUPLICATE_LINE'
  | 'ED_LINE_MISSING'
  | 'PQ_LINE_MISSING'
  | 'ED_SIGNATURE_INVALID'
  | 'PQ_SIGNATURE_INVALID';
export type CheckpointResult =
  | {
      readonly ok: true;
      readonly origin: string;
      readonly treeSize: number;
      readonly rootHash: Uint8Array;
      readonly timestamp: number; // POSIX seconds from the 0x06 line
    }
  | { readonly ok: false; readonly code: CheckpointCode };

const SIG_LINE = /^— ([^\s+]+) ([A-Za-z0-9+/=]+)$/u;
// Signed notes MUST NOT contain ASCII control characters other than newline.
const hasControlChar = (s: string) => [...s].some((c) => c < ' ' && c !== '\n');

/** Verifies a hybrid checkpoint for `origin`. Returns a typed error and never throws. */
export function verifyCheckpoint(note: string, origin: string, keys: CheckpointKeys): CheckpointResult {
  try {
    return check(note, origin, keys);
  } catch {
    return { ok: false, code: 'MALFORMED' };
  }
}

function check(note: string, origin: string, keys: CheckpointKeys): CheckpointResult {
  const fail = (code: CheckpointCode) => ({ ok: false, code }) as const;
  // Signed-note framing: text ending in a newline, a blank line, signature lines each ending in a newline.
  if (typeof note !== 'string' || hasControlChar(note) || !note.endsWith('\n')) return fail('MALFORMED');
  const split = note.lastIndexOf('\n\n');
  if (split < 0) return fail('MALFORMED');
  const text = note.slice(0, split + 1);
  const sigLines = note.slice(split + 2, -1).split('\n');
  if (sigLines.length > MAX_SIG_LINES) return fail('MALFORMED');

  const body = text.slice(0, -1).split('\n');
  if (body.length < 3 || body.some((l) => l === '')) return fail('MALFORMED');
  if (body.length > 3) return fail('EXTENSION_LINES'); // never signed by 0x06, never written by us
  const [o, sizeText, rootText] = body as [string, string, string];
  if (o !== origin) return fail('ORIGIN_MISMATCH');
  if (!/^(0|[1-9][0-9]{0,15})$/.test(sizeText) || !Number.isSafeInteger(Number(sizeText))) return fail('MALFORMED');
  const treeSize = Number(sizeText);
  const rootHash = fromBase64Strict(rootText);
  if (rootHash?.length !== 32) return fail('MALFORMED');

  const edId = bytesToHex(noteKeyId(keys.ed.name, ED, keys.ed.publicKey));
  const pqId = bytesToHex(noteKeyId(keys.pq.name, PQ, keys.pq.publicKey));
  let edSeen = false;
  let timestamp: bigint | undefined;
  for (const line of sigLines) {
    const m = SIG_LINE.exec(line);
    const blob = m && fromBase64Strict(m[2] as string);
    if (!m || !blob || blob.length < 4) return fail('MALFORMED');
    const id = bytesToHex(blob.subarray(0, 4));
    const sig = blob.subarray(4);
    if (m[1] === keys.ed.name && id === edId) {
      if (edSeen) return fail('DUPLICATE_LINE');
      edSeen = true;
      const ok =
        sig.length === 64 &&
        keys.ed.publicKey.length === 32 &&
        ed25519.verify(sig, utf8ToBytes(text), keys.ed.publicKey, { zip215: false });
      if (!ok) return fail('ED_SIGNATURE_INVALID');
    } else if (m[1] === keys.pq.name && id === pqId) {
      if (timestamp !== undefined) return fail('DUPLICATE_LINE');
      if (sig.length !== 8 + MLDSA44_SIG) return fail('PQ_SIGNATURE_INVALID');
      timestamp = new DataView(sig.buffer, sig.byteOffset, 8).getBigUint64(0);
      const msg = cosignedSubtree(keys.pq.name, timestamp, origin, 0n, BigInt(treeSize), rootHash);
      if (!mldsaVerify('ml-dsa-44', keys.pq.publicKey, msg, sig.subarray(8), C2SP_0X06_CONTEXT)) {
        return fail('PQ_SIGNATURE_INVALID');
      }
    } // any other key is ignored, as the spec requires
  }
  if (!edSeen) return fail('ED_LINE_MISSING');
  if (timestamp === undefined) return fail('PQ_LINE_MISSING');
  if (timestamp > BigInt(Number.MAX_SAFE_INTEGER)) return fail('MALFORMED');
  return { ok: true, origin, treeSize, rootHash, timestamp: Number(timestamp) };
}

// ---------- RFC 4998 style renewal (re-signing anchored checkpoints with ML-DSA-65) ----------
// Each statement names the previous statement's hash, so the chain cannot be cut or reordered. The signature uses the
// context `legx/checkpoint/v1`. The scheduled job that makes them is task 3.12.
// Source: https://www.rfc-editor.org/rfc/rfc4998#section-5 (archive timestamp chains and renewal)

export interface RenewalStatement {
  readonly prevHash: Uint8Array;
  readonly checkpointHash: Uint8Array;
  readonly pqSig: Uint8Array;
  readonly hash: Uint8Array;
}

/** What the ML-DSA-65 key signs: tupleHash("legx/renewal/v1", [prevHash, SHA-256(checkpoint note)]). */
export function renewalMsg(prevHash: Uint8Array, checkpointNote: string): Uint8Array {
  if (prevHash.length !== 32) throw new Error('prevHash must be 32 bytes');
  return tupleHash('legx/renewal/v1', [prevHash, sha256(utf8ToBytes(checkpointNote))]);
}

/** Pure: the statement and its hash, tupleHash("legx/renewal-statement/v1", [prevHash, checkpointHash, pqSig]). */
export function renewalStatement(prevHash: Uint8Array, newCheckpoint: string, pqSig: Uint8Array): RenewalStatement {
  renewalMsg(prevHash, newCheckpoint); // length check
  const checkpointHash = sha256(utf8ToBytes(newCheckpoint));
  return {
    prevHash,
    checkpointHash,
    pqSig,
    hash: tupleHash('legx/renewal-statement/v1', [prevHash, checkpointHash, pqSig]),
  };
}

export type RenewalCode = 'MALFORMED' | 'CHAIN_BROKEN' | 'CHECKPOINT_MISMATCH' | 'HASH_MISMATCH' | 'SIG_INVALID';

/** The first statement starts from 32 zero bytes; each next one names the previous hash. Never throws. */
export function verifyRenewalChain(
  chain: readonly RenewalStatement[],
  checkpoints: readonly string[],
  pqPublicKey: Uint8Array,
): PqResult<RenewalCode> {
  try {
    return checkChain(chain, checkpoints, pqPublicKey);
  } catch {
    return { ok: false, code: 'MALFORMED' };
  }
}

function checkChain(
  chain: readonly RenewalStatement[],
  checkpoints: readonly string[],
  pqPublicKey: Uint8Array,
): PqResult<RenewalCode> {
  const fail = (code: RenewalCode) => ({ ok: false, code }) as const;
  if (chain.length !== checkpoints.length) return fail('CHECKPOINT_MISMATCH');
  let prev: Uint8Array = new Uint8Array(32);
  for (const [i, s] of chain.entries()) {
    const note = checkpoints[i] as string;
    if (bytesToHex(s.prevHash) !== bytesToHex(prev)) return fail('CHAIN_BROKEN');
    if (bytesToHex(s.checkpointHash) !== bytesToHex(sha256(utf8ToBytes(note)))) return fail('CHECKPOINT_MISMATCH');
    if (bytesToHex(s.hash) !== bytesToHex(renewalStatement(s.prevHash, note, s.pqSig).hash))
      return fail('HASH_MISMATCH');
    if (!mldsaVerify('ml-dsa-65', pqPublicKey, renewalMsg(prev, note), s.pqSig, 'legx/checkpoint/v1')) {
      return fail('SIG_INVALID');
    }
    prev = s.hash;
  }
  return { ok: true };
}
