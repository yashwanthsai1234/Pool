// The hybrid checkpoint job's core (DESIGN 6.13, 8.2; closes issue I-7): turns whatever note the log serves (Tessera
// signs its own Ed25519 line only) into a note with BOTH of our lines, 0x01 Ed25519 and 0x06 timestamped ML-DSA-44, and
// wraps a `TransparencyLogPort` so the evidence service's `checkpoint()` publishes only complete notes.
// Before it signs it checks that the tree extends the one it signed last: a cosigner must never sign two checkpoints
// that no consistency proof connects.
// Source: https://c2sp.org/tlog-checkpoint (note body, signature types, the never-sign-inconsistent rule)
// Source: https://c2sp.org/tlog-cosignature@v1.1.0 (the 0x06 line: key ID, 8-byte timestamp, ML-DSA-44 over the CosignedSubtree)
// Source: https://c2sp.org/signed-note (line framing, key IDs; verifiers ignore unknown keys)
import type { Checkpoint, CheckpointSignerPort, ClockPort, TransparencyLogPort } from '@legx/contracts/ports';
import { fromRipple } from '@legx/core/fees';
import { verifyConsistency } from '@legx/core/merkle';
import { toBase64 } from '@legx/core/pq';
import {
  type CheckpointBody,
  type CheckpointKeys,
  checkpointText,
  cosignedSubtree,
  noteKeyId,
  verifyCheckpoint,
} from '@legx/core/pqCheckpoint';
import { concatBytes } from '@noble/hashes/utils.js';

const utf8 = new TextEncoder();
const hexToBytes = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));
const u64 = (n: bigint) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n);
  return b;
};
const sigLine = (name: string, blob: Uint8Array) => `— ${name} ${toBase64(blob)}\n`;

export class InconsistentCheckpoint extends Error {
  constructor(message: string) {
    super(`refusing to cosign: ${message}`);
    this.name = 'InconsistentCheckpoint';
  }
}

/** The names our two keys carry in signed notes (no spaces, no `+`). */
export interface NoteNames {
  readonly ed25519: string;
  readonly mlDsa44: string;
}
export const defaultNames = (origin: string): NoteNames => ({ ed25519: origin, mlDsa44: `${origin}-mldsa44` });

/** Splits a note into its body (three lines) and its signature lines; throws on anything that is not a checkpoint. */
function split(note: string): { body: CheckpointBody; foreign: string[] } {
  const at = note.lastIndexOf('\n\n');
  if (at < 0 || !note.endsWith('\n')) throw new Error('not a signed note');
  const [origin, size, root] = note.slice(0, at).split('\n');
  const treeSize = Number(size);
  const rootHash = root === undefined ? undefined : Buffer.from(root, 'base64');
  if (!origin || !Number.isSafeInteger(treeSize) || treeSize < 0 || rootHash?.length !== 32) {
    throw new Error('not a checkpoint');
  }
  return {
    body: { origin, treeSize, rootHash: new Uint8Array(rootHash) },
    foreign: note
      .slice(at + 2, -1)
      .split('\n')
      .filter((l) => l !== ''),
  };
}

export interface CosignOptions {
  readonly signer: CheckpointSignerPort;
  /** Validated ledger close_time (Ripple epoch): the 0x06 timestamp. Never the wall clock. */
  readonly closeTime: number;
  readonly names?: NoteNames;
}

/**
 * Returns `note` with our 0x01 and 0x06 lines. A note that already verifies under our keys is returned as it is (so
 * a second run is a no-op); otherwise our lines are replaced, other cosigners' lines stay.
 */
export async function cosignCheckpoint(note: string, options: CosignOptions): Promise<string> {
  const { body, foreign } = split(note);
  const names = options.names ?? defaultNames(body.origin);
  const keys = await options.signer.publicKeys();
  const verifying: CheckpointKeys = {
    ed: { name: names.ed25519, publicKey: keys.ed25519 },
    pq: { name: names.mlDsa44, publicKey: keys.mlDsa44 },
  };
  if (verifyCheckpoint(note, body.origin, verifying).ok) return note;

  const text = checkpointText(body);
  const timestamp = BigInt(fromRipple(options.closeTime));
  const sig = await options.signer.signCheckpoint({
    noteBody: utf8.encode(text),
    cosignedSubtree: cosignedSubtree(names.mlDsa44, timestamp, body.origin, 0n, BigInt(body.treeSize), body.rootHash),
  });
  const kept = foreign.filter((l) => !l.startsWith(`— ${names.ed25519} `) && !l.startsWith(`— ${names.mlDsa44} `));
  const signed =
    sigLine(names.ed25519, concatBytes(noteKeyId(names.ed25519, 0x01, keys.ed25519), sig.ed25519)) +
    sigLine(names.mlDsa44, concatBytes(noteKeyId(names.mlDsa44, 0x06, keys.mlDsa44), u64(timestamp), sig.mlDsa44));
  const result = `${text}\n${kept.map((l) => `${l}\n`).join('')}${signed}`;
  // Never publish what our own verifier would refuse (a broken signer, a wrong key ID).
  if (!verifyCheckpoint(result, body.origin, verifying).ok) throw new Error('the cosigned checkpoint does not verify');
  return result;
}

export interface HybridLogOptions extends Omit<CosignOptions, 'closeTime'> {
  readonly clock: ClockPort;
  /** The checkpoint we signed last (the evidence service's latest `checkpoint_anchor`), if any. */
  readonly previous: () => Promise<{ readonly treeSize: number; readonly rootHash: string } | undefined>;
}

/** `log` whose `checkpoint()` always carries both of our lines. The leaves, the proofs and `add` are the log's own. */
export function hybridCheckpointLog(log: TransparencyLogPort, options: HybridLogOptions): TransparencyLogPort {
  return {
    add: (leaf) => log.add(leaf),
    inclusionProof: (i, n) => log.inclusionProof(i, n),
    consistencyProof: (a, b) => log.consistencyProof(a, b),
    async checkpoint(): Promise<Checkpoint> {
      const fresh = await log.checkpoint();
      await assertExtends(log, await options.previous(), fresh);
      const closeTime = (await options.clock.now()).closeTime;
      return { ...fresh, note: await cosignCheckpoint(fresh.note, { ...options, closeTime }) };
    },
  };
}

async function assertExtends(
  log: TransparencyLogPort,
  prev: { treeSize: number; rootHash: string } | undefined,
  next: Checkpoint,
): Promise<void> {
  if (!prev || prev.treeSize === 0) return;
  if (next.treeSize < prev.treeSize) throw new InconsistentCheckpoint('the tree shrank');
  if (next.treeSize === prev.treeSize) {
    if (next.rootHash !== prev.rootHash) throw new InconsistentCheckpoint('same size, different root');
    return;
  }
  const proof = (await log.consistencyProof(prev.treeSize, next.treeSize)).map(hexToBytes);
  if (!verifyConsistency(prev.treeSize, next.treeSize, hexToBytes(prev.rootHash), hexToBytes(next.rootHash), proof)) {
    throw new InconsistentCheckpoint('no consistency proof connects it to the last checkpoint');
  }
}
