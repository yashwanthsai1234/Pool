// In-process RFC 9162 transparency log (DESIGN 8.2, "the in-process tree in Appendix A is enough" until Tessera).
// Leaves are the stored envelope bytes. A checkpoint is a C2SP signed note with the Ed25519 (0x01) and ML-DSA-44
// (0x06) lines, signed by `pqCheckpoint.ts` (task 1.16). Duplicate leaves return the first index (the `leaf_hash
// UNIQUE` rule of 8.2).
// Source: https://www.rfc-editor.org/rfc/rfc9162#section-2.1, https://c2sp.org/tlog-checkpoint, https://c2sp.org/signed-note
import type { Checkpoint, TransparencyLogPort } from '@legx/contracts/ports';
import type { Hex32 } from '@legx/contracts/values';
import { bytesToHex, hexToBytes, inclusionPath, mth, utf8ToBytes, verifyInclusion } from './dealcore.ts';
import { consistencyProof } from './merkle.ts';
import {
  type CheckpointCode,
  type CheckpointKeys,
  type CheckpointResult,
  signCheckpoint,
  verifyCheckpoint,
} from './pqCheckpoint.ts';

export interface LogSigning {
  origin: string;
  ed: { name: string; seed: Uint8Array };
  pq: { name: string; secretKey: Uint8Array };
  /** The validated ledger close_time (Ripple epoch) to stamp the 0x06 line with; never the wall clock. */
  closeTime: () => number;
}

export function createLog(signing: LogSigning): TransparencyLogPort {
  const leaves: Uint8Array[] = [];
  const index = new Map<string, number>();
  const prefix = (size: number) => {
    if (!Number.isInteger(size) || size < 1 || size > leaves.length)
      throw new Error(`tree size ${size} is not in 1..${leaves.length}`);
    return leaves.slice(0, size);
  };
  const hex = (h: Uint8Array) => bytesToHex(h) as Hex32;
  return {
    async add(leaf) {
      const key = bytesToHex(mth([leaf]));
      const known = index.get(key);
      if (known !== undefined) return { index: known };
      leaves.push(leaf.slice()); // a copy: a caller's later change cannot alter a stored leaf
      index.set(key, leaves.length - 1);
      return { index: leaves.length - 1 };
    },
    async checkpoint(): Promise<Checkpoint> {
      const rootHash = mth(leaves);
      const note = signCheckpoint(
        { origin: signing.origin, treeSize: leaves.length, rootHash },
        signing.ed,
        signing.pq,
        signing.closeTime(),
      );
      return { origin: signing.origin, treeSize: leaves.length, rootHash: hex(rootHash), note };
    },
    async inclusionProof(i, treeSize) {
      const tree = prefix(treeSize);
      if (!Number.isInteger(i) || i < 0 || i >= treeSize)
        throw new Error(`leaf index ${i} is not in 0..${treeSize - 1}`);
      return inclusionPath(i, tree).map(hex);
    },
    async consistencyProof(fromSize, toSize) {
      return consistencyProof(fromSize, prefix(toSize)).map(hex);
    },
  };
}

/** An offline receipt (C2SP tlog-proof shape): the leaf, its index, the inclusion path and a hybrid checkpoint. */
export interface Receipt {
  leaf: Uint8Array;
  index: number;
  path: readonly Hex32[];
  note: string;
}

export type ReceiptResult =
  | Extract<CheckpointResult, { ok: true }>
  | { ok: false; code: CheckpointCode | 'INCLUSION_FAILED' };

export function verifyReceipt(r: Receipt, origin: string, keys: CheckpointKeys): ReceiptResult {
  const cp = verifyCheckpoint(r.note, origin, keys);
  if (!cp.ok) return cp;
  let path: Uint8Array[];
  try {
    path = r.path.map((h) => hexToBytes(h));
  } catch {
    return { ok: false, code: 'INCLUSION_FAILED' }; // not hex: no valid path (Buffer silently truncated it)
  }
  return verifyInclusion(r.leaf, r.index, cp.treeSize, path, cp.rootHash)
    ? cp
    : { ok: false, code: 'INCLUSION_FAILED' };
}

/**
 * Folds the zero-knowledge trust records (registry roots, circuit manifest, verification-key hashes) into the next
 * checkpoint: one log leaf, `legx/zk-trust-anchor/v1` || root, from `zkCheckpointInput(...).root` (DESIGN 6.10, 8.3).
 * Idempotent: the same root returns the same index.
 */
export function addZkTrustAnchor(log: Pick<TransparencyLogPort, 'add'>, zkRoot: string): Promise<{ index: number }> {
  if (!/^[0-9a-f]{64}$/.test(zkRoot)) throw new Error('zk trust root must be 64 lowercase hex characters');
  return log.add(utf8ToBytes(`legx/zk-trust-anchor/v1\n${zkRoot}`));
}
