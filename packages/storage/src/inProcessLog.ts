// The in-process RFC 9162 log (demo profile): the same TransparencyLogPort as the Tessera adapter, with a hybrid
// checkpoint (Ed25519 line 0x01 plus ML-DSA-44 line 0x06) signed through the log's own CheckpointSignerPort.
// Source: https://www.rfc-editor.org/rfc/rfc9162 and https://c2sp.org/tlog-checkpoint
// Source: https://c2sp.org/tlog-cosignature@v1.1.0 (the 0x06 line: key ID, 8-byte timestamp, signature)
import type { Checkpoint, CheckpointSignerPort, ClockPort, TransparencyLogPort } from '@legx/contracts/ports';
import type { Hex32 } from '@legx/contracts/values';
import { fromRipple } from '@legx/core/fees';
import { toBase64 } from '@legx/core/pq';
import { checkpointText, cosignedSubtree, noteKeyId } from '@legx/core/pqCheckpoint';
import { bytesToHex, concatBytes } from '@noble/hashes/utils.js';
import { consistencyPath, type Hash, inclusionPath, leafHash, nodeHash, type SubtreeHash, treeRoot } from './merkle.ts';

export interface InProcessLogOptions {
  readonly origin: string;
  readonly signer: CheckpointSignerPort;
  /** The 0x06 timestamp is the validated ledger `close_time`, never the wall clock (IMPLEMENTATION 1.3 rule 5). */
  readonly clock: ClockPort;
  /** Signed-note key names (no spaces, no `+`). Default: the origin, and the origin plus `-mldsa44`. */
  readonly names?: { readonly ed25519: string; readonly mlDsa44: string };
}

const u64 = (n: bigint) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n);
  return b;
};
const sigLine = (name: string, blob: Uint8Array) => `— ${name} ${toBase64(blob)}\n`;
const hex32 = (h: Hash) => bytesToHex(h) as Hex32;

export function inProcessLog(options: InProcessLogOptions): TransparencyLogPort {
  const { origin, signer, clock } = options;
  const names = options.names ?? { ed25519: origin, mlDsa44: `${origin}-mldsa44` };
  const leaves: Hash[] = [];
  // Perfect subtrees never change once complete, so their hashes are cached for good.
  const cache = new Map<string, Hash>();
  const sub: SubtreeHash = async (level, index) => {
    if (level === 0) return leaves[index] as Hash;
    const key = `${level}:${index}`;
    let h = cache.get(key);
    if (!h) {
      h = nodeHash(await sub(level - 1, 2 * index), await sub(level - 1, 2 * index + 1));
      cache.set(key, h);
    }
    return h;
  };

  return {
    async add(leaf) {
      leaves.push(leafHash(leaf));
      return { index: leaves.length - 1 };
    },

    async checkpoint(): Promise<Checkpoint> {
      const treeSize = leaves.length;
      const root = await treeRoot(sub, treeSize);
      const timestamp = BigInt(fromRipple((await clock.now()).closeTime));
      const keys = await signer.publicKeys();
      const text = checkpointText({ origin, treeSize, rootHash: root });
      const sig = await signer.signCheckpoint({
        noteBody: new TextEncoder().encode(text),
        cosignedSubtree: cosignedSubtree(names.mlDsa44, timestamp, origin, 0n, BigInt(treeSize), root),
      });
      const note = `${text}\n${sigLine(
        names.ed25519,
        concatBytes(noteKeyId(names.ed25519, 0x01, keys.ed25519), sig.ed25519),
      )}${sigLine(names.mlDsa44, concatBytes(noteKeyId(names.mlDsa44, 0x06, keys.mlDsa44), u64(timestamp), sig.mlDsa44))}`;
      return { origin, treeSize, rootHash: hex32(root), note };
    },

    async inclusionProof(index, treeSize) {
      if (treeSize > leaves.length) throw new RangeError('tree size beyond the log');
      return (await inclusionPath(sub, index, treeSize)).map(hex32);
    },

    async consistencyProof(fromSize, toSize) {
      if (toSize > leaves.length) throw new RangeError('tree size beyond the log');
      return (await consistencyPath(sub, fromSize, toSize)).map(hex32);
    },
  };
}
