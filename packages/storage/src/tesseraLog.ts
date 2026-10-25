// Adapter to a Trillian Tessera POSIX sidecar (production profile).
// Write side: `POST /add` with the leaf bytes as the body returns the new index as plain decimal text, once the entry has
// an index (not yet integrated). Read side: the C2SP tlog-tiles API (`/checkpoint`, `/tile/<L>/<N>[.p/<W>]`), from which
// we compute proofs ourselves.
// Source: https://github.com/transparency-dev/tessera/blob/main/cmd/conformance/posix/main.go (the /add handler)
// Source: https://c2sp.org/tlog-tiles (paths, tile height 8, partial tiles) and https://c2sp.org/tlog-checkpoint
import type { Checkpoint, CheckpointSignerPort, ClockPort, TransparencyLogPort } from '@legx/contracts/ports';
import type { Hex32 } from '@legx/contracts/values';
import { fromRipple } from '@legx/core/fees';
import { fromBase64Strict, toBase64 } from '@legx/core/pq';
import { cosignedSubtree, noteKeyId } from '@legx/core/pqCheckpoint';
import { bytesToHex, concatBytes } from '@noble/hashes/utils.js';
import { consistencyPath, type Hash, inclusionPath, nodeHash, type SubtreeHash, treeRoot } from './merkle.ts';

export interface TesseraLogOptions {
  /** Base URL of the sidecar, without a trailing slash (it serves `/add`, `/checkpoint` and `/tile/...`). */
  readonly baseUrl: string;
  readonly fetch?: typeof fetch;
  /** How long `add` waits for a checkpoint that covers the new entry. */
  readonly integrateTimeoutMs?: number;
  readonly pollIntervalMs?: number;
  /**
   * Adds the timestamped ML-DSA-44 cosignature line (C2SP type 0x06) that a stock Tessera does not write (I-7). The
   * timestamp is the validated ledger close time, as in `signCheckpoint` of `@legx/core`. Only the ML-DSA half of the
   * signer's output is used: Tessera keeps signing the Ed25519 line itself.
   */
  readonly cosign?: { readonly signer: CheckpointSignerPort; readonly name: string; readonly clock: ClockPort };
}

const TILE_HEIGHT = 8;
const TILE_WIDTH = 256;
const MAX_TILE_BYTES = TILE_WIDTH * 32;

/** `<N>` as zero-padded 3-digit groups, each but the last prefixed `x`. Source: https://c2sp.org/tlog-tiles#merkle-tree */
export function tileIndexPath(n: number): string {
  const groups: string[] = [];
  let rest = n;
  do {
    groups.unshift(String(rest % 1000).padStart(3, '0'));
    rest = Math.floor(rest / 1000);
  } while (rest > 0);
  return groups.map((g, i) => (i < groups.length - 1 ? `x${g}` : g)).join('/');
}

const hex32 = (h: Hash) => bytesToHex(h) as Hex32;
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export function tesseraLog(options: TesseraLogOptions): TransparencyLogPort {
  const doFetch = options.fetch ?? fetch;
  const base = options.baseUrl;
  const timeoutMs = options.integrateTimeoutMs ?? 10_000;
  const pollMs = options.pollIntervalMs ?? 50;
  const cosign = options.cosign;

  const get = (path: string) => doFetch(`${base}${path}`);

  async function checkpoint(): Promise<Checkpoint> {
    const res = await get('/checkpoint');
    if (!res.ok) throw new Error(`tessera /checkpoint: HTTP ${res.status}`);
    const note = await res.text();
    const [origin, size, root] = note.split('\n');
    const treeSize = Number(size);
    const rootHash = root === undefined ? undefined : fromBase64Strict(root);
    if (
      !origin ||
      !/^(0|[1-9][0-9]*)$/.test(size ?? '') ||
      !Number.isSafeInteger(treeSize) ||
      rootHash?.length !== 32
    ) {
      throw new Error('tessera /checkpoint: malformed checkpoint');
    }
    return {
      origin,
      treeSize,
      rootHash: hex32(rootHash),
      note: cosign ? await cosigned(note, origin, treeSize, rootHash) : note,
    };
  }

  // Source: https://c2sp.org/tlog-cosignature@v1.1.0#ml-dsa-44 and https://c2sp.org/signed-note (signature line format)
  async function cosigned(note: string, origin: string, treeSize: number, rootHash: Uint8Array): Promise<string> {
    if (!cosign) return note;
    const ts = BigInt(fromRipple((await cosign.clock.now()).closeTime));
    const sub = cosignedSubtree(cosign.name, ts, origin, 0n, BigInt(treeSize), rootHash);
    const { mlDsa44 } = await cosign.signer.signCheckpoint({
      noteBody: new TextEncoder().encode(note),
      cosignedSubtree: sub,
    });
    const pub = (await cosign.signer.publicKeys()).mlDsa44;
    const time = new Uint8Array(8);
    new DataView(time.buffer).setBigUint64(0, ts);
    const blob = concatBytes(noteKeyId(cosign.name, 0x06, pub), time, mlDsa44);
    return `${note.endsWith('\n') ? note : `${note}\n`}— ${cosign.name} ${toBase64(blob)}\n`;
  }

  /** Subtree hashes from the hash tiles of the tree of `treeSize` leaves. */
  function tileReader(treeSize: number): SubtreeHash {
    const tiles = new Map<string, Promise<Uint8Array>>();
    const tile = (level: number, n: number): Promise<Uint8Array> => {
      const key = `${level}/${n}`;
      let p = tiles.get(key);
      if (!p) {
        p = fetchTile(level, n, treeSize);
        tiles.set(key, p);
        p.catch(() => tiles.delete(key));
      }
      return p;
    };
    return async (h, i) => {
      const l = Math.floor(h / TILE_HEIGHT);
      const r = h % TILE_HEIGHT; // the subtree is 2^r adjacent entries of a level-l tile
      const first = i * 2 ** r;
      const data = await tile(l, Math.floor(first / TILE_WIDTH));
      const offset = first % TILE_WIDTH;
      let row: Hash[] = [];
      for (let k = 0; k < 2 ** r; k++) {
        row.push(data.subarray((offset + k) * 32, (offset + k + 1) * 32));
      }
      if (row.some((x) => x.length !== 32)) throw new Error('tessera tile is shorter than the checkpoint requires');
      while (row.length > 1) {
        const next: Hash[] = [];
        for (let k = 0; k < row.length; k += 2) next.push(nodeHash(row[k] as Hash, row[k + 1] as Hash));
        row = next;
      }
      return row[0] as Hash;
    };
  }

  async function fetchTile(level: number, n: number, treeSize: number): Promise<Uint8Array> {
    const entries = Math.floor(treeSize / TILE_WIDTH ** level); // hashes that exist at this tile level
    const width = Math.min(TILE_WIDTH, entries - n * TILE_WIDTH);
    if (width < 1) throw new RangeError('tile beyond the tree');
    const full = `/tile/${level}/${tileIndexPath(n)}`;
    // A partial tile may be deleted once the full tile exists, so a 404 falls back to the full tile (spec: may be fetched too).
    const urls = width === TILE_WIDTH ? [full] : [`${full}.p/${width}`, full];
    for (const url of urls) {
      const res = await get(url);
      if (res.status === 404) continue;
      if (!res.ok) throw new Error(`tessera ${url}: HTTP ${res.status}`);
      const body = new Uint8Array(await res.arrayBuffer());
      if (body.length > MAX_TILE_BYTES || body.length % 32 !== 0 || body.length < width * 32) {
        throw new Error(`tessera ${url}: unexpected tile size ${body.length}`);
      }
      return body;
    }
    throw new Error(`tessera tile ${full} not found`);
  }

  /** Tiles for `treeSize`, after checking the size is covered and, for the latest size, that they hash to the checkpoint. */
  async function reader(treeSize: number): Promise<SubtreeHash> {
    const cp = await checkpoint();
    if (!Number.isSafeInteger(treeSize) || treeSize < 1 || treeSize > cp.treeSize) {
      throw new RangeError('tree size outside the log');
    }
    const sub = tileReader(treeSize);
    if (treeSize === cp.treeSize && hex32(await treeRoot(sub, treeSize)) !== cp.rootHash) {
      throw new Error('tessera tiles do not hash to the checkpoint root');
    }
    return sub;
  }

  return {
    async add(leaf) {
      const res = await doFetch(`${base}/add`, { method: 'POST', body: leaf });
      const text = await res.text();
      if (!res.ok || !/^(0|[1-9][0-9]*)$/.test(text))
        throw new Error(`tessera /add: HTTP ${res.status} ${text.slice(0, 100)}`);
      const index = Number(text);
      // Wait until a checkpoint covers the entry, so that proofs for it exist when we return.
      const deadline = Date.now() + timeoutMs;
      while ((await checkpoint()).treeSize <= index) {
        if (Date.now() > deadline) throw new Error(`tessera: entry ${index} not integrated within ${timeoutMs} ms`);
        await sleep(pollMs);
      }
      return { index };
    },
    checkpoint,
    async inclusionProof(index, treeSize) {
      return (await inclusionPath(await reader(treeSize), index, treeSize)).map(hex32);
    },
    async consistencyProof(fromSize, toSize) {
      return (await consistencyPath(await reader(toSize), fromSize, toSize)).map(hex32);
    },
  };
}
