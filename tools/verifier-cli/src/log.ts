// DESIGN 8.8 items 3 to 7: the events and their chain, the transparency log (inclusion, consistency, the hybrid
// checkpoint), the ledger anchor and the RFC 3161 time stamps. Everything is checked from the files in the bundle.
// Source: https://www.rfc-editor.org/rfc/rfc9162#section-2.1 (inclusion and consistency proofs)
// Source: https://github.com/C2SP/C2SP/blob/main/tlog-proof.md (the `.tlog-proof` file)
// Source: https://www.rfc-editor.org/rfc/rfc3161 (time-stamp tokens)
import { verifyInclusion } from '@legx/core/dealcore';
import { type ChainEntry, entryLink, leafHashOf, ZERO } from '@legx/core/evidence';
import { type KeyRegistry, type RegisteredKey, verifyHybrid } from '@legx/core/hybridEnvelope';
import { verifyConsistency } from '@legx/core/merkle';
import { fromBase64Strict } from '@legx/core/pq';
import { type CheckpointKeys, verifyCheckpoint, vkey } from '@legx/core/pqCheckpoint';
import { verifyTimestampToken } from '@legx/evidence/tsa';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { type BundleFiles, b64, isObj } from './files.ts';
import type { ServiceKeys } from './integrity.ts';
import type { Findings } from './report.ts';

const RIPPLE_EPOCH_OFFSET = 946_684_800;
const HEX64 = /^[0-9a-f]{64}$/;
const utf8 = new TextEncoder();

// ---------- keys ----------

/** The registry the hybrid verifier needs: the deal's enrollment keys and the service keys, from keys/. */
export function registryFromBundle(files: BundleFiles, service: ServiceKeys | undefined): KeyRegistry {
  const map = new Map<string, RegisteredKey>();
  const rows = files.json('keys/enrollment_keys.json');
  for (const r of Array.isArray(rows) ? rows : []) {
    if (
      !isObj(r) ||
      typeof r.key_id !== 'string' ||
      typeof r.ed25519_pub !== 'string' ||
      typeof r.valid_from !== 'number'
    )
      continue;
    const mldsa = b64(r.mldsa65_pub);
    const window = {
      validFrom: r.valid_from,
      ...(typeof r.valid_to === 'number' ? { validTo: r.valid_to } : {}),
      logged: true,
      pair: r.key_id,
    };
    // One key-id convention across the services (I-3.7-e): `<pair>#ed25519` and `<pair>#ml-dsa-65`; bundles written
    // before it used `<pair>` and `<pair>:pq`, so both are read.
    if (/^[0-9a-f]{64}$/.test(r.ed25519_pub)) {
      const ed: RegisteredKey = { alg: 'ed25519', publicKey: hexToBytes(r.ed25519_pub), ...window };
      map.set(r.key_id, ed);
      map.set(`${r.key_id}#ed25519`, ed);
    }
    if (mldsa) {
      const pq: RegisteredKey = { alg: 'ml-dsa-65', publicKey: mldsa, ...window };
      map.set(`${r.key_id}:pq`, pq);
      map.set(`${r.key_id}#ml-dsa-65`, pq);
    }
  }
  if (service) {
    map.set(service.ed.keyId, {
      alg: 'ed25519',
      publicKey: service.ed.publicKey,
      validFrom: 0,
      logged: true,
      pair: `service:${service.ed.keyId}`,
    });
    map.set(service.pq.keyId, {
      alg: 'ml-dsa-65',
      publicKey: service.pq.publicKey,
      validFrom: 0,
      logged: true,
      pair: `service:${service.ed.keyId}`,
    });
  }
  return (id) => map.get(id);
}

/** When the signer says the event happened, in Ripple epoch seconds; the event is in a time-stamped log, so this is bounded. */
function claimedTime(bytes: Uint8Array): number {
  try {
    const env = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    const body = JSON.parse(new TextDecoder().decode(fromBase64Strict(env.payload)));
    return Math.floor(Date.parse(body.predicate.occurred_at) / 1000) - RIPPLE_EPOCH_OFFSET;
  } catch {
    return 0;
  }
}

// ---------- events: both signatures, the chain ----------

/** The latest time any event claims; keys of attestations are judged at this time. */
export const latestClaimedTime = (events: readonly { readonly bytes: Uint8Array }[]): number =>
  Math.max(0, ...events.map((e) => claimedTime(e.bytes)));

export interface EventFile {
  readonly path: string;
  readonly bytes: Uint8Array;
}

export function checkEvents(files: BundleFiles, registry: KeyRegistry, out: Findings): EventFile[] {
  const events = files.under('events/', '.dsse.json').map((path) => ({ path, bytes: files.bytes(path) as Uint8Array }));
  if (events.length === 0) {
    out.fail('chain', 'events/', 'the bundle holds no events');
    return events;
  }
  let prev = ZERO;
  for (const [i, e] of events.entries()) {
    const entry: ChainEntry = { envelopeBytes: e.bytes, leafHash: leafHashOf(e.bytes) };
    const link = entryLink(entry);
    const sig = link ? verifyHybrid(link.env, registry, claimedTime(e.bytes)) : undefined;
    if (sig?.ok) out.pass('hybrid-signature', e.path, 'Ed25519 and ML-DSA-65 signatures both verify');
    else out.fail('hybrid-signature', e.path, sig ? `signature check failed: ${sig.code}` : 'not a valid envelope');
    const name = `events/${String(i).padStart(6, '0')}.dsse.json`;
    if (link && link.seq === i && link.prevHash === prev && e.path === name)
      out.pass('chain', e.path, `seq ${i} continues the hash chain`);
    else out.fail('chain', e.path, 'seq, prev_hash or file name does not continue the chain');
    prev = entry.leafHash;
  }
  return events;
}

// ---------- the checkpoint (both lines) ----------

export interface Checkpoint {
  readonly note: string;
  readonly origin: string;
  readonly treeSize: number;
  readonly root: string;
}

export function checkCheckpoint(files: BundleFiles, out: Findings): Checkpoint | undefined {
  const FILE = 'tlog/checkpoint.txt';
  const note = files.text(FILE);
  const k = files.json('keys/checkpoint_keys.json');
  if (note === undefined) {
    out.skip('checkpoint', FILE, 'no checkpoint in the bundle: nothing is anchored yet');
    return undefined;
  }
  if (!isObj(k) || typeof k.origin !== 'string' || !isObj(k.ed) || !isObj(k.pq)) {
    out.fail('checkpoint', 'keys/checkpoint_keys.json', 'missing or malformed checkpoint keys');
    return undefined;
  }
  const edPub =
    typeof k.ed.public_key === 'string' && HEX64.test(k.ed.public_key) ? hexToBytes(k.ed.public_key) : undefined;
  const pqPub = b64(k.pq.public_key);
  if (!edPub || !pqPub || typeof k.ed.name !== 'string' || typeof k.pq.name !== 'string') {
    out.fail('checkpoint', 'keys/checkpoint_keys.json', 'malformed checkpoint key');
    return undefined;
  }
  const keys: CheckpointKeys = { ed: { name: k.ed.name, publicKey: edPub }, pq: { name: k.pq.name, publicKey: pqPub } };
  if (k.ed.vkey !== vkey(keys.ed.name, 0x01, edPub) || k.pq.vkey !== vkey(keys.pq.name, 0x06, pqPub)) {
    out.fail('checkpoint', 'keys/checkpoint_keys.json', 'a recorded vkey does not match its public key');
    return undefined;
  }
  const r = verifyCheckpoint(note, k.origin, keys);
  if (!r.ok) {
    const which =
      r.code === 'ED_LINE_MISSING'
        ? 'the Ed25519 (0x01) line is missing'
        : r.code === 'PQ_LINE_MISSING'
          ? 'the ML-DSA-44 (0x06) line is missing'
          : r.code;
    out.fail('checkpoint', FILE, `hybrid checkpoint refused: ${which}`);
    return undefined;
  }
  out.pass('checkpoint', FILE, `both lines verify (Ed25519 0x01 and ML-DSA-44 0x06), tree size ${r.treeSize}`);
  return { note, origin: r.origin, treeSize: r.treeSize, root: bytesToHex(r.rootHash) };
}

// ---------- inclusion proofs and consistency ----------

function parseTlogProof(text: string): { index: number; path: Uint8Array[]; note: string } | undefined {
  const lines = text.split('\n');
  if (lines[0] !== 'c2sp.org/tlog-proof@v1') return undefined;
  const m = /^index (0|[1-9][0-9]*)$/.exec(lines[1] ?? '');
  if (!m) return undefined;
  const path: Uint8Array[] = [];
  let i = 2;
  for (; i < lines.length && lines[i] !== ''; i++) {
    const h = fromBase64Strict(lines[i] as string);
    if (h?.length !== 32) return undefined;
    path.push(h);
  }
  if (lines[i] !== '') return undefined;
  return { index: Number(m[1]), path, note: lines.slice(i + 1).join('\n') };
}

export function checkInclusion(
  files: BundleFiles,
  events: readonly EventFile[],
  cp: Checkpoint | undefined,
  out: Findings,
): void {
  const proofs = new Set(files.under('tlog/proofs/', '.tlog-proof'));
  for (const e of events) {
    const name = `tlog/proofs/${e.path.slice('events/'.length, -'.dsse.json'.length)}.tlog-proof`;
    const text = files.text(name);
    if (text === undefined) {
      out.fail('merkle-proof', e.path, 'no inclusion proof: the event is not covered by the anchored checkpoint');
      continue;
    }
    proofs.delete(name);
    const p = parseTlogProof(text);
    if (!p || !cp) {
      out.fail('merkle-proof', name, p ? 'there is no valid checkpoint to check against' : 'not a tlog-proof file');
    } else if (p.note !== cp.note) {
      out.fail('merkle-proof', name, 'the proof carries a different checkpoint than tlog/checkpoint.txt');
    } else if (!verifyInclusion(e.bytes, p.index, cp.treeSize, p.path, hexToBytes(cp.root))) {
      out.fail('merkle-proof', name, 'the inclusion path does not lead to the checkpoint root');
    } else out.pass('merkle-proof', name, `leaf ${p.index} is in the tree of ${cp.treeSize}`);
  }
  for (const stray of proofs) out.fail('merkle-proof', stray, 'a proof for an event that is not in the bundle');
}

export function checkConsistency(files: BundleFiles, cp: Checkpoint | undefined, out: Findings): void {
  const FILE = 'tlog/consistency.json';
  const c = files.json(FILE);
  if (!isObj(c)) {
    if (cp) out.warn('consistency', FILE, 'no consistency proof in the bundle');
    else out.skip('consistency', FILE, 'no checkpoint, so nothing to be consistent with');
    return;
  }
  const path = Array.isArray(c.path)
    ? c.path.map((h) => (typeof h === 'string' && HEX64.test(h) ? hexToBytes(h) : undefined))
    : undefined;
  const ok =
    cp !== undefined &&
    typeof c.from_size === 'number' &&
    typeof c.from_root === 'string' &&
    HEX64.test(c.from_root) &&
    c.to_size === cp.treeSize &&
    c.to_root === cp.root &&
    path !== undefined &&
    !path.includes(undefined) &&
    verifyConsistency(c.from_size, cp.treeSize, hexToBytes(c.from_root), hexToBytes(cp.root), path as Uint8Array[]);
  if (ok)
    out.pass('consistency', FILE, `the tree of ${c.from_size} is a prefix of the checkpoint tree of ${cp?.treeSize}`);
  else out.fail('consistency', FILE, 'the consistency proof does not connect the earlier tree to the checkpoint root');
}

// ---------- the ledger anchor ----------

/** The 72-byte memo: SHA-256(origin) || tree size (8 bytes, big endian) || root. Source: DESIGN 8.3 */
function anchorMemo(tx: unknown): { originHash: string; treeSize: number; root: string } | undefined {
  if (!isObj(tx) || tx.TransactionType !== 'AccountSet' || !Array.isArray(tx.Memos)) return undefined;
  const memo = isObj(tx.Memos[0]) && isObj(tx.Memos[0].Memo) ? tx.Memos[0].Memo : undefined;
  if (!memo || memo.MemoType !== bytesToHex(utf8.encode('legx/ckpt/v1')).toUpperCase()) return undefined;
  if (typeof memo.MemoData !== 'string' || !/^[0-9A-Fa-f]{144}$/.test(memo.MemoData)) return undefined;
  const data = hexToBytes(memo.MemoData.toLowerCase());
  return {
    originHash: bytesToHex(data.subarray(0, 32)),
    treeSize: Number(new DataView(data.buffer, data.byteOffset + 32, 8).getBigUint64(0)),
    root: bytesToHex(data.subarray(40, 72)),
  };
}

export function checkAnchors(files: BundleFiles, cp: Checkpoint | undefined, out: Findings): undefined {
  const FILE = 'anchors/anchor.json';
  const a = files.json(FILE);
  if (!isObj(a)) {
    out.skip('anchor', FILE, 'no anchor record in the bundle');
    return;
  }
  if (!cp) return out.fail('anchor', FILE, 'there is no valid checkpoint to compare with');
  if (a.tree_size !== cp.treeSize || a.root !== cp.root)
    return out.fail('anchor', FILE, 'the anchor record names another tree size or root than the checkpoint');
  if (a.anchored !== true) return out.warn('anchor', FILE, 'the checkpoint is not anchored on the ledger yet');
  const servers = files.under('anchors/', '.json').filter((p) => p !== FILE);
  if (servers.length < 2) out.warn('anchor', FILE, 'raw ledger JSON from fewer than two independent servers');
  const answers: string[] = [];
  for (const path of servers) {
    const s = files.json(path);
    const found = isObj(s) && s.found === true && isObj(s.tx) ? s.tx : undefined;
    if (!found || !isObj(found.tx)) {
      out.fail('anchor', path, 'the server did not return the anchor transaction');
      continue;
    }
    const memo = anchorMemo(found.tx);
    const meta = isObj(found.meta) ? found.meta : {};
    const reason =
      found.hash !== a.tx_hash && found.tx.hash !== a.tx_hash
        ? 'the transaction hash is not the anchored one'
        : found.ledgerIndex !== a.ledger_index
          ? 'validated in another ledger than the anchor record says'
          : meta.TransactionResult !== 'tesSUCCESS'
            ? 'the transaction did not succeed'
            : !memo || memo.treeSize !== cp.treeSize || memo.root !== cp.root
              ? 'the memo does not carry this checkpoint'
              : memo.originHash !== bytesToHex(sha256(utf8.encode(cp.origin)))
                ? 'the memo names another log origin'
                : undefined;
    if (reason) out.fail('anchor', path, reason);
    else {
      out.pass('anchor', path, `ledger ${a.ledger_index} carries the checkpoint (tree size ${cp.treeSize})`);
      answers.push(JSON.stringify([found.tx, isObj(s) ? s.ledger : undefined]));
    }
  }
  if (new Set(answers).size > 1)
    out.fail('anchor', 'anchors/', 'the two servers disagree about the anchor transaction or its ledger');
}

// ---------- time stamps ----------

export function pemCerts(text: string): Uint8Array[] {
  return [...text.matchAll(/-----BEGIN CERTIFICATE-----([^-]+)-----END CERTIFICATE-----/g)].map(
    (m) => new Uint8Array(Buffer.from((m[1] as string).replace(/\s+/g, ''), 'base64')),
  );
}

export async function checkTimestamps(
  files: BundleFiles,
  cp: Checkpoint | undefined,
  roots: readonly Uint8Array[],
  out: Findings,
): Promise<undefined> {
  const tokens = files.under('timestamps/', '.tst');
  if (tokens.length === 0) return out.warn('timestamp', 'timestamps/', 'no RFC 3161 token yet (time stamp pending)');
  if (!cp || roots.length === 0)
    return out.fail(
      'timestamp',
      'timestamps/',
      'tokens present but no checkpoint or no trusted TSA roots to check them against',
    );
  let valid = 0;
  for (const path of tokens) {
    const token = files.bytes(path) as Uint8Array;
    const r = await verifyTimestampToken(token, sha256(utf8.encode(cp.note)), roots);
    if (r.ok) {
      valid++;
      out.pass('timestamp', path, `time stamp of the checkpoint at ${r.genTime.toISOString()}, signed by ${r.signer}`);
    } else out.fail('timestamp', path, `token refused: ${r.code}`);
  }
  if (valid === 1) out.warn('timestamp', 'timestamps/', 'only one authority stamped the checkpoint (two are expected)');
}
