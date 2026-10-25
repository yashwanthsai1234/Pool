// Stores a verified proof's trust record in zk_proof (through @legx/db) and the recorded loader files in the object
// store (through @legx/storage), and re-verifies a stored record offline (DESIGN 6.10 "Offline re-verification").
// The table never holds passport data: the proof is the public proof set (core publicProofSet) and the identifier is
// stored only as C_side, so the salt is needed to write a row.
import type { ObjectStorePort } from '@legx/contracts/ports';
import type { ZkVerification, ZkVerifyRequest } from '@legx/contracts/records';
import type { Profile } from '@legx/core/attest';
import { checkZkResult, type ZkExpectation, zkIdentityCommitment } from '@legx/core/zkIdentity';
import type { Database } from '@legx/db';
import { proofSetBytes, type RecordedLoaders, type ReverifyCode, reverifyOffline } from '@legx/zk/verify';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import type { ZkAdapter } from './adapter.ts';
import { ZkVerifierError } from './errors.ts';

/** Evidence retention for the recorded files: the longest dispute window (DESIGN 8.6 uses 10 years for evidence). */
const RETAIN_DAYS = 3650;

export interface StoreDeps {
  readonly adapter: ZkAdapter;
  readonly db: Database;
  readonly objects: ObjectStorePort;
}

export interface StoreInput {
  readonly dealId: string;
  readonly side: 'A' | 'B';
  readonly request: ZkVerifyRequest;
  /** What the deal data requires (stage, bound value, profile, CancelAfter or the sealed identity). */
  readonly expect: ZkExpectation;
  /** The client's zkSalt32, from the lawyer's encrypted copy only; it is never stored or logged here. */
  readonly salt: Uint8Array;
}

/** Content-addressed: the key holds the SHA-256, and the store returns the hash it recorded. */
async function put(objects: ObjectStorePort, prefix: string, text: string): Promise<string> {
  const bytes = utf8ToBytes(text);
  const r = await objects.put(`${prefix}/${bytesToHex(sha256(bytes))}`, bytes, RETAIN_DAYS);
  if (r.status === 'conflict') throw new ZkVerifierError('ZK_STORE_FAILED', `${prefix} exists with other bytes`);
  return r.sha256;
}

/**
 * Verifies, runs core's result checks, writes the files and the row. Nothing is stored unless every check passed;
 * a missing trust field fails here (core: TRUST_RECORD_INCOMPLETE) and again at the table (ZkTrustRecord is strict).
 */
export async function verifyAndStore(d: StoreDeps, i: StoreInput): Promise<{ verification: ZkVerification }> {
  const { set, verification, loaders, bodies } = await d.adapter.verifyDetailed(i.request);
  const checked = checkZkResult(verification, i.request.originalQuery, i.expect);
  if (!checked.ok) throw new ZkVerifierError('ZK_NOT_VERIFIED', 'the proof was refused', checked.code);
  const files: Record<string, string> = {};
  for (const [key, body] of bodies) files[key] = await put(d.objects, 'zk/files', body);
  files.loaders = await put(d.objects, 'zk/loaders', JSON.stringify(loaders));
  const t = verification.trust;
  await d.db.repos.zkProofs.insert({
    deal_id: i.dealId,
    side: i.side,
    stage: i.request.stage,
    proof: proofSetBytes(set.proofs),
    registry_roots: {
      chain_id: t.chainId,
      block_number: t.blockNumber,
      block_hash: t.blockHash,
      registry_address: t.registryAddress,
      root: t.root,
      circuit_manifest_version: t.circuitManifestVersion,
      vkey_hashes: t.vkeyHashes,
      identifier_type: verification.uniqueIdentifierType,
      dev_mode: t.devMode,
      loader_files: files,
    },
    identifier_hash: bytesToHex(zkIdentityCommitment(i.salt, checked.identifier)),
  });
  return { verification };
}

/**
 * Re-verifies a stored record from the object store with the network blocked: the recorded loaders and file bodies
 * are read back (each checked against the recorded hash), then core and the SDK re-check. The caller supplies the
 * proof set (the bundle's evidence), because the row holds only its public bytes.
 */
export async function reverifyStored(
  objects: ObjectStorePort,
  row: { verification: ZkVerification; loader_files: Readonly<Record<string, string>> },
  set: Parameters<typeof reverifyOffline>[0],
  profile: Profile,
  now?: number,
): Promise<{ ok: true } | { ok: false; code: ReverifyCode | 'FILE_MISSING' }> {
  const read = async (prefix: string, hash: string) => {
    const b = await objects.get(`${prefix}/${hash}`);
    return b && bytesToHex(sha256(b)) === hash ? new TextDecoder().decode(b) : undefined;
  };
  const loadersText = await read('zk/loaders', row.loader_files.loaders ?? '');
  if (loadersText === undefined) return { ok: false, code: 'FILE_MISSING' };
  const bodies = new Map<string, string>();
  for (const [key, hash] of Object.entries(row.loader_files)) {
    if (key === 'loaders') continue;
    const body = await read('zk/files', hash);
    if (body === undefined) return { ok: false, code: 'FILE_MISSING' };
    bodies.set(key, body);
  }
  const r = await reverifyOffline(
    set,
    row.verification,
    JSON.parse(loadersText) as RecordedLoaders,
    bodies,
    profile,
    now,
  );
  return r.ok ? { ok: true } : r;
}
