// DESIGN 8.8 items 2, 8 to 10: the contract and clause proofs, the trust profile of the zero-knowledge records, the
// offline re-verification of each zero-knowledge proof from the recorded registry answer and circuit files, and a rerun
// of the release gate (`checkRelease`) on the recorded input. The gate covers the signed contract, the operations
// bindings, the bar records, the credentials and the passport and onboarding attestations.
// Source: DESIGN.md 6.10 (offline re-verification), 6.17 (the 15 gate codes), 8.8
import { existsSync } from 'node:fs';
import { checkTrustRecord, type Profile } from '@legx/core/attest';
import { verifyClause } from '@legx/core/contract';
import type { Envelope } from '@legx/core/evidence';
import { type KeyRegistry, verifyHybrid } from '@legx/core/hybridEnvelope';
import { fromBase64Strict } from '@legx/core/pq';
import { checkRelease, type ReleaseInput } from '@legx/core/releaseGate';
import { type ProofSet, type RecordedLoaders, reverifyOffline } from '@legx/zk/verify';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { type BundleFiles, isObj, type Json } from './files.ts';
import type { Findings } from './report.ts';

const HEX = /^([0-9a-f]{2})*$/;

// ---------- the contract ----------

export function checkContract(files: BundleFiles, clauseProofs: ReadonlyMap<string, Uint8Array>, out: Findings): void {
  const FILE = 'contract/contract.json';
  const c = files.json(FILE);
  if (!isObj(c) || typeof c.contract_root !== 'string' || !/^[0-9a-f]{64}$/.test(c.contract_root)) {
    out.fail('contract', FILE, 'missing or malformed contract record');
    return;
  }
  const recorded = isObj(c.files) ? c.files : {};
  for (const [name, hash] of Object.entries(recorded)) {
    const b = files.bytes(`contract/files/${name}`);
    if (b && bytesToHex(sha256(b)) === hash)
      out.pass('contract', `contract/files/${name}`, 'matches the hash in contract.json');
    else
      out.fail('contract', `contract/files/${name}`, 'differs from, or is missing against, the hash in contract.json');
  }
  const proofs = new Map<string, Uint8Array>(clauseProofs);
  for (const p of files.under('contract/files/', '.clause-proof.json')) proofs.set(p, files.bytes(p) as Uint8Array);
  for (const [path, bytes] of proofs) checkClauseProof(path, bytes, hexToBytes(c.contract_root), out);
  if (proofs.size === 0)
    out.skip('clause-proof', 'contract/', 'no clause proof chosen by a party; pass one with --clause');
}

/** `{index, size, salt (hex), clause (base64), path (hex[])}`: one clause against the contract root (DESIGN 4, W1). */
function checkClauseProof(path: string, bytes: Uint8Array, root: Uint8Array, out: Findings): undefined {
  try {
    const j = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as Json;
    const clause = typeof j.clause === 'string' ? fromBase64Strict(j.clause) : undefined;
    const hex = (x: unknown) => (typeof x === 'string' && HEX.test(x) ? hexToBytes(x) : undefined);
    const salt = hex(j.salt);
    const route = Array.isArray(j.path) ? j.path.map(hex) : undefined;
    if (
      !clause ||
      salt?.length !== 32 ||
      !route ||
      route.includes(undefined) ||
      !Number.isInteger(j.index) ||
      !Number.isInteger(j.size)
    ) {
      return out.fail('clause-proof', path, 'malformed clause proof');
    }
    const ok = verifyClause(
      { index: j.index as number, size: j.size as number, salt, clause, path: route as Uint8Array[] },
      root,
    );
    if (ok) out.pass('clause-proof', path, `clause ${j.index} is under the contract root`);
    else out.fail('clause-proof', path, 'the clause does not lead to the contract root');
  } catch {
    out.fail('clause-proof', path, 'malformed clause proof');
  }
}

// ---------- signed attestations and gate records ----------

/** Attestation and gate-record envelopes carry the hybrid signatures of enrolled keys (DESIGN 6.15, 6.17). */
export function checkRecordSignatures(files: BundleFiles, registry: KeyRegistry, at: number, out: Findings): void {
  for (const path of [...files.under('attestations/', '.dsse.json'), ...files.under('release/gate/', '.dsse.json')]) {
    const r = verifyHybrid(files.json(path) as Envelope, registry, at);
    if (r.ok) out.pass('attestation', path, 'both signatures verify');
    else out.fail('attestation', path, `signature check failed: ${r.code}`);
  }
}

// ---------- zero-knowledge records ----------

export function checkTrust(files: BundleFiles, profile: Profile, out: Findings): undefined {
  const FILE = 'zk/trust_records.json';
  const rows = files.json(FILE);
  if (!Array.isArray(rows))
    return out.skip('trust-profile', FILE, 'no zero-knowledge records (chip method or none yet)');
  for (const r of rows) {
    const name = isObj(r) ? `${String(r.side)}-${String(r.stage)}` : '?';
    const roots = isObj(r) && isObj(r.registry_roots) ? r.registry_roots : undefined;
    const trust = roots && Object.fromEntries(Object.entries(roots).filter(([k]) => k !== 'loader_files'));
    const production = checkTrustRecord(trust, 'production');
    if (production.ok) out.pass('trust-profile', FILE, `${name}: no Sepolia, no mock identifier, no dev mode`);
    else if (profile === 'demo' && production.code !== 'ZK_RECORD_INCOMPLETE') {
      out.warn(
        'trust-profile',
        FILE,
        `${name}: ${production.code}; accepted only because this is demo mode, never for production`,
      );
    } else out.fail('trust-profile', FILE, `${name}: refused in ${profile} mode: ${production.code}`);
  }
}

interface ReverifyFile {
  readonly set: ProofSet;
  readonly verification: Parameters<typeof reverifyOffline>[1];
  readonly loaders: RecordedLoaders;
  readonly bodies: Record<string, string>;
}

/**
 * Proofs are verified by barretenberg, a native `bb` program (about 20 MB) that cannot be inside a JavaScript file. From
 * the source tree the library finds its own copy. In the one-file build (`LEGX_BUNDLED`, set by scripts/bundle.ts) the
 * arbitrator points `--bb` (or BB_BINARY_PATH) at the `bb` that comes with the bundle, or the proofs are "not verified".
 */
function backendMissing(): string | undefined {
  if (process.env.LEGX_BUNDLED !== '1') return undefined;
  const path = process.env.BB_BINARY_PATH;
  return path && existsSync(path)
    ? undefined
    : 'the barretenberg program is not available: pass --bb <path to bb> (proofs are not re-verified)';
}

/** The recorded loaders of a proof: `zk/reverify/<side>-<stage>.json`, replayed with `fetch` and sockets never used. */
export async function checkZk(files: BundleFiles, profile: Profile, out: Findings): Promise<ReverifyFile[]> {
  const found: ReverifyFile[] = [];
  const proofs = files.under('zk/proofs/', '.json');
  if (proofs.length === 0) {
    out.skip('zk-proof', 'zk/proofs/', 'no zero-knowledge proofs in the bundle');
    return found;
  }
  for (const p of proofs) {
    const name = p.slice('zk/proofs/'.length, -'.json'.length);
    const path = `zk/reverify/${name}.json`;
    const f = files.json(path) as Partial<ReverifyFile> | undefined;
    if (!isObj(f) || !f.set || !f.verification || !f.loaders || !isObj(f.bodies)) {
      out.skip(
        'zk-proof',
        path,
        'the recorded registry answer and circuit files are not in the bundle: proof not re-verified',
      );
      continue;
    }
    const missing = backendMissing();
    if (missing) {
      out.skip('zk-proof', path, missing);
      continue;
    }
    const bodies = new Map(Object.entries(f.bodies as Record<string, string>));
    const hashes = (f.loaders as RecordedLoaders).files ?? {};
    const mismatch = Object.entries(hashes).find(([k, h]) => {
      const body = bodies.get(k);
      return body === undefined || bytesToHex(sha256(new TextEncoder().encode(body))) !== h;
    });
    if (mismatch) {
      out.fail('zk-proof', path, `recorded file ${mismatch[0]} is missing or differs from its recorded hash`);
      continue;
    }
    // Replay on the day it was recorded: the SDK counts whole days from "today" (packages/zk verify.ts).
    const r = await reverifyOffline(f.set, f.verification, f.loaders, bodies, profile, f.loaders.verifiedDay * 1000);
    if (r.ok) out.pass('zk-proof', path, 'verified = true from the recorded registry answer and circuit files');
    else out.fail('zk-proof', path, `not verified: ${r.code}`);
    found.push(f as ReverifyFile);
  }
  return found;
}

// ---------- the release gate ----------

const GATE_CHECK: Record<string, string> = {
  CONTRACT_SEAL_OK: 'signed-contract',
  OPS_BINDINGS_OK: 'bindings',
  BAR_A_OK: 'bar-records',
  BAR_B_OK: 'bar-records',
  ATTORNEY_CREDENTIAL_A_OK: 'bar-records',
  ATTORNEY_CREDENTIAL_B_OK: 'bar-records',
  PASSPORT_A_OK: 'attestations',
  PASSPORT_B_OK: 'attestations',
  ONBOARDING_OK: 'attestations',
  IDS_DISTINCT: 'attestations',
  IDENTITY_POLICY_OK: 'attestations',
};

/** Bytes travel in the gate input as `{"$bytes": "<base64>"}`. */
function revive(x: unknown): unknown {
  if (Array.isArray(x)) return x.map(revive);
  if (isObj(x)) {
    if (typeof x.$bytes === 'string' && Object.keys(x).length === 1) {
      const b = fromBase64Strict(x.$bytes);
      if (!b) throw new Error('bad bytes');
      return b;
    }
    return Object.fromEntries(Object.entries(x).map(([k, v]) => [k, revive(v)]));
  }
  return x;
}

export function checkGate(files: BundleFiles, profile: Profile, out: Findings): void {
  const FILE = 'release/gate-input.json';
  const raw = files.json(FILE);
  const gates = files.under('release/gate/', '.dsse.json');
  if (raw === undefined) {
    const why =
      gates.length > 0
        ? 'a release gate record is present but its input is not in the bundle'
        : 'the release gate has not run for this deal';
    for (const c of ['signed-contract', 'bindings', 'bar-records', 'attestations', 'release-gate'])
      out.skip(c, FILE, `${why}: not verified`);
    return;
  }
  let input: ReleaseInput;
  try {
    input = { ...(revive(raw) as ReleaseInput), profile };
  } catch {
    out.fail('release-gate', FILE, 'the recorded gate input is malformed');
    return;
  }
  for (const f of checkRelease(input)) {
    const check = GATE_CHECK[f.code] ?? 'release-gate';
    if (f.ok) out.pass(check, FILE, `${f.code}`);
    else out.fail(check, FILE, `${f.code}: ${f.detail ?? 'refused'}`);
  }
}

// ---------- the optional chain check (the one online step) ----------

/** Compares each recorded registry answer with a live node. Separate, labelled, and only on request (DESIGN 8.8, 6.10). */
export async function chainCheck(reverify: readonly ReverifyFile[], rpcUrl: string, out: Findings): Promise<void> {
  const CHECK = 'chain-check (ONLINE, optional)';
  if (reverify.length === 0) return out.skip(CHECK, rpcUrl, 'no recorded registry answers to compare');
  for (const r of reverify) {
    for (const call of r.loaders.rpc) {
      try {
        const res = await fetch(rpcUrl, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'eth_call',
            params: [{ to: call.to, data: call.data }, `0x${r.loaders.block.number.toString(16)}`],
          }),
        });
        const body = (await res.json()) as { result?: string };
        if (body.result === call.result)
          out.pass(CHECK, rpcUrl, `${call.to} answers as recorded at block ${r.loaders.block.number}`);
        else out.fail(CHECK, rpcUrl, `${call.to} answers differently from the record`);
      } catch (e) {
        out.fail(CHECK, rpcUrl, `could not ask the node: ${(e as Error).message}`);
      }
    }
  }
}
