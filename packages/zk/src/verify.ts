// ZKPassport verification with a recorded trust record, and offline re-verification from the recorded registry
// answer and circuit files (DESIGN 6.10 "Trust anchors" and "Offline re-verification"; IMPLEMENTATION T-U-32).
// Source: @zkpassport/sdk 0.19.2 `verify({ config })`, whose config reaches createRegistryClient(chain, config)
// (rpcUrl, circuitManifestUrlGenerator, packagedCircuitUrlGenerator, ...: @zkpassport/registry 0.15.3 typings), and
// https://github.com/zkpassport/zkpassport-packages/blob/a61b0cf461f1fab10e1b838dacd81e862107acb0/packages/registry-sdk/src/client.ts
// (isRootValid: eth_call of isRootValid(bytes32 registryId, bytes32 root, uint256 timestamp) = 0x2aae4296).

import type { ZkVerification } from '@legx/contracts/records';
import { checkTrustRecord, type Profile, type TrustCode } from '@legx/core/attest';
import { publicProofSet, trustRecordOf } from '@legx/core/zkIdentity';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { NullifierType, type ProofResult, type Query, type QueryResult, ZKPassport } from './sdk.ts';

/** What our request code stores with the proofs: the SDK result has no scope or domain (DESIGN 6.10). */
export interface ZkRequestRecord {
  readonly stage: 'onboarding' | 'release';
  readonly domain: string;
  readonly scope: string;
  readonly devMode: boolean;
  readonly validity: number;
  readonly originalQuery: Query;
}

/** The registry answers and circuit files one verification read, pinned to one block. */
export interface RecordedLoaders {
  readonly chainId: number;
  readonly block: { readonly number: number; readonly hash: string };
  readonly rpc: readonly { readonly to: string; readonly data: string; readonly result: string }[];
  /** `manifest/<version>` or `circuit/<vkey hash>` -> SHA-256 of the file body. */
  readonly files: Readonly<Record<string, string>>;
  /** Local midnight (unix seconds) on the verifying machine; the SDK's date check counts whole days from it. */
  readonly verifiedDay: number;
}

/** File bodies by key (`manifest/<version>`, `circuit/<hash>`). */
export type FileBodies = ReadonlyMap<string, string>;

export interface ProofSet {
  readonly request: ZkRequestRecord;
  readonly proofs: readonly ProofResult[];
  readonly queryResult: QueryResult;
}

export type ReverifyCode =
  | `TRUST_MISMATCH:${'chain_id' | 'block' | 'registry_address' | 'root' | 'circuit_manifest_version' | 'vkey_hashes' | 'circuit_files'}`
  | 'PROOF_NOT_VERIFIED'
  | TrustCode;

const RPC_URL = 'http://rpc.legx-recorded.invalid/'; // RFC 2606 .invalid: never resolves
const FILES_URL = 'http://files.legx-recorded.invalid';
const IS_ROOT_VALID = '0x2aae4296';
const CERTIFICATE_REGISTRY_ID = 1n;

/**
 * The bytes of a proof set as the evidence log stores it, without the disclosed values (core publicProofSet);
 * `proofSha256` hashes these.
 */
export function proofSetBytes(proofs: readonly ProofResult[]): Uint8Array {
  return utf8ToBytes(JSON.stringify(publicProofSet(proofs)));
}

/** The file key of a ZKPassport CDN URL, or undefined for anything verify() should not fetch. */
function fileKey(url: string): string | undefined {
  const manifest = /\/by-version\/([0-9]+\.[0-9]+\.[0-9]+)\/manifest\.json$/.exec(url);
  if (manifest) return `manifest/${manifest[1]}`;
  const circuit = /\/by-hash\/(0x[0-9a-f]{64})\.json$/.exec(url);
  return circuit ? `circuit/${circuit[1]}` : undefined;
}

const urlOf = (input: unknown) => String((input as { url?: string })?.url ?? input);
const hex = (s: string) => bytesToHex(sha256(utf8ToBytes(s)));
const localMidnight = (ms: number) => {
  const d = new Date(ms);
  return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime() / 1000;
};

// verify() reads the registry and CDN through the global fetch, so one verification runs at a time.
let queue: Promise<unknown> = Promise.resolve();
function serialized<T>(f: () => Promise<T>): Promise<T> {
  const run = queue.then(f, f);
  queue = run.catch(() => undefined);
  return run;
}

async function withFetch<T>(fetcher: typeof fetch, f: () => Promise<T>): Promise<T> {
  const original = globalThis.fetch;
  globalThis.fetch = fetcher;
  try {
    return await f();
  } finally {
    globalThis.fetch = original;
  }
}

async function rpcCall(rpcUrl: string, method: string, params: unknown[], f: typeof fetch = fetch): Promise<unknown> {
  const res = await f(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const body = (await res.json()) as { result?: unknown; error?: { message: string } };
  if (body.error || body.result === undefined) throw new Error(`${method}: ${body.error?.message ?? 'no result'}`);
  return body.result;
}

/** The certificate registry root in a recorded isRootValid call, if it is one. */
function certificateRoot(data: string): string | undefined {
  if (!data.startsWith(IS_ROOT_VALID) || data.length !== 10 + 3 * 64) return undefined;
  if (BigInt(`0x${data.slice(10, 74)}`) !== CERTIFICATE_REGISTRY_ID) return undefined;
  return `0x${data.slice(74, 138)}`;
}

function sdkVerify(set: ProofSet, config: Record<string, unknown>, validity: number) {
  return new ZKPassport(set.request.domain).verify({
    proofs: [...set.proofs],
    originalQuery: set.request.originalQuery,
    queryResult: set.queryResult,
    scope: set.request.scope,
    devMode: set.request.devMode,
    verifierMode: 'local',
    validity,
    config,
  });
}

/** The SDK's errors as messages only: `expected` and `received` can hold disclosed values (DESIGN 8.7). */
function messagesOnly(errors: Record<string, Record<string, { message: string }>> | undefined) {
  const out: Record<string, Record<string, string>> = {};
  for (const [category, checks] of Object.entries(errors ?? {}))
    for (const [check, e] of Object.entries(checks)) {
      out[category] ??= {};
      (out[category] as Record<string, string>)[check] = e.message;
    }
  return out;
}

/**
 * Verifies a proof set through the SDK (`verifierMode: "local"`, our RPC, the pinned SDK) and records what it
 * read: the registry answers pinned to one block, the circuit manifest and the circuit files. The result is the
 * ZkVerifierPort result with its trust record (IMPLEMENTATION P1.2-08).
 */
export function verifyAndRecord(
  set: ProofSet,
  rpcUrl: string,
  now: number = Date.now(),
): Promise<{ verification: ZkVerification; loaders: RecordedLoaders; bodies: FileBodies }> {
  return serialized(async () => {
    const chainId = Number(await rpcCall(rpcUrl, 'eth_chainId', []));
    const block = (await rpcCall(rpcUrl, 'eth_getBlockByNumber', ['latest', false])) as {
      number: string;
      hash: string;
    };
    const rpc: { to: string; data: string; result: string }[] = [];
    const bodies = new Map<string, string>();
    const original = globalThis.fetch;
    const recorder: typeof fetch = async (input, init) => {
      const url = urlOf(input);
      if (init?.method === 'POST' && url === rpcUrl) {
        const req = JSON.parse(String(init.body)) as { method: string; params: [{ to: string; data: string }, string] };
        if (req.method !== 'eth_call') throw new Error(`unexpected RPC method ${req.method}`);
        const [call] = req.params;
        const result = (await rpcCall(rpcUrl, 'eth_call', [call, block.number], original)) as string; // pinned block
        rpc.push({ to: call.to.toLowerCase(), data: call.data.toLowerCase(), result });
        return Response.json({ jsonrpc: '2.0', id: (req as { id?: number }).id, result });
      }
      const key = fileKey(url);
      if (!key) throw new Error(`unexpected fetch during verification: ${url}`);
      const body = await (await original(input, init)).text();
      bodies.set(key, body);
      return new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });
    };
    const result = await withFetch(recorder, () => sdkVerify(set, { rpcUrl }, set.request.validity));
    const loaders: RecordedLoaders = {
      chainId,
      block: { number: Number(block.number), hash: block.hash },
      rpc,
      files: Object.fromEntries([...bodies].map(([k, v]) => [k, hex(v)]).sort()),
      verifiedDay: localMidnight(now),
    };
    return { verification: toVerification(set, result, loaders), loaders, bodies };
  });
}

export function toVerification(
  set: ProofSet,
  result: Awaited<ReturnType<typeof sdkVerify>>,
  loaders: RecordedLoaders,
): ZkVerification {
  const bind = set.proofs.find((p) => p.name === 'bind');
  const bound = (bind?.committedInputs as { bind?: { data?: { custom_data?: string } } } | undefined)?.bind?.data;
  const roots = loaders.rpc.map((c) => certificateRoot(c.data)).filter((r) => r !== undefined);
  const type = result.uniqueIdentifierType;
  return {
    verified: result.verified,
    uniqueIdentifier: result.uniqueIdentifier ?? null,
    uniqueIdentifierType: type === undefined ? null : (NullifierType[type] as ZkVerification['uniqueIdentifierType']),
    queryResultErrors: messagesOnly(result.queryResultErrors as never),
    proofSha256: bytesToHex(sha256(proofSetBytes(set.proofs))) as ZkVerification['proofSha256'],
    vkeyHash: (bind?.vkeyHash ?? '') as ZkVerification['vkeyHash'],
    version: set.proofs[0]?.version ?? '',
    committedInputs: { custom_data: bound?.custom_data ?? '' },
    scope: set.request.scope,
    domain: set.request.domain,
    trust: {
      chainId: loaders.chainId,
      blockNumber: loaders.block.number,
      blockHash: loaders.block.hash as ZkVerification['trust']['blockHash'],
      registryAddress: (loaders.rpc[0]?.to ?? '') as ZkVerification['trust']['registryAddress'],
      root: (roots[0] ?? '') as ZkVerification['trust']['root'],
      circuitManifestVersion: set.proofs[0]?.version ?? '',
      vkeyHashes: vkeyHashesOf(set.proofs) as ZkVerification['trust']['vkeyHashes'],
      devMode: set.request.devMode,
    },
  };
}

const vkeyHashesOf = (proofs: readonly ProofResult[]) => [...new Set(proofs.map((p) => p.vkeyHash ?? ''))].sort();

/**
 * The recorded trust record must describe the recorded files: the same chain, block, registry address and
 * root as the recorded registry answers, the same manifest version and key hashes as the proofs and files, and
 * file bodies with the recorded hashes. Source: DESIGN 6.10 ("Why the record is trustworthy")
 */
function checkTrust(
  set: ProofSet,
  trust: ZkVerification['trust'],
  loaders: RecordedLoaders,
  bodies: FileBodies,
): ReverifyCode | undefined {
  if (trust.chainId !== loaders.chainId) return 'TRUST_MISMATCH:chain_id';
  if (trust.blockNumber !== loaders.block.number || trust.blockHash !== loaders.block.hash)
    return 'TRUST_MISMATCH:block';
  if (loaders.rpc.length === 0 || loaders.rpc.some((c) => c.to !== trust.registryAddress))
    return 'TRUST_MISMATCH:registry_address';
  if (!loaders.rpc.some((c) => certificateRoot(c.data) === trust.root)) return 'TRUST_MISMATCH:root';
  const versions = new Set([trust.circuitManifestVersion, ...set.proofs.map((p) => p.version)]);
  if (versions.size !== 1 || loaders.files[`manifest/${trust.circuitManifestVersion}`] === undefined)
    return 'TRUST_MISMATCH:circuit_manifest_version';
  const hashes = vkeyHashesOf(set.proofs);
  if (hashes.join() !== [...trust.vkeyHashes].sort().join()) return 'TRUST_MISMATCH:vkey_hashes';
  for (const h of hashes) if (loaders.files[`circuit/${h}`] === undefined) return 'TRUST_MISMATCH:vkey_hashes';
  for (const [key, digest] of Object.entries(loaders.files)) {
    const body = bodies.get(key);
    if (body === undefined || hex(body) !== digest) return 'TRUST_MISMATCH:circuit_files';
  }
  return undefined;
}

/** A fetch that answers only from the recording and throws for everything else (no network). */
function replayFetch(loaders: RecordedLoaders, bodies: FileBodies): typeof fetch {
  return async (input, init) => {
    const url = urlOf(input);
    if (url === RPC_URL && init?.method === 'POST') {
      const req = JSON.parse(String(init.body)) as { id?: number; params: [{ to: string; data: string }] };
      const [call] = req.params;
      const hit = loaders.rpc.find((c) => c.to === call.to.toLowerCase() && c.data === call.data.toLowerCase());
      if (!hit) throw new Error(`offline: no recorded answer for ${call.data.slice(0, 10)}`);
      return Response.json({ jsonrpc: '2.0', id: req.id, result: hit.result });
    }
    const body = url.startsWith(`${FILES_URL}/`) ? bodies.get(url.slice(FILES_URL.length + 1)) : undefined;
    if (body === undefined) throw new Error(`offline: fetch blocked: ${url}`);
    return new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });
  };
}

/** The loaders injected into verify({ config }): every URL points into the recording. */
const OFFLINE_CONFIG = {
  rpcUrl: RPC_URL,
  circuitManifestUrlGenerator: (_chainId: number, o: { version?: string }) => `${FILES_URL}/manifest/${o.version}`,
  packagedCircuitUrlGenerator: (_chainId: number, hash: string) => `${FILES_URL}/circuit/${hash}`,
  packagedCertsUrlGenerator: (_chainId: number, root: string) => `${FILES_URL}/certificates/${root}`,
  sanctionsTreeUrlGenerator: (_chainId: number, root: string) => `${FILES_URL}/sanctions/${root}`,
};

/** The SDK run with every loader served from the recording; `validity` is shifted by the whole days since then. */
export function sdkVerifyOffline(set: ProofSet, loaders: RecordedLoaders, bodies: FileBodies, now: number) {
  const validity = set.request.validity + (localMidnight(now) - loaders.verifiedDay);
  return serialized(() => withFetch(replayFetch(loaders, bodies), () => sdkVerify(set, OFFLINE_CONFIG, validity)));
}

/**
 * Offline re-verification by an arbitrator: the trust record is checked against the recorded files, the
 * production refusals repeat, and the SDK verifies again with every loader served from the recording.
 * A proof keeps the verdict it had when it was recorded.
 */
export async function reverifyOffline(
  set: ProofSet,
  verification: ZkVerification,
  loaders: RecordedLoaders,
  bodies: FileBodies,
  profile: Profile,
  now: number = Date.now(),
): Promise<{ ok: true; verified: true; uniqueIdentifier: string | null } | { ok: false; code: ReverifyCode }> {
  // A recorded failure has no identifier type and read no circuit files (the SDK stopped first): it can only fail
  // again. A recorded success repeats the trust record checks and the production refusals (task 1.9's rules), then
  // must describe the recorded files.
  if (verification.verified) {
    const trust = checkTrustRecord(trustRecordOf(verification), profile);
    if (!trust.ok) return { ok: false, code: trust.code };
    const mismatch = checkTrust(set, verification.trust, loaders, bodies);
    if (mismatch) return { ok: false, code: mismatch };
  }
  // The SDK throws on some malformed proof sets (a missing committedInputs, for one); that is not verified either.
  const result = await sdkVerifyOffline(set, loaders, bodies, now).catch(() => undefined);
  if (!result?.verified) return { ok: false, code: 'PROOF_NOT_VERIFIED' };
  return { ok: true, verified: true, uniqueIdentifier: result.uniqueIdentifier ?? null };
}
