// Test bundles come from the evidence service's own builder (task 3.4); nothing here writes a bundle by hand except
// `resign`, which re-signs a changed file list the way the builder does so a semantic check can be tested alone.
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { type Envelope, pae } from '@legx/core/evidence';
import { toBase64 } from '@legx/core/pq';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { createAnchorService } from '../../../services/evidence/src/anchor.ts';
import { type BundleDeps, collectBundle, jsonBytes, MANIFEST_TYPE } from '../../../services/evidence/src/bundle.ts';
import { canonicalBytes } from '../../../services/evidence/src/events.ts';
import { type ZipFile, zip } from '../../../services/evidence/src/zip.ts';
import { ANCHOR_ACCOUNT, fakeLedger } from '../../../services/evidence/test/helpers/fakeLedger.ts';
import { makeLocalTsa } from '../../../services/evidence/test/helpers/localTsa.ts';
import { memoryJobs } from '../../../services/evidence/test/helpers/memoryJobs.ts';
import { makeWorld } from '../../../services/evidence/test/helpers/world.ts';
import { run } from '../src/cli.ts';

export type World = Awaited<ReturnType<typeof makeWorld>>;

export interface TestBundle {
  readonly w: World;
  readonly deps: BundleDeps;
  readonly files: ZipFile[];
  readonly zip: Uint8Array;
}

/** A deal with three events, an anchor on the fake ledger and a local RFC 3161 authority, built by the real builder. */
export async function makeBundle(verifyScript = '// verify.ts\n'): Promise<TestBundle> {
  const w = await makeWorld();
  const alice = await w.enroll('alice', 'A');
  for (const k of ['shell.opened', 'frost.signed', 'identity.onboarded'] as const)
    await w.events.append(w.dealId, await w.sign(alice, 'alice', k));
  const tsa = await makeLocalTsa('auth-a');
  const ledger = fakeLedger();
  const queue = memoryJobs();
  const anchors = createAnchorService({
    db: w.db,
    logSvc: w.logSvc,
    ledger: ledger.port,
    signTx: async (t) => JSON.stringify(t),
    anchorAccount: ANCHOR_ACCOUNT,
    network: 'standalone',
    origin: w.origin,
    objects: w.objects,
    retainDays: 10,
    jobs: queue.jobs,
    tsa: [tsa.client()],
  });
  await anchors.start();
  await anchors.anchorNow();
  await queue.drain();
  const deps: BundleDeps = {
    db: w.db,
    log: w.log,
    objects: w.objects,
    signer: w.service.signer,
    clock: w.clock,
    retainDays: 10,
    origin: w.origin,
    checkpointKeys: w.cpKeys,
    ledgers: [
      { name: 'server-a', ledger: ledger.port },
      { name: 'server-b', ledger: ledger.port },
    ],
    authorities: ['auth-a'],
    trustedRoots: [tsa.rootDer],
    registry: w.deps.registry,
    verifyScript,
    beforeBuild: async () => {
      await anchors.anchorNow();
    },
  };
  const files = await collectBundle(deps, w.dealId);
  return { w, deps, files, zip: zip(files) };
}

/** Replaces some files, then rewrites manifest.json and manifest.dsse.json with the service signer. */
export async function resign(b: TestBundle, change: Record<string, Uint8Array | null>): Promise<ZipFile[]> {
  const map = new Map(b.files.map((f) => [f.path, f.bytes]));
  for (const [p, bytes] of Object.entries(change)) {
    if (bytes === null) map.delete(p);
    else map.set(p, bytes);
  }
  map.delete('manifest.json');
  map.delete('manifest.dsse.json');
  const list = [...map.entries()].sort(([a], [c]) => (a < c ? -1 : 1));
  const manifest = jsonBytes({
    deal_id: b.w.dealId,
    files: list.map(([path, bytes]) => ({ path, sha256: bytesToHex(sha256(bytes)), size: bytes.length })),
  });
  const statement = canonicalBytes({
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: 'manifest.json', digest: { sha256: bytesToHex(sha256(manifest)) } }],
    predicateType: 'https://legx.dev/bundle-manifest/v1',
    predicate: { deal_id: b.w.dealId, sig_algs: ['ed25519', 'ml-dsa-65'] },
  });
  const sig = await b.deps.signer.signHybrid(pae(MANIFEST_TYPE, statement), 'legx/dsse/v1');
  const env: Envelope = {
    payloadType: MANIFEST_TYPE,
    payload: toBase64(statement),
    signatures: [
      { keyid: sig.keyIds.ed25519, sig: toBase64(sig.ed25519) },
      { keyid: sig.keyIds.mlDsa65, sig: toBase64(sig.mlDsa65) },
    ],
  };
  map.set('manifest.json', manifest);
  map.set('manifest.dsse.json', canonicalBytes(env));
  return [...map.entries()].map(([path, bytes]) => ({ path, bytes }));
}

export interface Verdict {
  readonly code: number;
  readonly text: string;
  readonly report: { result: string; findings: { check: string; file: string; status: string; message: string }[] };
}

/** Runs the CLI on archive bytes, as a user would on a file, and reads back both reports. */
export async function verify(archive: Uint8Array, args: string[] = []): Promise<Verdict> {
  const dir = mkdtempSync(join(tmpdir(), 'legx-verify-'));
  const path = join(dir, 'bundle.zip');
  writeFileSync(path, archive);
  const out: string[] = [];
  const code = await run([path, '--out-dir', dir, '--profile', 'demo', ...args], {
    out: (t) => out.push(t),
    err: (t) => out.push(t),
  });
  const report = JSON.parse(readFileSync(join(dir, 'legx-verify-report.json'), 'utf8'));
  expectText(readFileSync(join(dir, 'legx-verify-report.txt'), 'utf8'), out.join(''));
  return { code, text: out.join(''), report };
}

function expectText(file: string, printed: string): void {
  if (file !== printed) throw new Error('the report file differs from what was printed');
}

export const failures = (v: Verdict) => v.report.findings.filter((f) => f.status === 'fail');

/** `verify` for tests that are not about trust: accepts the bundle's own signing key and time stamp roots. */
export const verifyLenient = (archive: Uint8Array, args: string[] = []) =>
  verify(archive, ['--insecure-unpinned', '--insecure-bundle-tsa-roots', ...args]);
