// `legx-verify <bundle.zip | unzipped folder>`: checks an evidence bundle (DESIGN 8.8) with no network calls and writes a
// text report and a JSON report. Exit code 0: every check passed. Exit code 1: a check failed (the report names the
// file and the check), or the bundle could not be read. Exit code 2: wrong usage.
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import type { Profile } from '@legx/core/attest';
import { nodeRootCertificates } from '../../../services/evidence/src/tsa.ts';
import { type BundleFiles, loadBundle } from './files.ts';
import { checkManifest, checkManifestSignature, readServiceKeys } from './integrity.ts';
import {
  checkAnchors,
  checkCheckpoint,
  checkConsistency,
  checkEvents,
  checkInclusion,
  checkTimestamps,
  latestClaimedTime,
  pemCerts,
  registryFromBundle,
} from './log.ts';
import { chainCheck, checkContract, checkGate, checkRecordSignatures, checkTrust, checkZk } from './release.ts';
import { buildReport, Findings, renderText } from './report.ts';

const USAGE = `usage: legx-verify <bundle.zip | folder> [options]
  --profile production|demo   production (default) refuses Sepolia, mock identifiers and dev mode; demo only warns
  --service-key <hex>         pin the service's Ed25519 key (the manifest signature is trusted only then)
  --insecure-unpinned         accept the signing key found inside the bundle (no pin): testing only
  --tsa-roots <pem file>      the time stamp authorities' root certificates (default: the system roots shipped with Node)
  --insecure-bundle-tsa-roots trust timestamps/roots.pem from the bundle itself: testing only
  --clause <file>             also check one clause proof against the contract root (repeatable)
  --out-dir <dir>             where legx-verify-report.txt and .json are written (default: current folder)
  --require-complete          a check that could not run because data is missing counts as a failure
  --bb <path>                 the barretenberg bb program, for zero-knowledge proofs when running verify.js
  --chain-check --rpc-url <u> the one optional ONLINE step: compare recorded registry answers with a live node
`;

export interface Options {
  readonly bundle: string;
  readonly profile: Profile;
  readonly serviceKey: string | undefined;
  readonly insecureUnpinned: boolean;
  readonly tsaRoots: string | undefined;
  readonly bundleTsaRoots: boolean;
  readonly clauses: readonly string[];
  readonly outDir: string;
  readonly requireComplete: boolean;
  readonly rpcUrl: string | undefined;
  readonly bb: string | undefined;
}

export function parseArgs(argv: readonly string[]): Options | string {
  const o = {
    bundle: '',
    profile: 'production' as Profile,
    serviceKey: undefined as string | undefined,
    insecureUnpinned: false,
    tsaRoots: undefined as string | undefined,
    bundleTsaRoots: false,
    clauses: [] as string[],
    outDir: '.',
    requireComplete: false,
    rpcUrl: undefined as string | undefined,
    bb: undefined as string | undefined,
  };
  let chain = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    const value = () => argv[++i];
    if (a === '--profile') {
      const v = value();
      if (v !== 'production' && v !== 'demo') return '--profile must be production or demo';
      o.profile = v;
    } else if (a === '--service-key') {
      const v = value();
      if (!v || !/^[0-9a-fA-F]{64}$/.test(v)) return '--service-key needs 64 hex characters';
      o.serviceKey = v;
    } else if (a === '--insecure-unpinned') o.insecureUnpinned = true;
    else if (a === '--insecure-bundle-tsa-roots') o.bundleTsaRoots = true;
    else if (a === '--tsa-roots') {
      const v = value();
      if (!v) return '--tsa-roots needs a PEM file';
      o.tsaRoots = v;
    } else if (a === '--clause') {
      const v = value();
      if (!v) return '--clause needs a file';
      o.clauses.push(v);
    } else if (a === '--out-dir') {
      const v = value();
      if (!v) return '--out-dir needs a folder';
      o.outDir = v;
    } else if (a === '--bb') {
      const v = value();
      if (!v) return '--bb needs a path';
      o.bb = v;
    } else if (a === '--rpc-url') {
      o.rpcUrl = value();
    } else if (a === '--require-complete') o.requireComplete = true;
    else if (a === '--chain-check') chain = true;
    else if (a.startsWith('-')) return `unknown option ${a}`;
    else if (o.bundle === '') o.bundle = a;
    else return 'only one bundle can be checked at a time';
  }
  if (o.bundle === '') return 'no bundle given';
  if (chain && !o.rpcUrl) return '--chain-check needs --rpc-url';
  if (!chain) o.rpcUrl = undefined;
  return o;
}

export interface Io {
  out(text: string): void;
  err(text: string): void;
}

/** Runs one group of checks; a crash inside a check is a failure of that check, never a pass. */
async function guarded<T>(
  out: Findings,
  check: string,
  file: string,
  fn: () => T | Promise<T>,
): Promise<T | undefined> {
  try {
    return await fn();
  } catch (e) {
    out.fail(check, file, `the check crashed: ${(e as Error).message}`);
    return undefined;
  }
}

/** The roots time stamps are checked against: the arbitrator's own, never the bundle's unless explicitly allowed (I-S-E3). */
function tsaRoots(opts: Options, f: BundleFiles): Uint8Array[] {
  if (opts.tsaRoots) return pemCerts(readFileSync(opts.tsaRoots, 'utf8'));
  if (opts.bundleTsaRoots) return pemCerts(f.text('timestamps/roots.pem') ?? '');
  return nodeRootCertificates();
}

export async function run(argv: readonly string[], io: Io): Promise<number> {
  const opts = parseArgs(argv);
  if (typeof opts === 'string') {
    io.err(`${opts}\n${USAGE}`);
    return 2;
  }
  if (opts.bb) process.env.BB_BINARY_PATH = opts.bb;
  const out = new Findings();
  let files: BundleFiles | undefined;
  let digest = '';
  try {
    const loaded = loadBundle(opts.bundle);
    files = loaded.files;
    digest = loaded.archive ? createHash('sha256').update(loaded.archive).digest('hex') : '(folder)';
  } catch (e) {
    out.fail('archive', opts.bundle, `cannot read the bundle: ${(e as Error).message}`);
  }
  let dealId: string | undefined;
  if (files) {
    const f = files;
    const manifest = await guarded(out, 'manifest', 'manifest.json', () => checkManifest(f, out));
    dealId = manifest?.dealId;
    const service = readServiceKeys(f);
    await guarded(out, 'manifest-signature', 'manifest.dsse.json', () =>
      checkManifestSignature(f, service, opts.serviceKey, opts.insecureUnpinned, out),
    );
    const registry = registryFromBundle(f, service);
    const events = (await guarded(out, 'chain', 'events/', () => checkEvents(f, registry, out))) ?? [];
    const cp = await guarded(out, 'checkpoint', 'tlog/checkpoint.txt', () => checkCheckpoint(f, out));
    await guarded(out, 'merkle-proof', 'tlog/', () => checkInclusion(f, events, cp, out));
    await guarded(out, 'consistency', 'tlog/consistency.json', () => checkConsistency(f, cp, out));
    await guarded(out, 'anchor', 'anchors/', () => checkAnchors(f, cp, out));
    await guarded(out, 'timestamp', 'timestamps/', () => checkTimestamps(f, cp, tsaRoots(opts, f), out));
    const clauses = new Map<string, Uint8Array>();
    for (const c of opts.clauses) clauses.set(basename(c), new Uint8Array(readFileSync(c)));
    await guarded(out, 'contract', 'contract/', () => checkContract(f, clauses, out));
    await guarded(out, 'attestation', 'attestations/', () =>
      checkRecordSignatures(f, registry, latestClaimedTime(events), out),
    );
    await guarded(out, 'trust-profile', 'zk/trust_records.json', () => checkTrust(f, opts.profile, out));
    const reverified = (await guarded(out, 'zk-proof', 'zk/', () => checkZk(f, opts.profile, out))) ?? [];
    await guarded(out, 'release-gate', 'release/gate-input.json', () => checkGate(f, opts.profile, out));
    if (opts.rpcUrl)
      await guarded(out, 'chain-check (ONLINE, optional)', opts.rpcUrl, () =>
        chainCheck(reverified, opts.rpcUrl as string, out),
      );
  }
  const findings = opts.requireComplete
    ? out.list.map((x) =>
        x.status === 'skip' ? { ...x, status: 'fail' as const, message: `${x.message} (--require-complete)` } : x,
      )
    : out.list;
  const report = buildReport({ name: basename(opts.bundle), sha256: digest, dealId }, opts.profile, findings);
  const text = renderText(report);
  io.out(text);
  mkdirSync(opts.outDir, { recursive: true });
  writeFileSync(join(opts.outDir, 'legx-verify-report.txt'), text);
  writeFileSync(join(opts.outDir, 'legx-verify-report.json'), `${JSON.stringify(report, null, 2)}\n`);
  return report.result === 'pass' ? 0 : 1;
}
