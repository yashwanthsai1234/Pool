import { readFileSync } from 'node:fs';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, expect, it, vi } from 'vitest';
import { createAnchorService } from '../src/anchor.ts';
import { type BundleDeps, buildBundle, collectBundle } from '../src/bundle.ts';
import { unzip } from '../src/zip.ts';
import { ANCHOR_ACCOUNT, fakeLedger } from './helpers/fakeLedger.ts';
import { makeLocalTsa } from './helpers/localTsa.ts';
import { memoryJobs } from './helpers/memoryJobs.ts';
import { makeWorld } from './helpers/world.ts';

vi.setConfig({ testTimeout: 60_000 });

async function setup() {
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
    verifyScript: readFileSync(new URL('../assets/verify.ts', import.meta.url), 'utf8'),
    beforeBuild: async () => {
      await anchors.anchorNow();
    },
  };
  return { w, deps };
}

describe('P3.4-10 evidence bundle', () => {
  it('two builds give the same bytes, and it holds the items of DESIGN 8.8', async () => {
    const { w, deps } = await setup();
    const a = await buildBundle(deps, w.dealId);
    const b = await buildBundle(deps, w.dealId);
    expect(a.bytes).toEqual(b.bytes);
    expect(a.sha256).toBe(bytesToHex(sha256(a.bytes)));
    const files = new Map(unzip(a.bytes).map((f) => [f.path, f.bytes]));
    const has = (p: string) => [...files.keys()].some((k) => k.startsWith(p));
    for (const p of [
      'manifest.json',
      'manifest.dsse.json',
      'contract/',
      'events/000000',
      'tlog/proofs/',
      'tlog/checkpoint.txt',
      'anchors/server-a.json',
      'anchors/server-b.json',
      'timestamps/auth-a.tst',
      'timestamps/auth-a.chain.pem',
      'keys/',
      'signed-contract/',
      'ops/',
      'frost/',
      'zk/',
      'verify.ts',
      'README.txt',
      'fre902/',
      'checks/report.json',
    ])
      expect(has(p), p).toBe(true);
    const manifest = JSON.parse(new TextDecoder().decode(files.get('manifest.json')));
    for (const f of manifest.files) expect(bytesToHex(sha256(files.get(f.path) as Uint8Array))).toBe(f.sha256);
  });

  it('events are the stored bytes; a changed database changes the bundle', async () => {
    const { w, deps } = await setup();
    const files = await collectBundle(deps, w.dealId);
    const rows = await w.db.repos.evidenceEvents.listAfter(w.dealId, -1);
    for (const r of rows)
      expect(files.find((f) => f.path === `events/${String(r.seq).padStart(6, '0')}.dsse.json`)?.bytes).toEqual(
        r.envelope,
      );
    expect(files.find((f) => f.path === 'frost/000002-frost.signed.dsse.json')).toBeDefined();
  });
});
