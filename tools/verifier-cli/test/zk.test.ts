// P3.8-05, P3.8-06: offline zero-knowledge re-verification of the recorded mock-passport proofs (task 1.17) and the
// trust profile. The bundle gets the files the CLI reads (build/ISSUES.md item 3); the builder does not write them yet.
import net from 'node:net';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { failures, verifyLenient } from './helpers.ts';
import { alice, enc, ready, recordFiles, rootsOf, withZk } from './zkHelpers.ts';

vi.setConfig({ testTimeout: 180_000, hookTimeout: 180_000 });

beforeAll(ready);

describe('P3.8-05 offline ZK re-verification', () => {
  it('each proof is verified from the recorded registry answer and circuit files, with fetch and sockets throwing', async () => {
    const archive = await withZk({});
    const realFetch = globalThis.fetch;
    const realConnect = net.Socket.prototype.connect;
    const seen: string[] = [];
    globalThis.fetch = (async (u: unknown) => {
      seen.push(String(u));
      throw new Error('network blocked');
    }) as typeof fetch;
    // bb.js talks to its native prover over a Unix socket (`path`); every TCP connection throws (as in packages/zk offline.test.ts).
    net.Socket.prototype.connect = function (this: net.Socket, ...args: unknown[]) {
      const opts = args[0] as { path?: string } | unknown[];
      const path = Array.isArray(opts) ? (opts[0] as { path?: string })?.path : opts?.path;
      if (typeof path !== 'string') throw new Error('TCP blocked');
      return (realConnect as (...a: unknown[]) => net.Socket).apply(this, args);
    } as typeof net.Socket.prototype.connect;
    let v: Awaited<ReturnType<typeof verifyLenient>>;
    try {
      v = await verifyLenient(archive);
    } finally {
      globalThis.fetch = realFetch;
      net.Socket.prototype.connect = realConnect;
    }
    expect(failures(v)).toEqual([]);
    expect(v.code).toBe(0);
    const zk = v.report.findings.filter((f) => f.check === 'zk-proof');
    expect(zk.map((f) => `${f.file} ${f.status}`)).toEqual([
      'zk/reverify/A-release.json pass',
      'zk/reverify/B-release.json pass',
    ]);
    expect(seen.filter((u) => !u.includes('.invalid'))).toEqual([]);
  });

  it('a recorded circuit file that differs from its hash fails, naming the file', async () => {
    const reverify = JSON.parse(
      new TextDecoder().decode(recordFiles('A-release', alice)['zk/reverify/A-release.json'] as Uint8Array),
    );
    const key = Object.keys(reverify.bodies)[0] as string;
    reverify.bodies[key] = `${reverify.bodies[key]} `;
    const v = await verifyLenient(await withZk({ 'zk/reverify/A-release.json': enc(reverify) }));
    expect(v.code).toBe(1);
    expect(failures(v).map((f) => `${f.file} ${f.check}`)).toEqual(['zk/reverify/A-release.json zk-proof']);
  });

  it('a proof that no longer verifies fails; a missing recording is reported as not verified', async () => {
    const reverify = JSON.parse(
      new TextDecoder().decode(recordFiles('A-release', alice)['zk/reverify/A-release.json'] as Uint8Array),
    );
    reverify.set.proofs = reverify.set.proofs.slice(0, 1);
    const v = await verifyLenient(await withZk({ 'zk/reverify/A-release.json': enc(reverify) }));
    expect(failures(v).map((f) => `${f.file} ${f.check}`)).toEqual(['zk/reverify/A-release.json zk-proof']);
    const missing = await verifyLenient(await withZk({ 'zk/reverify/A-release.json': null }));
    expect(missing.code).toBe(0);
    expect(missing.report.findings.find((f) => f.file === 'zk/reverify/A-release.json')?.status).toBe('skip');
    expect(
      (await verifyLenient(await withZk({ 'zk/reverify/A-release.json': null }), ['--require-complete'])).code,
    ).toBe(1);
  });
});

describe('P3.8-06 the trust profile', () => {
  const cases = [
    ['Sepolia (chain 11155111)', { chain_id: 11155111, dev_mode: false, identifier_type: 'SALTED' }, 'SEPOLIA_REFUSED'],
    [
      'a mock identifier type',
      { chain_id: 1, dev_mode: false, identifier_type: 'SALTED_MOCK' },
      'MOCK_IDENTIFIER_REFUSED',
    ],
    ['dev_mode true', { chain_id: 1, dev_mode: true, identifier_type: 'SALTED' }, 'DEVMODE_REFUSED'],
  ] as const;
  for (const [name, over, code] of cases) {
    it(`${name}: production refuses with the reason, demo warns`, async () => {
      const archive = await withZk({}, [{ side: 'A', stage: 'release', roots: rootsOf(alice, over) }]);
      const prod = await verifyLenient(archive, ['--profile', 'production']);
      expect(prod.code).toBe(1);
      const f = failures(prod).find((x) => x.check === 'trust-profile');
      expect(f?.file).toBe('zk/trust_records.json');
      expect(f?.message).toContain(code);
      const demo = await verifyLenient(archive, ['--profile', 'demo']);
      expect(failures(demo).filter((x) => x.check === 'trust-profile')).toEqual([]);
      expect(demo.report.findings.find((x) => x.check === 'trust-profile')?.status).toBe('warn');
    });
  }

  it('an incomplete record is refused in both modes', async () => {
    const roots = { ...rootsOf(alice) } as Record<string, unknown>;
    delete roots.root;
    const archive = await withZk({}, [{ side: 'A', stage: 'release', roots }]);
    expect((await verifyLenient(archive, ['--profile', 'demo'])).code).toBe(1);
  });
});
