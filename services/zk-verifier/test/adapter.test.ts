// Task 3.11 (IMPLEMENTATION P3.11-01 to -05, -09 to -12, -16 to -18): the production adapter on a fake network that
// serves task 1.17's recorded mock-passport sets. No test touches the real network.
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { bindCustomData, offlineQuery, ZkRequestError } from '@legx/zk/request';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { zkVerifierPortContract } from '../../../packages/zk/test/zkVerifierPort.contract.ts';
import { DEFAULT_CDN_HOSTS, HOSTED_VERIFIER_HOST } from '../src/config.ts';
import { guardedFetch } from '../src/guard.ts';
import { adapter, demo, loadSet, request, useFakeNetwork } from './helpers.ts';
import { CDN, RPC_A, RPC_B } from './network.ts';

let env: ReturnType<typeof useFakeNetwork>;
beforeEach(() => {
  env = useFakeNetwork();
});
afterEach(() => env.restore());

const release = loadSet('alice-release');
const hostsOf = () => new Set(env.net.calls.map((c) => c.host));
const code = (p: Promise<unknown>) =>
  p.then(
    () => 'resolved',
    (e: { code?: string; reason?: string }) => (e.reason ? `${e.code}:${e.reason}` : (e.code ?? String(e))),
  );

// P3.11-01: the same contract suite as the replay fake and the offline adapter (packages/zk/test/port.test.ts).
zkVerifierPortContract('production adapter on the fake network (demo profile)', () => adapter());

describe('P3.11-02/03 local mode and one set of hosts', () => {
  it('never calls the hosted verifier and reaches only the configured RPC hosts and the circuit file host', async () => {
    const hosted = [] as string[];
    const base = env.net.fetch;
    globalThis.fetch = async (input, init) => {
      const host = new URL(typeof input === 'string' || input instanceof URL ? input : input.url).host;
      if (host === HOSTED_VERIFIER_HOST) hosted.push(host);
      return base(input, init);
    };
    const v = await adapter().verify(request(release));
    expect(v.verified).toBe(true);
    expect(hosted).toEqual([]);
    expect(hostsOf()).toEqual(new Set([new URL(RPC_A).host, new URL(RPC_B).host, new URL(CDN).host]));
  });

  it('with one provider (demo) the registry calls go to that one host', async () => {
    await adapter({ rpcUrls: [RPC_A] }).verify(request(release));
    const rpcHosts = new Set(env.net.calls.filter((c) => c.method !== 'GET').map((c) => c.host));
    expect(rpcHosts).toEqual(new Set([new URL(RPC_A).host]));
  });

  it('the guard refuses the hosted verifier and any unknown host in code, and never reaches the network', async () => {
    const reached = [] as string[];
    const guard = guardedFetch(
      async (u) => {
        reached.push(String(u));
        return new Response('{}');
      },
      new Set([new URL(RPC_A).host]),
      new Set([new URL(RPC_A).host, ...DEFAULT_CDN_HOSTS]),
      { failure: undefined },
    );
    for (const url of [`https://${HOSTED_VERIFIER_HOST}/verify`, 'https://example.com/']) {
      await expect(guard(url)).rejects.toMatchObject({ code: 'ZK_EGRESS_BLOCKED' });
    }
    expect(reached).toEqual([]);
  });

  it('a configuration that names the hosted verifier is refused at start-up', () => {
    expect(() => adapter({ rpcUrls: [`https://${HOSTED_VERIFIER_HOST}/rpc`, RPC_B] })).toThrow(
      /ZK_CONFIG_HOSTED_VERIFIER/,
    );
    expect(() => adapter({ cdnHosts: [HOSTED_VERIFIER_HOST] })).toThrow(/ZK_CONFIG_HOSTED_VERIFIER/);
  });

  it('the production profile uses the same hosts and still never reaches the hosted verifier', async () => {
    // A devMode:false request on the mock proofs does not verify (the registry is another chain); the point is egress.
    const prod = adapter({ profile: 'production', devMode: false });
    await code(prod.verify(request(release, { devMode: false })));
    expect(hostsOf().has(HOSTED_VERIFIER_HOST)).toBe(false);
    for (const h of hostsOf()) expect([new URL(RPC_A).host, new URL(RPC_B).host, ...DEFAULT_CDN_HOSTS]).toContain(h);
  });
});

describe('P3.11-04/05/17 start-up checks', () => {
  it('a different SDK version stops start-up', () => {
    expect(() => adapter({ sdkVersion: '0.19.1' })).toThrow(/ZK_CONFIG_SDK_VERSION/);
    expect(() => adapter({ sdkVersion: '0.20.0' })).toThrow(/ZK_CONFIG_SDK_VERSION/);
  });

  it('devMode in the production profile refuses to start; demo accepts it', () => {
    expect(() => adapter({ profile: 'production', devMode: true })).toThrow(/ZK_CONFIG_DEVMODE_REFUSED/);
    expect(adapter({ profile: 'demo', devMode: true })).toBeDefined();
  });

  it('production needs two RPC providers on different hosts', () => {
    expect(() => adapter({ profile: 'production', devMode: false, rpcUrls: [RPC_A] })).toThrow(
      /ZK_CONFIG_RPC_PROVIDERS/,
    );
    expect(() => adapter({ profile: 'production', devMode: false, rpcUrls: [RPC_A, `${RPC_A}?k=2`] })).toThrow(
      /ZK_CONFIG_RPC_PROVIDERS/,
    );
    expect(adapter({ profile: 'production', devMode: false })).toBeDefined();
  });

  it('a proof made in devMode is refused in production, before any request', async () => {
    const prod = adapter({ profile: 'production', devMode: false });
    expect(await code(prod.verify(request(release)))).toBe('ZK_REFUSED:DEVMODE_REFUSED');
    expect(env.net.calls).toEqual([]);
  });

  it('the domain is exactly legx.app: a page origin, no domain and another domain stop start-up', () => {
    for (const domain of ['https://legx.app', 'app.legx.app', 'example.com', undefined])
      expect(() => adapter({ domain })).toThrow(/ZK_CONFIG_WRONG_DOMAIN/);
    expect(demo.domain).toBe('legx.app');
  });

  it('a proof made under another domain is refused', async () => {
    const other = loadSet('alice-other-domain');
    expect(await code(adapter().verify(request(other)))).toBe('ZK_REFUSED:WRONG_DOMAIN');
    expect(env.net.calls).toEqual([]);
  });
});

describe('P3.11-09 CommonJS loading', () => {
  it('the SDK loads through require and verifies; a plain ESM import fails under Node (documented)', async () => {
    expect((await adapter().verify(request(release))).verified).toBe(true);
    const zkDir = join(import.meta.dirname, '../../../packages/zk');
    const run = () =>
      execFileSync(process.execPath, ['--input-type=module', '-e', "await import('@zkpassport/sdk')"], {
        cwd: zkDir,
        stdio: 'pipe',
      });
    expect(run).toThrow(/ERR_UNSUPPORTED_DIR_IMPORT|Directory import/);
  });
});

describe('P3.11-10/11 the CDN or the RPC is down', () => {
  const cdn = new URL(CDN).host;
  const sleeps = [] as number[];
  const deps = { sleep: async (ms: number) => void sleeps.push(ms) };
  beforeEach(() => {
    sleeps.length = 0;
  });

  it('CDN down: retries with backoff, then ZkCdnUnavailable', async () => {
    env.net.behaviour.set(cdn, 'down');
    const err = await adapter({}, deps)
      .verify(request(release))
      .catch((e: Error) => e);
    expect(err).toMatchObject({ name: 'ZkCdnUnavailable', code: 'ZK_CDN_UNAVAILABLE' });
    expect(sleeps).toEqual([250, 500]);
  });

  it('CDN answering 503 is the same failure, not a stored file', async () => {
    env.net.behaviour.set(cdn, 'busy');
    expect(await code(adapter({}, deps).verify(request(release)))).toBe('ZK_CDN_UNAVAILABLE');
  });

  it('a CDN that comes back during the retries gives a normal result', async () => {
    env.net.behaviour.set(cdn, 'down');
    const a = adapter({}, { sleep: async () => void env.net.behaviour.delete(cdn) });
    expect((await a.verify(request(release))).verified).toBe(true);
  });

  it('RPC down (first or second provider): ZkRegistryUnavailable, fail closed', async () => {
    for (const url of [RPC_A, RPC_B]) {
      env.net.behaviour.clear();
      env.net.behaviour.set(new URL(url).host, 'down');
      expect(await code(adapter({}, deps).verify(request(release)))).toBe('ZK_REGISTRY_UNAVAILABLE');
    }
  });

  it('two providers that disagree on the block are not retried', async () => {
    env.net.blockHash.set(new URL(RPC_B).host, `0x${'ab'.repeat(32)}`);
    expect(await code(adapter({}, deps).verify(request(release)))).toBe('ZK_ROOTS_DISAGREE');
    expect(sleeps).toEqual([]);
  });
});

describe('P3.11-12/16 forged proofs and the production rules', () => {
  it('one flipped byte is not verified (adapter level, with the contract suite as the base case)', async () => {
    const proofs = release.proofs.map((p) => ({ ...p }));
    const bind = proofs.find((p) => p.name === 'bind') as { proof: string };
    bind.proof = `${bind.proof.slice(0, 50)}${bind.proof[50] === 'a' ? 'b' : 'a'}${bind.proof.slice(51)}`;
    const r = await adapter()
      .verify(request(release, { proofs } as never))
      .catch(() => undefined);
    expect(r?.verified ?? false).toBe(false);
  });

  it('the production adapter does not accept a mock proof as verified (devMode off: the SDK rejects it)', async () => {
    const prod = adapter({ profile: 'production', devMode: false });
    const r = await prod.verify(request(release, { devMode: false })).catch(() => undefined);
    expect(r?.verified ?? false).toBe(false);
  });
});

describe('P3.11-18 the bind length is checked by our code', () => {
  it('506 bytes pass; 507 is refused before the SDK is asked to bind', () => {
    const q = offlineQuery();
    expect(() => bindCustomData(q, 'a'.repeat(506))).not.toThrow();
    let err: unknown;
    try {
      bindCustomData(offlineQuery(), 'a'.repeat(507));
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ZkRequestError);
    expect((err as ZkRequestError).code).toBe('BOUND_TOO_LONG');
  });
});
