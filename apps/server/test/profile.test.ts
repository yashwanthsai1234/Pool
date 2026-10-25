// P3.7-05 and P3.7-07: the production profile refuses to start when any demo setting is present.
import { describe, expect, it } from 'vitest';
import { assertNotSepoliaChain, assertProfile, ProfileViolation, profileFromEnv } from '../src/config.ts';

const real = { impl: 'kms', demo: false };
const prod = { profile: 'production' as const, ports: { signer: real, objectStore: { impl: 's3', demo: false } } };

const refuses = (i: Parameters<typeof assertProfile>[0], code: string) => {
  try {
    assertProfile(i);
  } catch (e) {
    expect(e).toBeInstanceOf(ProfileViolation);
    expect((e as ProfileViolation).code).toBe(code);
    return;
  }
  throw new Error(`expected ProfileViolation ${code}`);
};

describe('P3.7-05 production refuses demo ports', () => {
  it('accepts a production profile with real ports only', () => {
    expect(() => assertProfile(prod)).not.toThrow();
  });
  it.each(['signer', 'objectStore', 'transparencyLog', 'barRegistry', 'releaseGate', 'ledger'])(
    'a demo %s port is refused',
    (name) => {
      refuses({ ...prod, ports: { ...prod.ports, [name]: { impl: 'demo-impl', demo: true } } }, 'DEMO_PORT');
    },
  );
  it('any LEGX_DEMO_* variable is refused, even an empty-looking one', () => {
    refuses({ ...prod, env: { LEGX_DEMO_SIGNER: 'file' } }, 'DEMO_ENV');
    refuses({ ...prod, env: { LEGX_DEMO_X: '' } }, 'DEMO_ENV');
    expect(() => assertProfile({ ...prod, env: { LEGX_DEMO_X: undefined, PATH: '/bin' } })).not.toThrow();
  });
  it('the recovery agent or the firm co-signer inside the production process is refused', () => {
    refuses({ ...prod, agentsMounted: true }, 'AGENTS_IN_PROCESS');
  });
  it('the demo profile accepts all of it', () => {
    expect(() =>
      assertProfile({
        profile: 'demo',
        ports: { signer: { impl: 'file', demo: true } },
        env: { LEGX_DEMO_SIGNER: 'file' },
        zk: { devMode: true, rpcUrls: ['https://rpc.sepolia.org'], identifierType: 'NON_SALTED_MOCK' },
        agentsMounted: true,
      }),
    ).not.toThrow();
  });
  it('an unset or unknown LEGX_PROFILE is production', () => {
    expect(profileFromEnv({})).toBe('production');
    expect(profileFromEnv({ LEGX_PROFILE: 'Demo' })).toBe('production');
    expect(profileFromEnv({ LEGX_PROFILE: 'demo' })).toBe('demo');
  });
});

describe('P3.7-07 production refuses a dev-mode ZK adapter', () => {
  const zk = { devMode: false, rpcUrls: ['https://eth-a.example', 'https://eth-b.example'] };
  it('accepts a real configuration', () => {
    expect(() => assertProfile({ ...prod, zk })).not.toThrow();
  });
  it('devMode', () => refuses({ ...prod, zk: { ...zk, devMode: true } }, 'ZK_DEV_MODE'));
  it('a Sepolia RPC', () =>
    refuses(
      { ...prod, zk: { ...zk, rpcUrls: [...zk.rpcUrls, 'https://ethereum-sepolia-rpc.publicnode.com'] } },
      'ZK_SEPOLIA',
    ));
  it('a mock identifier type', () => refuses({ ...prod, zk: { ...zk, identifierType: 'NON_SALTED_MOCK' } }, 'ZK_MOCK'));
});

// I-S-A3: a Sepolia RPC without the word "sepolia" in its URL is caught by the chain id it reports.
describe('I-S-A3 production checks eth_chainId, not only the URL', () => {
  const chain = (id: string) =>
    (async () => new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: id }))) as unknown as typeof fetch;
  it('refuses 0xaa36a7 (Sepolia) behind an innocent URL', async () => {
    await expect(
      assertNotSepoliaChain('production', ['https://rpc.example/eth'], chain('0xaa36a7')),
    ).rejects.toMatchObject({
      code: 'ZK_SEPOLIA',
    });
  });
  it('accepts mainnet, and ignores the demo profile', async () => {
    await expect(
      assertNotSepoliaChain('production', ['https://rpc.example/eth'], chain('0x1')),
    ).resolves.toBeUndefined();
    await expect(
      assertNotSepoliaChain('demo', ['https://rpc.example/eth'], chain('0xaa36a7')),
    ).resolves.toBeUndefined();
  });
  it('an unreachable or malformed answer fails closed in production', async () => {
    await expect(
      assertNotSepoliaChain('production', ['https://rpc.example/eth'], (async () => {
        throw new Error('down');
      }) as unknown as typeof fetch),
    ).rejects.toThrow();
    await expect(assertNotSepoliaChain('production', ['https://rpc.example/eth'], chain('nope'))).rejects.toThrow();
  });
});
