// Tag: live-sepolia. Verifies a recorded mock proof against the LIVE Sepolia ZKPassport registry and the real circuit
// CDN, through the production adapter in the demo profile. Run by hand now, nightly later:
//   LEGX_LIVE_SEPOLIA=1 pnpm vitest run --project integration services/zk-verifier
// Optional: SEPOLIA_RPC_URL and SEPOLIA_RPC_URL_2 (two providers; the second must agree with the first).
// Without LEGX_LIVE_SEPOLIA the test is skipped, so the default integration run never needs the internet.
// Source: https://docs.zkpassport.id (registry on Sepolia for dev mode), @zkpassport/registry 0.15.3 (built-in endpoint)
import { createRequire } from 'node:module';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { adapter, loadSet, request } from '../test/helpers.ts';

const live = process.env.LEGX_LIVE_SEPOLIA === '1';
// The ZKPassport registry package's built-in Sepolia endpoint is the fallback provider.
const registry = createRequire(import.meta.resolve('@legx/zk/sdk'))('@zkpassport/registry') as {
  createRegistryClient(chain: string): { rpcUrl: string };
};
const builtIn = registry.createRegistryClient('ethereum_sepolia').rpcUrl;
const rpcUrls = [process.env.SEPOLIA_RPC_URL ?? builtIn, process.env.SEPOLIA_RPC_URL_2].filter((u): u is string => !!u);

describe.skipIf(!live)('live-sepolia: a recorded mock proof against the live registry', () => {
  beforeAll(() => {
    // Only the date is faked: the recorded proof's date check counts from the day it was made. The network is real.
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.parse(loadSet('alice-release').recordedAt));
  });
  afterAll(() => vi.useRealTimers());

  it('verifies, records a Sepolia/mock/devMode trust record, and the production profile would refuse it', async () => {
    const v = await adapter({ rpcUrls }).verify(request(loadSet('alice-release')));
    expect(v.verified).toBe(true);
    expect(v.trust).toMatchObject({ chainId: 11155111, devMode: true });
    expect(v.trust.root).toMatch(/^0x[0-9a-f]{64}$/);
    expect(v.uniqueIdentifierType).toBe('NON_SALTED_MOCK');
  }, 180_000);
});
