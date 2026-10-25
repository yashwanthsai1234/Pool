// Recorded demo proofs: usable in the demo profile, refused by production (CLI loader and the verifier adapter).
import { describe, expect, it } from 'vitest';
import { createZkAdapter } from '../../../services/zk-verifier/src/index.ts';
import { loadRecorded, RecordedRefused } from '../src/recorded.ts';

describe('recorded demo proofs', () => {
  it('load in the demo profile, as devMode mock proofs', () => {
    for (const n of ['alice-onboarding', 'alice-release', 'bob-release'] as const) {
      const r = loadRecorded(n, 'demo');
      expect(r.source).toBe('recorded');
      expect(r.request.devMode).toBe(true);
    }
  });
  it('the production profile refuses them before reading anything', () => {
    expect(() => loadRecorded('alice-release', 'production', '/nonexistent')).toThrow(RecordedRefused);
  });
  it('the production verifier refuses a recorded proof with DEVMODE_REFUSED, before any network', async () => {
    const r = loadRecorded('alice-release', 'demo');
    const prod = createZkAdapter({
      profile: 'production',
      devMode: false,
      domain: 'legx.app',
      sdkVersion: '0.19.2',
      rpcUrls: ['https://a.legx.invalid/', 'https://b.legx.invalid/'],
    });
    const req = {
      stage: r.request.stage,
      domain: r.request.domain,
      scope: r.request.scope,
      devMode: r.request.devMode,
      proofs: r.proofs,
      originalQuery: (r.request as never as { originalQuery: unknown }).originalQuery,
      queryResult: r.queryResult,
    };
    await expect(prod.verify(req)).rejects.toMatchObject({ code: 'ZK_REFUSED', reason: 'DEVMODE_REFUSED' });
  });
});
