// I-3.7-g: the production profile builds from settings only, and a missing setting stops the start by name.
// Source: IMPLEMENTATION 3.7 (production ports), build/ISSUES.md I-3.7-g
import { describe, expect, it } from 'vitest';
import { buildProduction } from '../src/production.ts';
import { pinnedKeys } from '../src/stack.ts';

describe('I-3.7-g production adapters', () => {
  it('names the first missing setting and opens nothing', async () => {
    await expect(buildProduction({ LEGX_PROFILE: 'production' })).rejects.toThrow(/LEGX_AWS_REGION is not set/);
  });
  it('refuses a network the project never uses (Mainnet is not configurable here)', async () => {
    const env = {
      LEGX_AWS_REGION: 'eu-west-1',
      LEGX_BAR_JURISDICTIONS: 'GB',
      LEGX_ZK_RPC: 'https://a.example,https://b.example',
      LEGX_LOG_ORIGIN: 'legx.example/log',
      LEGX_LEDGER_WS: 'wss://x.example',
      LEGX_NETWORK: 'standalone',
    };
    await expect(buildProduction(env)).rejects.toThrow(/LEGX_NETWORK must be one of/);
  });
});

describe('pinned key lists (lawyers, operators, observers)', () => {
  it('reads raw Ed25519 as hex and ML-DSA-65 as base64, and knows no other id', () => {
    const find = pinnedKeys(
      JSON.stringify({ obs: { ed25519: '01'.repeat(32), mlDsa65: Buffer.from([1, 2, 3]).toString('base64') } }),
    );
    expect(find('obs')?.ed25519).toEqual(new Uint8Array(32).fill(1));
    expect(find('obs')?.mlDsa65).toEqual(Uint8Array.of(1, 2, 3));
    expect(find('someone-else')).toBeUndefined();
  });
  it('an unset variable pins nobody', () => {
    expect(pinnedKeys(undefined)('x')).toBeUndefined();
  });
});
