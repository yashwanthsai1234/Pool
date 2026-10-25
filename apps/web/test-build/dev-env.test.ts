// OD-31 in the dev server: `pnpm dev` after `scripts/demo/seed.ts` gives the dashboard the seeded observer key and the
// standalone ledger's RPC without any manual step; never in a production build, and never over what the user already set.
import { describe, expect, it } from 'vitest';
import { devEnvFromDemoState } from '../dev-env.ts';

const STATE = JSON.stringify({
  network: 'standalone',
  observer: {
    keyId: 'observer-1',
    ed25519Private: '302e',
    mlDsa65Private: '3034',
    ed25519Public: 'aa',
    mlDsa65Public: 'bb',
  },
});

describe('devEnvFromDemoState', () => {
  it('maps the seeded observer key and the standalone ledger RPC', () => {
    const env = devEnvFromDemoState(STATE, { command: 'serve', env: {} });
    expect(JSON.parse(env.VITE_LEGX_OBSERVER as string)).toEqual({
      keyId: 'observer-1',
      ed25519Pkcs8: '302e',
      mlDsa65Pkcs8: '3034',
    });
    expect(env.VITE_LEGX_XRPL_RPC).toBe('http://127.0.0.1:6113');
    expect(env.VITE_LEGX_OBSERVER).not.toContain('"ed25519Public"');
  });

  it('adds nothing for a build, for the production profile, for a missing or broken state file', () => {
    expect(devEnvFromDemoState(STATE, { command: 'build', env: {} })).toEqual({});
    expect(devEnvFromDemoState(STATE, { command: 'serve', env: { VITE_LEGX_PROFILE: 'production' } })).toEqual({});
    expect(devEnvFromDemoState(undefined, { command: 'serve', env: {} })).toEqual({});
    expect(devEnvFromDemoState('{not json', { command: 'serve', env: {} })).toEqual({});
  });

  it('never overrides what the user set', () => {
    const env = devEnvFromDemoState(STATE, {
      command: 'serve',
      env: { VITE_LEGX_OBSERVER: 'mine', VITE_LEGX_XRPL_RPC: 'https://node.example' },
    });
    expect(env).toEqual({});
  });
});
