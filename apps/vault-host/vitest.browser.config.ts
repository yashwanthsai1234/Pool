import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';
import { type VaultOptions, World } from './test/world.ts';

// Source: https://vitest.dev/guide/browser/commands (custom commands run in Node, called from the browser test)
// Real Chromium and WebKit. The vault origins are separate ports served from Node; the test page is the "app".
// Loaded by the root vitest.config.ts with LEGX_BROWSER=1: `pnpm vitest run --project vault-host-browser`.
let world: Promise<World> | undefined;
const getWorld = () => {
  world ??= World.create();
  return world;
};

export default defineConfig({
  optimizeDeps: {
    include: [
      'zod',
      '@legx/core > @noble/post-quantum/ml-dsa.js',
      '@legx/core > @hpke/core',
      '@legx/core > @hpke/hybridkem-x-wing',
    ],
  },
  test: {
    name: 'vault-host-browser',
    include: ['test/**/*.browser.test.ts'],
    testTimeout: 40_000,
    hookTimeout: 120_000,
    browser: {
      enabled: true,
      headless: true,
      provider: playwright(),
      instances: [{ browser: 'chromium' }, { browser: 'webkit' }],
      commands: {
        startVault: async (_ctx, o: VaultOptions) => (await getWorld()).startVault(o),
        vaultReports: async (_ctx, origin: string) => (await getWorld()).reports(origin),
        foreignOrigin: async () => (await getWorld()).foreignOrigin,
      },
    },
  },
});
