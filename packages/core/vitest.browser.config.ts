import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

// Source: https://vitest.dev/guide/browser/playwright
// OD-27: @legx/core must run in a browser. Loaded by the root vitest.config.ts with LEGX_BROWSER=1:
// `LEGX_BROWSER=1 pnpm vitest run --project core-browser`.
export default defineConfig({
  // Pre-bundled, so a late dependency discovery does not reload a running test.
  optimizeDeps: { include: ['xrpl', 'asn1js', 'pkijs', '@hpke/core', '@hpke/hybridkem-x-wing'] },
  test: {
    name: 'core-browser',
    include: ['test/browser/*.browser.test.ts'],
    testTimeout: 60_000,
    browser: {
      enabled: true,
      headless: true,
      provider: playwright(),
      instances: [{ browser: 'chromium' }],
    },
  },
});
