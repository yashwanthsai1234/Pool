import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

// Source: https://vitest.dev/guide/browser/playwright
// The vault's own browser project (real WebCrypto, IndexedDB, CSP and WebAuthn on Chromium and WebKit).
// Loaded by the root vitest.config.ts with LEGX_BROWSER=1: `pnpm vitest run --project vault-browser`.
export default defineConfig({
  // Pre-bundled, so a late dependency discovery does not reload a running test.
  optimizeDeps: {
    include: [
      'fast-check',
      '@simplewebauthn/browser',
      'xrpl',
      'zod',
      '@legx/core > @noble/post-quantum/ml-dsa.js',
      '@legx/core > @hpke/core',
      '@legx/core > @hpke/hybridkem-x-wing',
      '@noble/post-quantum/hybrid.js',
      '@noble/post-quantum/ml-dsa.js',
    ],
  },
  test: {
    name: 'vault-browser',
    // I-W-17: the FROST ceremonies run real crypto in WebKit and time out when many pages compete: one file at a time.
    fileParallelism: false,
    include: ['test/**/*.browser.test.ts'],
    testTimeout: 30_000,
    browser: {
      enabled: true,
      headless: true,
      provider: playwright(),
      instances: [{ browser: 'chromium' }, { browser: 'webkit' }],
    },
  },
});
