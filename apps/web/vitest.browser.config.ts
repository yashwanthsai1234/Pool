import tailwindcss from '@tailwindcss/vite';
import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

// Source: https://vitest.dev/guide/browser/playwright
// Real Chromium and WebKit, real WebCrypto, real CSP. Loaded by the root vitest.config.ts as the `browser` project.
export default defineConfig({
  plugins: [tailwindcss()],
  // pre-bundled, so Vite does not reload a running test (the FROST screens pull in the vault's crypto dependencies)
  optimizeDeps: {
    include: [
      'fast-check',
      'xrpl',
      'zod',
      '@legx/vault > @simplewebauthn/browser',
      '@legx/vault > @noble/post-quantum/hybrid.js',
      '@legx/core > @noble/post-quantum/ml-dsa.js',
      '@legx/core > @hpke/core',
      '@legx/core > @hpke/hybridkem-x-wing',
      // the lawyer console reads passports (task 4.4)
      '@legx/core > pkijs',
      '@legx/core > asn1js',
      '@legx/core > @noble/curves/misc.js',
      '@legx/core > @noble/hashes/legacy.js',
      '@legx/core > pkijs > @peculiar/asn1-cms',
      '@legx/core > pkijs > @peculiar/asn1-ecc',
      '@legx/core > pkijs > @peculiar/asn1-rsa',
      '@legx/core > pkijs > @peculiar/asn1-schema',
      '@legx/core > pkijs > @peculiar/asn1-x509',
    ],
  },
  test: {
    name: 'browser',
    // I-W-17: the FROST ceremonies run real crypto in WebKit and starve under many parallel pages; one file at a time per browser is steady.
    fileParallelism: false,
    include: ['test/**/*.browser.test.{ts,tsx}', '../../packages/ui/test/**/*.browser.test.{ts,tsx}'],
    browser: {
      enabled: true,
      headless: true,
      provider: playwright(),
      instances: [{ browser: 'chromium' }, { browser: 'webkit' }],
    },
  },
});
