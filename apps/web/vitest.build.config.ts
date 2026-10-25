import { defineConfig } from 'vitest/config';

// Node-side tests of the production build (bundle budget, CSP, service worker). They run real browsers through Playwright.
export default defineConfig({
  test: {
    name: 'web-build',
    include: ['test-build/**/*.test.ts'],
    testTimeout: 60_000,
    hookTimeout: 120_000,
    fileParallelism: false,
  },
});
