import { defineConfig } from 'vitest/config';

// Runs spec/test until the root config includes it (request in build/status/5.1.md).
export default defineConfig({
  test: {
    root: import.meta.dirname,
    include: ['test/**/*.test.ts'],
    environment: 'node',
    testTimeout: 600_000,
  },
});
