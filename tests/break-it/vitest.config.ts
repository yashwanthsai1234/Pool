import { defineConfig } from 'vitest/config';

// Break-it suite of task 5.7: every test here is a FAILING test that pins a security finding (I-S-*).
// Run: pnpm vitest run --config tests/break-it/vitest.config.ts
export default defineConfig({
  test: {
    root: import.meta.dirname,
    include: ['**/*.break.test.ts'],
    environment: 'node',
    testTimeout: 120_000,
  },
});
