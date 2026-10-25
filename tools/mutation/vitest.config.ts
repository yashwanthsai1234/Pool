import { readdirSync } from 'node:fs';
import { defineConfig } from 'vitest/config';

// Unit tests of packages/core only, for StrykerJS (5.4). LEGX_TESTS (comma list) keeps the test files whose path contains
// one of the substrings; LEGX_SKIP drops those that contain one.
const list = (v: string | undefined) => (v ?? '').split(',').filter(Boolean);
const only = list(process.env.LEGX_TESTS);
const skip = list(process.env.LEGX_SKIP);
const root = 'packages/core/test';
const files = (readdirSync(root, { recursive: true }) as string[])
  .filter((f) => f.endsWith('.test.ts') && !f.startsWith('browser'))
  .filter((f) => !only.length || only.some((s) => f.includes(s)))
  .filter((f) => !skip.some((s) => f.includes(s)))
  .map((f) => `${root}/${f}`);

export default defineConfig({
  test: { name: 'mutation', include: files, environment: 'node' },
});
