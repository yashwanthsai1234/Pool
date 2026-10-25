import { defineConfig } from 'vitest/config';

// One root config, inline projects (IMPLEMENTATION 4.2).
// The browser projects (apps/web as `browser`, packages/vault as `vault-browser`, packages/core as `core-browser`) load only when LEGX_BROWSER=1, so
// unit and integration runs never depend on the web toolchain: `LEGX_BROWSER=1 pnpm vitest run --project browser`.
const browser =
  process.env.LEGX_BROWSER === '1'
    ? [
        'apps/web/vitest.browser.config.ts',
        'packages/vault/vitest.browser.config.ts',
        'packages/core/vitest.browser.config.ts',
        'apps/vault-host/vitest.browser.config.ts',
      ]
    : [];

export default defineConfig({
  test: {
    projects: [
      ...browser,
      {
        extends: true,
        test: {
          name: 'unit',
          include: ['{packages,services,apps,tools}/*/test/**/*.test.ts', 'spec/test/**/*.test.ts'],
          exclude: ['**/node_modules/**', 'apps/web/**', '**/*.browser.test.*'], // browser tests run in their own projects
          environment: 'node',
        },
      },
      {
        extends: true,
        test: {
          name: 'integration',
          include: ['{packages,services,apps,tools}/*/test-int/**/*.int.test.ts'],
          exclude: ['**/node_modules/**'],
          environment: 'node',
          testTimeout: 600_000,
          hookTimeout: 600_000,
          fileParallelism: false,
        },
      },
      {
        // Phase 6: the composed server in containers `legx-sys-*` (Postgres 5520, ledger 6120). `pnpm vitest run --project system`.
        extends: true,
        test: {
          name: 'system',
          include: ['tests/system/test/**/*.test.ts'],
          environment: 'node',
          testTimeout: 180_000,
          hookTimeout: 180_000,
          fileParallelism: false,
        },
      },
    ],
  },
});
