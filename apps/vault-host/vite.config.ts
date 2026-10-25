import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';

// Reproducible build settings (IMPLEMENTATION 4.10, P4.10-01). Every choice below removes one source of variation:
// - a fixed `base`, so no absolute path or origin enters the output;
// - no source maps (they embed source paths), no compressed-size report, no public dir copy;
// - one JS file and one CSS file (no chunk splitting), so the CSP can name one script hash and no import graph exists;
// - names that are a hash of the content, and `assetsInlineLimit: 0` so no asset is inlined by a size heuristic;
// - `modulePreload: false`, so the page carries no generated preload tags.
// The remaining inputs are the lockfile (exact versions), the Node version (`.nvmrc`) and the three constants below.
// Source: https://vite.dev/config/build-options (sourcemap, assetsInlineLimit, cssCodeSplit, modulePreload, rollupOptions)
// Source: https://rolldown.rs/reference/OutputOptions.codeSplitting (false: everything in one file)
// Source: https://vite.dev/config/shared-options#define
const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as { version: string };

export default defineConfig({
  base: './',
  // I-20: xrpl's optional confidential-transfer WASM (2.1 MB) stays out of the vault: it is loaded lazily and never reached.
  resolve: { alias: { '@xrplf/mpt-crypto': fileURLToPath(new URL('./src/no-mpt-crypto.ts', import.meta.url)) } },
  publicDir: false,
  define: {
    __RELEASE_URL__: JSON.stringify(process.env.LEGX_RELEASE_URL ?? ''),
    __RELEASE_KEYS__: process.env.LEGX_RELEASE_KEYS ?? '{"ed25519":"","mlDsa65":""}',
    __VAULT_VERSION__: JSON.stringify(process.env.LEGX_VAULT_VERSION ?? pkg.version),
  },
  build: {
    target: 'es2022',
    sourcemap: false,
    cssCodeSplit: false,
    modulePreload: false,
    assetsInlineLimit: 0,
    reportCompressedSize: false,
    emptyOutDir: true,
    rollupOptions: {
      output: {
        codeSplitting: false,
        entryFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
});
