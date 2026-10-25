import { existsSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import tailwindcss from '@tailwindcss/vite';
import { tanstackRouter } from '@tanstack/router-plugin/vite';
import react from '@vitejs/plugin-react';
import { defineConfig, type Plugin, type UserConfig } from 'vite';
import { VitePWA } from 'vite-plugin-pwa';
import { CSP as BASE_CSP, CSP_META as BASE_CSP_META, withConnectSrc } from './csp.ts';
import { devEnvFromDemoState } from './dev-env.ts';
import { pwaOptions } from './pwa.ts';
import { API_BASE, LIVE_PATH } from './src/lib/paths.ts';

// LEGX_CONNECT_SRC: comma-separated public XRPL node origins the console and the dashboard may reach (OD-10).
const { CSP, CSP_META } = process.env.LEGX_CONNECT_SRC
  ? withConnectSrc(process.env.LEGX_CONNECT_SRC.split(',').map((s) => s.trim()))
  : { CSP: BASE_CSP, CSP_META: BASE_CSP_META };

// The dev server needs inline scripts (React refresh), so the CSP is applied to build output and `vite preview` only.
const cspMeta = (): Plugin => ({
  name: 'legx-csp-meta',
  apply: 'build',
  transformIndexHtml: () => [
    { tag: 'meta', attrs: { 'http-equiv': 'Content-Security-Policy', content: CSP_META }, injectTo: 'head-prepend' },
  ],
});

// MSW's worker script lives in public/ for the tests and `vite dev`; the production build must not ship it.
// Source: https://vite.dev/guide/assets#the-public-directory (public files are copied as they are)
const dropMockWorker = (): Plugin => ({
  name: 'legx-drop-mock-worker',
  apply: 'build',
  closeBundle() {
    rmSync(join(this.environment.config.build.outDir, 'mockServiceWorker.js'), { force: true });
  },
});

// xrpl 5 loads `@xrplf/mpt-crypto/wasm` (confidential MPT, about 2 MB of WASM) on demand. The app never uses
// confidential MPT, so the build swaps that one module for a stub that throws: no WASM in the bundle (IMPLEMENTATION 4.4).
// Source: https://vite.dev/guide/api-plugin#universal-hooks (resolveId, load); @xrplf/mpt-crypto 0.1.1 dist/esm/module.js
const MPT_WASM_STUB = '\0legx-no-mpt-wasm';
const noMptWasm = (): Plugin => ({
  name: 'legx-no-mpt-wasm',
  enforce: 'pre',
  resolveId: (id) => (id === '@xrplf/mpt-crypto/wasm' ? MPT_WASM_STUB : undefined),
  load: (id) =>
    id === MPT_WASM_STUB
      ? "export default async () => { throw new Error('confidential MPT is not supported in this app'); };"
      : undefined,
});

const SERVER = `http://127.0.0.1:${process.env.LEGX_PORT ?? 8710}`;
// The dev server needs inline scripts (React refresh), so its header carries only the framing rule.
const CSP_DEV = "frame-ancestors 'none'";

// Source: https://vite.dev/config/server-options#server-allowedhosts
// Source: https://tanstack.com/router/latest/docs/framework/react/installation/with-vite
// No Node polyfills on purpose: xrpl.js 5 runs in browsers without them (proved by test/xrpl-smoke.browser.test.ts).
export default defineConfig(({ command }) => {
  // `pnpm dev` after `scripts/demo/seed.ts`: the dashboard's observer key and the standalone ledger RPC (dev-env.ts).
  const state = join(import.meta.dirname, '../../demo/state.json');
  Object.assign(
    process.env,
    devEnvFromDemoState(existsSync(state) ? readFileSync(state, 'utf8') : undefined, { command, env: process.env }),
  );
  return config;
});

const config: UserConfig = {
  plugins: [
    tanstackRouter({ target: 'react', autoCodeSplitting: true }), // must come before react()
    react(),
    tailwindcss(),
    cspMeta(),
    dropMockWorker(),
    noMptWasm(),
    VitePWA(pwaOptions(process.env)),
  ],
  build: { target: 'es2022', manifest: true },
  server: {
    host: true,
    allowedHosts: ['.trycloudflare.com', '.ts.net', '.ngrok-free.app', '.loca.lt'],
    headers: { 'Content-Security-Policy': CSP_DEV },
    // The server mounts every route at its root (apps/server/src/compose.ts) and listens on LEGX_PORT, default 8710
    // (apps/server/src/main.ts), so `/api` is a prefix of the browser only: it is stripped here, and the client signs the
    // path the server sees (lib/api.ts). `/ws` is already unprefixed.
    // Source: https://vite.dev/config/server-options#server-proxy
    proxy: {
      [API_BASE]: { target: SERVER, rewrite: (p) => p.slice(API_BASE.length) || '/' },
      [LIVE_PATH]: { target: SERVER.replace(/^http/, 'ws'), ws: true },
    },
  },
  preview: { headers: { 'Content-Security-Policy': CSP } },
};
