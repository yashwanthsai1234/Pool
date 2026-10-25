import type { VitePWAOptions } from 'vite-plugin-pwa';
import { API_BASE, LIVE_PATH } from './src/lib/paths.ts';

// Source: https://vite-pwa-org.netlify.app/guide/unregister-service-worker.html (selfDestroying kill switch)
// Source: https://vite-pwa-org.netlify.app/workbox/generate-sw (navigateFallbackDenylist, globIgnores)
// Source: https://developer.chrome.com/docs/workbox/modules/workbox-build#type-GenerateSWOptions
const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

/** `PWA_SELF_DESTROY=1` builds a service worker that unregisters itself and clears caches (a stale build during rehearsal). */
export function pwaOptions(env: Record<string, string | undefined>): Partial<VitePWAOptions> {
  return {
    registerType: 'autoUpdate',
    injectRegister: false, // registered by src/lib/sw.ts through a Trusted Types policy
    selfDestroying: env.PWA_SELF_DESTROY === '1',
    manifest: {
      name: 'Legx',
      short_name: 'Legx',
      display: 'standalone',
      start_url: '/',
      theme_color: '#1d4ed8',
      background_color: '#ffffff',
      icons: [
        { src: '/icon-192.png', sizes: '192x192', type: 'image/png' },
        { src: '/icon-512.png', sizes: '512x512', type: 'image/png' },
        { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
      ],
    },
    workbox: {
      globPatterns: ['**/*.{js,css,html,svg,png,webmanifest}'],
      // xrpl 5 ships a 2 MB confidential-MPT WASM behind a dynamic import; never precache it. MSW's worker is test-only.
      globIgnores: ['**/*.wasm', '**/mockServiceWorker.js'],
      // No runtimeCaching: API and socket traffic is never cached, and never answered by the navigation fallback.
      navigateFallbackDenylist: [
        new RegExp(`^${escapeRegExp(API_BASE)}(/|$)`),
        new RegExp(`^${escapeRegExp(LIVE_PATH)}(/|$)`),
      ],
    },
  };
}
