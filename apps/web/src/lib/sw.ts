import { SW_POLICY } from '../../csp.ts';

const SW_URL = '/sw.js';

// Service-worker registration is a Trusted Types sink. The policy accepts exactly one URL.
// Source: https://w3c.github.io/trusted-types/dist/spec/#integrations (ServiceWorkerContainer.register)
export function registerServiceWorker(): void {
  if (!import.meta.env.PROD || !('serviceWorker' in navigator)) return;
  const policy = window.trustedTypes?.createPolicy(SW_POLICY, {
    createScriptURL: (url) => {
      if (url !== SW_URL) throw new TypeError(`blocked service worker URL: ${url}`);
      return url;
    },
  });
  const url = policy ? (policy.createScriptURL(SW_URL) as unknown as string) : SW_URL;
  void navigator.serviceWorker.register(url, { scope: '/' });
}
