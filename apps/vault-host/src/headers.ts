// The vault origin's response headers (DESIGN 6.4, IMPLEMENTATION P4.10-06). Derived from the signed manifest:
// `script-src` names the SHA-256 of the entry script and nothing else, so no other script can run, and the page's
// `<script integrity>` carries the same hash (SRI). `frame-ancestors` names the app origin only.
// Browser-safe and Node-safe: the host config, the test server and the header test all call this one function.
// Source: https://www.w3.org/TR/CSP3/#directive-frame-ancestors
// Source: https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy/script-src (hash + integrity)
import { VAULT_CSP } from '@legx/vault/csp';

export interface HeaderOptions {
  appOrigin: string;
  /** Origin that serves release.json: the only host the frame may fetch besides itself. */
  releaseOrigin: string;
  /** `sha256-...` of each entry script (from `cspHash`). */
  scriptHashes: readonly string[];
  /** Where the browser sends CSP violation reports. */
  reportUri?: string;
}

/** `VAULT_CSP` from @legx/vault, narrowed to this bundle: its script hash, its own origin and the release host. */
export function vaultHostCsp(o: HeaderOptions): string {
  const directives = new Map(
    VAULT_CSP.split('; ').map((d) => {
      const [name = '', ...rest] = d.split(' ');
      return [name, rest.join(' ')] as const;
    }),
  );
  directives.set('script-src', o.scriptHashes.map((h) => `'${h}'`).join(' '));
  directives.set('connect-src', `'self' ${o.releaseOrigin}`);
  directives.set('frame-ancestors', o.appOrigin);
  if (o.reportUri) directives.set('report-uri', o.reportUri);
  return [...directives].map(([n, v]) => `${n} ${v}`).join('; ');
}

export function securityHeaders(o: HeaderOptions): Record<string, string> {
  return {
    'Content-Security-Policy': vaultHostCsp(o),
    // No cache: the next load re-checks the bundle, and no service worker is ever registered on this origin.
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Resource-Policy': 'cross-origin',
  };
}

/** The `_headers` file format of Netlify and Cloudflare Pages: one block for every path. */
export const headersFile = (o: HeaderOptions): string =>
  `/*\n${Object.entries(securityHeaders(o))
    .map(([k, v]) => `  ${k}: ${v}`)
    .join('\n')}\n`;
