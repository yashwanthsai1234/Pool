// Strict Content-Security-Policy with Trusted Types (IMPLEMENTATION 4.4, pitfall 12: a CSP is the real XSS defence).
// Source: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP
// Source: https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API
// The only Trusted Types policy is `legx-sw` (src/lib/sw.ts), which allows exactly one script URL.
export const SW_POLICY = 'legx-sw';

const DIRECTIVES = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "worker-src 'self'",
  "manifest-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "require-trusted-types-for 'script'",
  `trusted-types ${SW_POLICY}`,
];

// I-S-A2: `frame-ancestors` is ignored in a <meta> element (and logs a warning), so it travels only as an HTTP header:
// `vite preview`, the dev server and any static host must send `CSP`; the <meta> copy is `CSP_META`.
// Source: https://www.w3.org/TR/CSP3/#directive-frame-ancestors  Source: https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
export const CSP_META = DIRECTIVES.join('; ');
export const CSP = [...DIRECTIVES, "frame-ancestors 'none'"].join('; ');

/**
 * The same policies with extra `connect-src` origins named at build time (the lawyer console's and the dashboard's own
 * public XRPL node, OD-10). Only plain origins are accepted: a typo cannot widen the policy to a scheme or a wildcard.
 */
export function withConnectSrc(extra: readonly string[]): { CSP: string; CSP_META: string } {
  const origins = extra.map((o) => new URL(o).origin);
  if (origins.some((o, i) => o === 'null' || extra[i]?.includes('*')))
    throw new Error('connect-src needs plain origins');
  const widen = (d: string) => (d === "connect-src 'self'" ? ["connect-src 'self'", ...origins].join(' ') : d);
  return { CSP: CSP.split('; ').map(widen).join('; '), CSP_META: CSP_META.split('; ').map(widen).join('; ') };
}
