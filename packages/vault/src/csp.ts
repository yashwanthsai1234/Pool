// The vault frame's Content Security Policy (IMPLEMENTATION 4.2 "Think hard"). Stricter than the app's: the frame
// makes no network requests at all (`connect-src 'none'`), so even script that ran inside it could not send a share
// anywhere but through the message port. Trusted Types with no policy refuses every string-to-script sink.
// Task 4.10 sends it as a header and adds `frame-ancestors <app origin>` (a <meta> CSP cannot carry that).
// Source: https://www.w3.org/TR/CSP3/ (script-src without 'unsafe-inline' also blocks javascript: URLs, section 6.1.11)
// Source: https://w3c.github.io/trusted-types/dist/spec/#trusted-types-csp-directive ('none' allows no policy)
export const VAULT_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'none'",
  "img-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "require-trusted-types-for 'script'",
  "trusted-types 'none'",
].join('; ');
