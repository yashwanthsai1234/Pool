# Sources: apps/vault-host (task 4.10)
- CSP3 hash-source, frame-ancestors, trusted types: https://www.w3.org/TR/CSP3/ , https://w3c.github.io/trusted-types/dist/spec/
- A hash in `script-src` matches an external script only when its `integrity` lists that hash: https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy/script-src , WPT `content-security-policy/script-src/script-src-sri_hash.sub.html`
- SRI: https://www.w3.org/TR/SRI/
- Vite build options (sourcemap, assetsInlineLimit, cssCodeSplit, modulePreload, rollupOptions.output): https://vite.dev/config/build-options ; define: https://vite.dev/config/shared-options#define
- Rolldown `codeSplitting: false` (one file): https://rolldown.rs/reference/OutputOptions.codeSplitting
- postMessage, origin and source checks, MessageChannel: https://html.spec.whatwg.org/multipage/web-messaging.html
- fetch `cache: 'no-store'`, `redirect: 'error'`: https://fetch.spec.whatwg.org/
- Vitest custom browser commands: https://vitest.dev/guide/browser/commands
- `_headers` file format (Netlify, Cloudflare Pages): https://developers.cloudflare.com/pages/configuration/headers/
