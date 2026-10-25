# Sources (apps/web)

- Vite 8 server options (allowedHosts, proxy): https://vite.dev/config/server-options
- Vite build manifest (bundle budget): https://vite.dev/config/build-options#build-manifest
- TanStack Router with Vite, file routes, autoCodeSplitting: https://tanstack.com/router/latest/docs/framework/react/installation/with-vite
- TanStack Query: https://tanstack.com/query/latest/docs/framework/react/overview
- Tailwind CSS 4 with Vite: https://tailwindcss.com/docs/installation/using-vite
- vite-plugin-pwa 2.0 (selfDestroying, workbox options): https://vite-pwa-org.netlify.app/guide/unregister-service-worker.html and https://vite-pwa-org.netlify.app/workbox/generate-sw
- Workbox GenerateSW options: https://developer.chrome.com/docs/workbox/modules/workbox-build
- CSP: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP
- Trusted Types: https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API and https://w3c.github.io/trusted-types/dist/spec/
- crypto.subtle secure-context rule: https://developer.mozilla.org/en-US/docs/Web/API/Crypto/subtle
- xrpl.js in browsers without polyfills: https://github.com/XRPLF/xrpl.js/blob/main/UNIQUE_SETUPS.md
- Vitest browser mode with Playwright: https://vitest.dev/guide/browser/playwright
- axe-core: https://github.com/dequelabs/axe-core
- WCAG 2.2 contrast ratio: https://www.w3.org/TR/WCAG22/#dfn-contrast-ratio
- oRPC OpenAPILink and contract-first client (`createORPCClient`, `JsonifiedClient`): https://orpc.dev/docs/openapi/client/openapi-link
- MSW 3 WebSocket mocking (`ws.link`, `connection` event, `client.send`, `client.close`): https://mswjs.io/docs/api/ws
- MSW 3 `worker.start` (`onUnhandledFrame`, `quiet`, `serviceWorker.url`): https://mswjs.io/docs/api/setup-worker/start
- MSW REST handlers (`http.get`, `HttpResponse.json`): https://mswjs.io/docs/api/http
- WebSocket events and close codes: https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API and https://www.rfc-editor.org/rfc/rfc6455#section-7.4
- TanStack Query `setQueryData`, `skipToken`: https://tanstack.com/query/latest/docs/reference/QueryClient#queryclientsetquerydata
- CSP3 `'self'` and WebSocket URLs: https://www.w3.org/TR/CSP3/#match-url-to-source-expression
- Vite glob import (golden examples as mock data): https://vite.dev/guide/features#glob-import

## Task 4.7
| URL | Used for |
|---|---|
| https://tanstack.com/router/latest/docs/framework/react/routing/file-naming-conventions | `-screens` folder kept out of the route tree |
| https://vite.dev/guide/api-plugin#universal-hooks | `legx-no-mpt-wasm` stub so xrpl's confidential-MPT WASM is not bundled |
| https://mswjs.io/docs/api/http | FROST relay, recovery and firm-HSM mocks |
- ZKPassport SDK 0.19.2 request flow (src/zk): https://docs.zkpassport.id and the package typings (request, QueryBuilder, callbacks)
- QR code generation (qrcode-generator 2.0.4): https://github.com/kazuhikoarase/qrcode-generator ; decoding in tests (jsQR 1.4.0): https://github.com/cozmo/jsQR

## Lawyer console (task 4.4)
- https://xrpl.org/docs/references/protocol/binary-format : signing prefixes (`SMT\0` for multi-signing, decoded by the approval prompt) and single-signing of the mint and the EscrowFinish.
- https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/ledger-methods/ledger : the console's own read-only validated-ledger check (OD-10).
- https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion : the lawyer's user-verified approval over SHA-256 of the exact message.
- https://www.rfc-editor.org/rfc/rfc9180 and https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/ : X-Wing HPKE for the release-code handover (OD-28).

## Party app (task 4.3)
- https://xrpl.org/docs/references/protocol/binary-format : encode/decode of the canonical transaction bytes (`-check.ts`, decoded on the phone).
- https://xrpl.org/docs/references/protocol/ledger-data/ledger-entry-types/accountroot : `lsfRequireDestTag` (0x00020000) for the destination-tag warning.
- https://zod.dev/api (z.config jitless) : the Trusted Types CSP and zod's `new Function` probe.
## Lawyer console services (I-W-10, round 2)
- https://www.rfc-editor.org/rfc/rfc9562#section-5.7 : UUIDv7 for the evidence event ids (`services.ts`).
- services/firm-cosigner/src/cosigner.ts `operatorRequestMessage` : the operations key's request to the firm HSM (vector in `test/lawyers/services.browser.test.tsx`).
- https://www.w3.org/TR/webauthn-3/#sctn-discoverable-credential : the approval prompt without a stored credential id (`webauthnApproval(rpId)`).
- build/DECISIONS.md OD-32, OD-35 : onboarding verification in the console; deals listed from vault metadata.
