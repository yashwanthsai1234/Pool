# @legx/vault sources

| URL | Used for |
|---|---|
| https://www.rfc-editor.org/rfc/rfc9591 | FROST signing rounds, nonce rules (7.3), message validation (7.7) |
| https://github.com/paulmillr/noble-curves/blob/2.4.0/src/abstract/frost.ts | `ed25519_FROST` behind `@legx/core/frost` (task 1.15) |
| https://w3c.github.io/webauthn/#prf-extension | PRF extension: `eval.first`, `results.first` (32 bytes), `enabled` at create |
| https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/WebAuthn_extensions | PRF inputs and outputs at create and get; using the output as a symmetric key seed |
| https://simplewebauthn.dev/docs/packages/browser | `startRegistration`, `startAuthentication` (v14.0.0) |
| https://github.com/MasterKale/SimpleWebAuthn/blob/master/packages/browser/src/methods/startAuthentication.ts | `extensions` passed through unchanged; `clientExtensionResults` returned raw |
| https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/ | Virtual authenticators in tests (`addVirtualAuthenticator` with `hasPrf`, `getCredentials`, `setUserVerified`) |
| https://raw.githubusercontent.com/ChromeDevTools/devtools-protocol/master/pdl/domains/WebAuthn.pdl | Exact `VirtualAuthenticatorOptions` fields |
| https://vitest.dev/guide/browser/playwright and https://vitest.dev/api/browser/commands | Browser mode, `cdp()` session on Chromium |
| https://w3c.github.io/webcrypto/ | AES-GCM, HKDF, PBKDF2, Ed25519, non-extractable keys, CryptoKey structured clone |
| https://www.rfc-editor.org/rfc/rfc5869 | HKDF from the PRF output |
| https://csrc.nist.gov/pubs/sp/800/38/d/final | 96-bit random GCM IVs |
| https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2 | PBKDF2-HMAC-SHA256 at 600,000 iterations for recovery codes |
| https://www.rfc-editor.org/rfc/rfc4648#section-6 | Base32 recovery codes |
| https://w3c.github.io/IndexedDB/#transaction-concept | Atomic single-transaction writes (quota error leaves nothing) |
| https://developer.mozilla.org/en-US/docs/Web/API/StorageManager/persist | `navigator.storage.persist()` |
| https://html.spec.whatwg.org/multipage/web-messaging.html#message-channels | MessagePort transport for the frame and the co-signer |
| https://www.w3.org/TR/CSP3/ | Vault frame CSP; `script-src` without `'unsafe-inline'` blocks `javascript:` URLs |
| https://w3c.github.io/trusted-types/dist/spec/ | `require-trusted-types-for 'script'`, `trusted-types 'none'` |
| https://zod.dev/api | Strict schemas for the frame messages and the backup file |

## FROST in the browser (task 4.7, `src/frost/`)

| URL | Used for |
|---|---|
| https://www.rfc-editor.org/rfc/rfc9591 | two-round signing over the relay, vectors (Appendix E.1) |
| https://frost.zfnd.org/tutorial/dkg.html | broadcast channel and authenticated, confidential round 2 |
| https://frost.zfnd.org/tutorial/refreshing-shares.html | keep old shares until every holder refreshed (`endRefresh`) |
| https://github.com/ZcashFoundation/frost/blob/frost-ed25519/v3.0.0/frost-core/src/keys/repairable.rs | repair helper and new-holder steps |
| https://github.com/ZcashFoundation/frost/blob/frost-ed25519/v3.0.0/frost-core/src/keys/refresh.rs | refresh steps |
| https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion | `requestApproval(hash)` assertion fields |
| https://simplewebauthn.dev/docs/packages/browser | `startAuthentication` for the approval |
| https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/ , https://www.rfc-editor.org/rfc/rfc9180 | share transport cipher |
| https://chromedevtools.github.io/devtools-protocol/tot/Emulation/#method-setCPUThrottlingRate , https://raw.githubusercontent.com/ChromeDevTools/devtools-protocol/master/pdl/domains/Emulation.pdl | 4x CPU throttle in P4.7-11 |
| https://mswjs.io/docs/api/http | relay, recovery and HSM mocks in the screen tests |
| services/coordinator/src/frost/{schema,relay}.ts, services/recovery-agent/src/{wire,holder}.ts | wire format and holder protocol mirrored (interop test) |

## Post-quantum keys in the browser (task 4.9, `src/pq/`)

| URL | Used for |
|---|---|
| https://csrc.nist.gov/pubs/fips/204/final | ML-DSA-65: 32-byte seed keygen, sizes, the context string |
| https://github.com/paulmillr/noble-post-quantum | 0.7.1 API (`keygen(seed)`, `sign(msg, sk, { context })`), not audited, no constant-time claim |
| https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/ | X-Wing: the 32-byte decapsulation seed, draft-11 vectors |
| https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files | ML-DSA keyGen and sigGen vectors (core's copies) run in the browser |
| https://chromedevtools.github.io/devtools-protocol/tot/Emulation/#method-setCPUThrottlingRate | 4x CPU throttle for P4.9-07 |
| DESIGN.md 6.3, 6.13, 8.10; build/DECISIONS.md OD-5, OD-21, OD-31 | enrollment keys, the 2-of-3 binding, API request signing |
| https://github.com/secure-systems-lab/dsse/blob/master/protocol.md | DSSE v1.0.2 PAE: what the frame's evidence signer parses before it signs (`dsse.ts`) |
| https://www.rfc-editor.org/rfc/rfc9881 | ML-DSA PKCS#8 seed-only form: the 22-byte prefix `3034020100300b060960864801650304031204228020` (observer key) |
| https://html.spec.whatwg.org/multipage/web-messaging.html#message-channels | the `signSlot`, `signHybrid`, `signerKeys` and `openBox` frame ops, and the HSM start call that crosses back to the page |
| DESIGN.md 6.2, 6.4, 6.10; build/DECISIONS.md OD-32 | slot signing with the firm HSM in the frame; the client's own lawyer opens the `zk-salt` and `zk-disclosure` boxes |
