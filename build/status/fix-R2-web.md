# fix-R2-web (lane F4, round 2)

State: done, except the items under Known gaps. `build/tmp/firm-hsm-ready` did not exist when I finished, so the slot ran against MSW and the real vault frame plus a mock HSM only (see Evidence).

## Tests
- `LEGX_BROWSER=1 pnpm vitest run --project browser --project vault-browser`: 89 files passed, 1 skipped; 910 tests passed, 6 skipped (Chromium and WebKit).
- `pnpm --filter @legx/web test` (build, CSP runtime, phone-route budget under 250 kB, slow 3G): 19 passed.
- `pnpm vitest run --project unit packages/vault`: 12 passed (new `dsse.test.ts` property tests, observer prefix test).
- `pnpm exec tsc -p` for apps/web, packages/vault, packages/ui: clean. `pnpm exec biome check apps/web packages/vault packages/ui`: clean.

## Real server run (firm-hsm-ready existed)
`tests/system/test/console.test.ts` (run with the legx-r2 containers: `LEGX_SYS_PG=...5550 LEGX_SYS_LEDGER=ws://127.0.0.1:6150 LEGX_SYS_PG_CONTAINER=legx-r2-pg LEGX_SYS_LEDGER_CONTAINER=legx-r2-xrpld LEGX_SYS_SERVER_PORT=8791 LEGX_SYS_REGISTRY_PORT=7091 pnpm vitest run --project system tests/system/test/console.test.ts`): 2 passed. The real `firm-hsm/sign` accepts the console's body (operator message from the console's own helper) for the lawyer of the slot and refuses the other slot and a client; `identity-box.get` answers the lawyer of side A and refuses the other side and the client. First run caught my test using a 16-byte session id (the contract wants 32). NOT run: a full signing round with the real HSM (needs a DKG with the HSM in the stack), and the I-W-10 `it.fails` in `tests/system/test/ui.test.ts` is NOT flipped: its web env has no served, release-signed vault origin (the frame refuses without a signed release), so `/lawyers` cannot list deals there.
- Route count in `apps/web/test/api.browser.test.ts` is now 38 (F1 added `identityBox`).

## Fixed
- **Observer prefix typo** (F3's finding): `PQ_PREFIX` in `packages/vault/src/pq/observer.ts` was `...0422802` (43 hex digits) and is now the 22-byte RFC 9881 prefix `3034020100300b060960864801650304031204228020`. The old prefix accepted a key whose last prefix byte was `0x2x`; new test in `test/pq/observer.test.ts` fails on the old code. `scripts/demo/sign.ts` can drop its seed-reading workaround (see Requests).
- **I-W-10** (row marked fixed): `/lawyers?deal=<id>&role=LA|LB` boots `LawyerConsoleHost` (`-console-host.tsx`), which calls `createConsoleDeps` (`-console/services.ts`). Same composition pattern as `PartyHost` and `createPartyServices`: `frameApiClient`, `VaultFrameGate`, `xrplRpc`, `contractLedgerRelay`; nothing is duplicated. The deal, the registry, both lawyers' key ids, the slot holders and the ledger history all come from one validated `ledger.snapshot`. The deal list rows link to the console.
  - **signer**: frame ops `signHybrid` and `signerKeys` (`frame-host.ts`, `dsse.ts`). The frame signs only the PAE of the two evidence payload types whose JSON body names the key's own deal, under `legx/dsse/v1`. It refuses free text, other contexts, another deal, bad lengths, trailing bytes. Web `frameSigner` refuses any other context before it asks.
  - **slot**: frame op `signSlot` (`ceremony.ts`, `protocol.ts`). Share 1 in the frame, the relay and the HSM start call cross back to the page like the DKG's calls. `Vault.signFrost` takes an optional per-call remote holder (`RemoteVia`) and still checks the request against the seal first. The frame checks the lawyer's WebAuthn approval is over the hash of the bytes it derived itself. Web `firmHsmSlot` calls `firm-hsm/sign` with the operations key's signature over `legx/firm-cosign-request/v1` (pair [1,2], the console aggregates, so no message in the call). `webauthnApproval(rpId)` works without a stored credential id (discoverable credentials).
  - **ops key**: `opsKey` over `enrollmentKeys` in this origin's own database (`legx-ops-lawyer-a|b`): non-extractable Ed25519, address derived from the key.
  - **evidence**: `apiEvidence` over `events.head` and `events.append` (`SEQ_TAKEN` on a lost race). `attach` and `condition` upload nothing: the ZK route already stores the proof set (`services/zk-verifier/src/store.ts`) and the coordinator reads the condition from the validated EscrowCreate (I-S-M2).
  - **identity**: `salt` opened in the frame (`openBox`, lawyer only, only the lawyer's own side), `zkVerify` over `zk.verify` with the opened salt, `zkRequest` from `ReleaseProofs` (the phone's proof, filled by the ZKPassport flow), CSCA list an input (empty fails closed).
  - **OD-32 onboarding**: `console.onboarding.verifyAndSign` (`-console/onboarding.ts`): `verifyOnboardingInConsole` (server sees public proofs only), the frame opens the disclosure box, the proof's person must match the sealed commitment, the attestation passes core's `verifyOnboarding`, then `identity.onboarded` is appended. Nothing is signed on any failure.

## Research notes
- DSSE PAE: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md (parsing is strict: type, decimal length without leading zeros, exact body length).
- ML-DSA PKCS#8 (seed only, 54 bytes, prefix ends `0422 8020`): https://www.rfc-editor.org/rfc/rfc9881
- Discoverable credentials, `allowCredentials` omitted: https://www.w3.org/TR/webauthn-3/#sctn-discoverable-credential
- MessagePort structured clone of `Uint8Array` across the frame: https://html.spec.whatwg.org/multipage/web-messaging.html#message-channels

## Evidence
- Slot, end to end in a real frame: `packages/vault/test/frost/slot-frame.browser.test.ts` (DKG in the frame with share 2 at a mock HSM, approval over the same hash gives a signature that verifies under the slot key; approval over another hash, a request the frame seal refuses, and an HSM refusal each fail with the right code and the HSM is not asked when it should not be).
- The operator message equals the firm cosigner's `operatorRequestMessage`: vector computed with `node build/tmp/F4/vec.ts` (97ec1a46...c08e), pinned in the services test (the service imports `node:crypto`, so the browser test cannot import it).
- Real route: not run (`build/tmp/firm-hsm-ready` absent). The MSW test pins the request body (`slot`, `pair`, `seal`, `operator`, `approval`, no `message`).

## Files created
`packages/vault/src/dsse.ts`; `packages/vault/test/{dsse.test.ts,signer.browser.test.ts,openbox.browser.test.ts,frost/slot-frame.browser.test.ts}`; `apps/web/src/routes/lawyers/-console/{services.ts,onboarding.ts}`; `apps/web/src/routes/lawyers/-console-host.tsx`; `apps/web/test/lawyers/{services,onboarding}.browser.test.tsx`. Edited: vault `frame-host.ts`, `protocol.ts`, `ceremony.ts`, `vault.ts`, `pq/keys.ts`, `pq/observer.ts`, `frost/approval.ts`; web `lawyers/index.tsx`, `-deals.tsx`, `-console/{index,ports,vaults}.ts`; SOURCES.md of both; `build/ISSUES.md` (I-W-10).

## OD-36 (answered after the first pass)
- (a) Frame seal: `packages/vault/src/seal.ts` (`sealKeeper`), ops `pinSeal` and `loadDeal`, `FrameHost.sealedDeal` is the vault's `deals`. Test first: `packages/vault/test/seal.browser.test.ts` (data with any field changed is refused, pin set once, no deal before pin and load). Deviation, with reason: the frame does not fetch `public-data` itself. Its CSP is `connect-src 'none'` and a signed request needs a validated ledger index only the page reaches. The page hands the data over and the frame recomputes `dealSeal` and compares it with the pin, so nothing in the seal can be forged by the page. The pin is set the first time the console meets the deal (TOFU, set once). Only the exit amount (`deals.get.amountDrops`) is outside the seal. The real frame (`apps/vault-host/src/frame.ts`) also served the vault with no host (enroll and signApi answered NOT_FOUND); it now builds `vaultFrameHost` and uses its `sealedDeal`.
- (b) `identity.salt()` reads `identityBox.get` (`GET /deals/:id/identity-box/:side`) and the vault opens the `zk-salt` box (`openBox`).
- Not done for the party app: its host does not pin or load the seal yet, so party signing in a production frame still refuses.

## Requests
- F3: `scripts/demo/sign.ts` can use `observerSigner` directly now (its seed-reading workaround for the ML-DSA PKCS#8 prefix is no longer needed).
- F1: the onboarding proofs and the `zk-disclosure` box are not read by the console yet (`onboarding.verifyAndSign` takes them as input); a route or field for the contract clauses and salts; `deals.mine` should return the key pair id if the console is to show it.
- Owner of `tests/system`: the web env needs `VITE_VAULT_ORIGIN` and `VITE_LEGX_XRPL_RPC` plus a served vault host and a seeded lawyer key before the I-W-10 `it.fails` can flip.

## Known gaps
- Party host: pin and load the seal (same two calls as `createConsoleDeps`).
- Contract clauses and salts have no import path: the host passes empty lists, so the contract card refuses (`ROOT_MISMATCH`) until a lawyer loads them.
- The slot holders' keys are read from the validated snapshot's registry rows, not from a ledger-anchored service key list the console verified itself (6.3).
- The identity change panel is still not mounted; the ZKPassport release flow does not yet call `ReleaseProofs.offer`; `reverify` for onboarding needs the self-hosted CRS (round 1 note).
- No browser test mounts `LawyerConsoleHost` (it needs a served vault origin); its parts are covered one by one.
