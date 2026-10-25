# fix-F4 (web, vault, ui)

State: done except the items under Known gaps

## Tests
- `LEGX_BROWSER=1 pnpm vitest run --project browser --project vault-browser`: 71 files passed, 756 tests passed, 8 skipped (two full runs; one earlier run had P4.7-02 WebKit fail under load).
- `pnpm --filter @legx/web test` (build, CSP runtime, budget): 15 passed. Phone route under 250 kB; xrpl is not in the entry bundle.
- `pnpm vitest run --project unit packages/vault`: 7 passed. tsc clean for web, vault, ui, vault-host except F2's `packages/core/src/passport` BufferSource errors. biome clean.

## Fixed
- I-W-2: dev proxy targets `LEGX_PORT` (default 8710) and strips `/api`; the client signs the path the server receives (OD-8). Checked with a stub server. `tests/system` ui test flipped to a plain `it`.
- I-S-A2: `CSP` carries `frame-ancestors 'none'` as a header (vite dev, preview); `CSP_META` omits it (a meta CSP ignores it). Vault host already sets `frame-ancestors <app origin>`. Source: https://www.w3.org/TR/CSP3/#directive-frame-ancestors
- I-3.7-b/c: live feed reads the server's `{type:'ledger'}` push, ignores unknown types, signs the upgrade through `?auth=` on every connect.
- I-31 (part): `createPartyServices` and `PartyHost` (lazy, `?deal=&key=`, `VITE_VAULT_ORIGIN`, `VITE_LEGX_XRPL_RPC`): requests signed inside the vault frame, records checked against the pinned hybrid registry (`keys.get`), `ledger.accountInfo`, `presence.get/submit`.
- I-29 (part): PQ binding screen and route `/party/pq-binding`.
- 4.10: DKG runs in the vault frame (`packages/vault/src/ceremony.ts`, `frame-host.ts`): shares are stored by the frame, only relay messages, events and the public result cross. Frame also enrolls keys and signs API requests.
- OD-31: `observerSigner` (vault) and `observerFeed` (web); dashboard signs its feed. OD-32: `verifyOnboardingInConsole`.
- I-W-17 browser: P4.7-02 explicit budget, P4.8-03 race (300 ms), `test:baselines` script for first-run screenshots (Vitest always fails a first baseline: https://vitest.dev/guide/browser/visual-regression-testing).
- Fixed cascades from other lanes in my tests: passport proof sets (I-S-G3), SLOT_SETUP_OK cascade (OD-21), route count 35, `zk.verify` takes side and salt, `holder_role` in the interop fixture.

## Known gaps
- Refresh, repair, recovery and rotation ceremonies still run in the page; only DKG moved.
- Shell key and badge acceptance are absent from production services (screens say so); needs a design for the party's ledger transactions.
- The phone treats every registry key as logged (`logged: true`); log inclusion is not checked on the phone.
- Dashboard: server `/ws` rule lists enrolled and lawyer only, not observer; `/health` is signed in the contract (OD-30 says unsigned); seeding must emit `VITE_LEGX_OBSERVER` JSON `{keyId, ed25519Pkcs8, mlDsa65Pkcs8}` and register both halves as `<keyId>#ed25519` and `#ml-dsa-65`.
- OD-32 function is not wired into a console onboarding flow (none exists); I-W-10 console wiring not done; system tests for party, console and dashboard still `it.fails`.
- Slow-3G test (I-5), P4.8-08, P4.8-21 not done. `LEGX_CONNECT_SRC` build variable adds the public XRPL origin to `connect-src`.

## Requests
- F3: accept observer on `/ws`; emit the observer key for the dashboard build; unsigned `/health` or a ledger index source.
- F1: confirm `zk.verify` still needs `zkSalt32` given OD-32.

## Second pass (orchestrator items)
- Refresh and repair run in the vault frame (`ceremony.ts`, tests in `packages/vault/test/frost/ceremony-frame.browser.test.ts`). Recovery and rotation hold no share (an API client and an orchestrator over `signFrost`), so there is nothing to move. Repair `receive` mode (a new device installing its share) has no end-to-end frame test.
- Shell key (`packages/vault/src/shell.ts`, `test/shell.browser.test.ts`): non-extractable Ed25519 in the frame, signs only 5a to 5g setup transactions of its own account, never Payment, EscrowCreate, offers, SetRegularKey, delegate or an AccountSet flag outside 4, 9, 12 to 15, and is wiped after DisableMaster. Party app: `createShellKey` for Alice returns the address. AccountDelete (closing an abandoned shell) is not signed: its destination needs the sealed payout, which does not exist yet. Not built: the page driving steps 5a to 5g.
- Badge acceptance stays absent: `CredentialAccept` is signed by the client's own XRPL account, and no design says where that key lives (DQ for the orchestrator). The screen says so.
- I-5: `apps/web/test-build/slow3g.test.ts` (CDP Slow 3G, 400 kbit/s, 400 ms): first screen in under 20 s over no more than the budget. The test server now gzips.
- P4.8-08: bb.js 5.0.0 starts without SharedArrayBuffer in Chromium and WebKit, so `reverifyInBrowser` (`src/zk/reverify.ts`) re-verifies in the page; `verifyOnboardingInConsole` takes `reverify` and a local failure blocks (`LOCAL_REVERIFY_FAILED`). Needs 24 MB of CRS points (BN254 g1 8 MB range, Grumpkin g1 16 MB) from crs.aztec-labs.com, which must be self-hosted and allowed in `connect-src` together with `data:` (bb.js loads its WASM from a data: URL; `LEGX_CONNECT_SRC` accepts `data:`). The two re-verify tests skip unless the CRS files are in `build/tmp/F4/` (g2.dat is committed in `test/fixtures`); they passed on both engines here.
- P4.8-21: `IdentityChangePanel` (`-console/identity-change.tsx`): 4-of-4 seal update, old and new seal, per-slot status, a refusal shown as a stall (O9) and recorded once. Not mounted in the console page: the slot responses come from the signing requests.
- F3 is done: `pnpm dev` after seeding gives the dashboard the seeded observer key and the standalone ledger RPC (`dev-env.ts`, never in a build or production). The server accepts the observer on `/ws`.
- I-W-10 stays open: the contract has no route that lists a lawyer's deals, and `createConsoleDeps` (vault, HSM, ops key, registry, ~20 ports) is a separate piece of work. Request F1: `deals.list` for lawyers.
- Browser tests run one file at a time per browser (`fileParallelism: false`): the full run is green in 3.5 minutes; with parallel pages the WebKit FROST tests starved (I-W-17).
- Final gates: browser plus vault-browser 75 files, 796 passed, 6 skipped; `pnpm --filter @legx/web test` 19 passed; phone route 172.8 kB; vault unit 7 passed; biome and tsc clean (except F2's core passport errors).

## Third pass (OD-33)
- `vault.signSingle` and the `xrpl-single` request kind (`packages/vault/test/single.browser.test.ts`, 14 cases): the frame signs only the sealed `CredentialAccept` with the FROST pair and returns the blob. The lawyer console refuses to describe that kind.
- Party step 5f: `acceptBadge` (`-badge.ts`) builds the transaction from the deal it recomputed the seal of (account from the sealed slot key, issuer the sealed wallet, type `LEGX_PARTY_<side>`, sequence from `ledger.accountInfo`, `LastLedgerSequence` = validated index + 20 from the phone's node), signs in the frame, submits through `ledger.submit`, and fails unless the ledger validated `tes...`.
- Steps 5a to 5g: `runLockSequence` (`-lock.ts`) signs the ten setup transactions (SignerListSet, AccountSet Domain and DepositAuth, four AccountSets 12 to 15, DepositPreauth, two CredentialCreate with the URI from the stored `key.bound` binding signatures, DisableMaster last) one validated ledger at a time, stops at the first refusal, and checks that the sealed wallet is the shell this device made. Lock screen button "Set up the deal wallet" with per-step progress. Fee is 10 drops (DESIGN 5.2 table); no live ledger run (no containers here).
- I-31 is now fixed. I-W-10 stays open: `deals.mine` exists, but the console needs a decision on the lawyer's identity key (enrollment keys are per deal in the vault, a directory key is not) before its ports can be composed. Request for the orchestrator.
- Both browser configs run one file at a time (`fileParallelism: false`); full run green: 77 files, 826 passed, 6 skipped (4.8 minutes).

## Fourth pass (OD-35, I-W-10)
- `/lawyers` lists the deals from the vault's own metadata: `vault.deals()` (enrollment rows of the lawyer's namespace) and, per deal, `deals.mine` signed with that deal's console key (`-deals.tsx`, `-deals-host.tsx`, test `test/lawyers/deals.browser.test.tsx`). A deal the server refuses stays in the list with its error. The frame remembers each deal's key pair id (`enroll(dealId, pairId)`, `pairs.ts`).
- Shared with the party app: `lib/vault-frame.tsx` (`VaultFrameGate`, `frameApiClient`); `PartyHost` now uses them. Console ports composed: `contractLedgerRelay`, `rpcPublicLedger` (`-console/compose.ts`).
- Not composed (the row stays `partly fixed`): `signer` (a hybrid signer over arbitrary evidence needs a frame op that restricts what it signs), `slot` (the lawyer DKG slot plus the firm HSM relay and the approval prompt), `ops` key, `evidence` port, `identity` (salt, trust list), `registry`, `lawyerKeyIds`. The console halves therefore still render only through `ConsoleProvider` in tests.
- `main.tsx` imports `-jitless.ts` first: a shared chunk that builds zod schemas at load otherwise ran zod's `new Function` probe before a route's own import (Trusted Types violation in the build runtime test).
- Gates: browser plus vault-browser 79 files, 840 passed, 6 skipped; web test 19 passed; phone route 173 kB.
