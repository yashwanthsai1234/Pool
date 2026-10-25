# fix-F3 (server wiring)

State: done (see Known gaps for what other lanes must finish)

## Fixed (rows marked `fixed (F3)` in build/ISSUES.md)
- **I-S-E1** `services/evidence/src/tsa.ts`: the PKI.js `SignedData.verify` result in `extendedMode` was ignored; now `signatureVerified !== true` is `SIGNATURE_INVALID`. The chain is still checked by `CertificateChainValidationEngine` at the token's own `genTime` (certificates expire before an arbitrator reads the bundle; `verify({checkChain})` with the cross-certificates DigiCert sends is refused by the engine as before). Pinned: `tests/break-it/evidence/tsa.break.test.ts` (3 pass).
  Sources: https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2 , https://github.com/PeculiarVentures/PKI.js/blob/master/src/SignedData.ts
  `nodeRootCertificates()` now uses `process.getBuiltinModule('node:tls')` so the offline bundle has no static `node:tls` import (a network-module pin of the bundle test).
- **I-S-E2, I-S-E3, I-S-E5** `tools/verifier-cli`: no pinned service key fails (`--insecure-unpinned` for tests); TSA roots come from `--tsa-roots <pem>` or the system roots, never `timestamps/roots.pem` (`--insecure-bundle-tsa-roots` for tests); an event without an inclusion proof fails. The CLI's own CMS re-check (workaround for E1) is removed. Existing CLI tests use `verifyLenient` (both insecure flags).
- **I-S-E4** `services/evidence/src/events.ts` `append`: `actor.key_id` must be the signing key, an enrollment key signs only as its slot's role, a party key never signs as coordinator/verifier/watcher.
- **I-W-15** signer: `signerContract.ts` imported a `DSSE_CONTEXT` that core does not export; the helper now declares the literal. 43 signer tests pass.
- **I-3.7-g** real wiring, one shared composition `apps/server/src/stack.ts`:
  - release gate = `@legx/core/releaseGate` `checkRelease` over one validated ledger snapshot and the stored records (`gate.ts`), fails closed (`INPUT_UNAVAILABLE:...`); `/health` port `release-gate` = `core-gate`;
  - `records.bundle` composed (BundleDeps, offline verifier built once with esbuild, `verifyScript.ts`); `bar.dealLink` (verifier `link`) and `bar.manualEvidence` (manual adapter, operator keys) served; `zk.verify` (`zk.ts`) verifies the public proofs only (OD-32: `queryResult` is replaced by `{}` before the adapter sees it) and stores via `verifyAndStore`;
  - watcher watches every deal wallet read from the DB (live `accounts` array refreshed every 500 ms), lock-checks sealed deals, and appends `lock.verified` / `ledger.disagreement` as coordinator-signed events;
  - pump: integrates every stored event into the log (`service.integrate`), publishes a checkpoint when the log grew, asks the anchor job to run; checkpoint and anchor jobs (pg-boss) and RFC 3161 time stamps (DigiCert + SSL.com, system roots) composed; `/health` lists `tsa`, `jobs`;
  - production profile: `production.ts` builds KMS signer, S3 Object Lock store, Tessera log, ledger network from env (missing setting stops the start by name), `main.ts` no longer throws "not wired".
- **I-3.7-h, I-W-4, I-W-6 (checkpoint job), I-W-7, I-W-8, I-W-9, I-W-12** see the composition above; demo keys now live in files (`service-keys.json`, `checkpoint-keys.json`).
- **I-D-1..I-D-4, OD-31** `scripts/demo/sign.ts` signs hybrid OD-5 requests with the demo enrollment keys (reuses the vault's `apiRequestSigner`/`observerSigner`); `seed.ts` makes keys for `lawyer-a`, `lawyer-b`, `operator` besides the observer; `apps/server/src/demo.ts` pins them from `demo/state.json` (`LEGX_LAWYER_KEYS`/`LEGX_OBSERVER_KEYS`/`LEGX_OPERATOR_KEYS` win when set). The live feed accepts an observer key (read only, any deal) via `observerKeys`.

## Tests
- `pnpm vitest run --project unit apps/server services/watcher services/evidence services/verifier services/zk-verifier services/renewal packages/signer packages/storage packages/observability tools/verifier-cli`: 520 pass, 16 fail on the loaded machine. Failures: the `services/evidence/test/pq` ones are 5 s timeouts under load (22 vitest processes, load 26); they pass alone (`--testTimeout=120000`: 22/22). `services/renewal noNoble` fails because of `services/recovery-agent/src/cipher.ts` (F1 lane). `apps/server/test/wiring.test.ts` fails for routes the new contract adds that F1 must serve (keys.register, firmHsm.sign, ledger.*, presence.*; my 501 stub for keys.register is removed so F1's handler cannot collide). `zk-verifier adapter CJS loading` is a timeout under load.
- `pnpm vitest run --root tests/break-it evidence`: 9 pass (E1, E2, E3, E4, E5 and I-3.7-h).
- System (my ports, containers `legx-f3-legx-sys-pg` 5530 and `legx-f3-legx-sys-xrpld` 6130, named so that `containersUp()` matches): `tests/system/test/sys.test.ts` and `wiring.test.ts`, see results at the end of this file.
- tsc: `apps/server`, `tools/verifier-cli`, `packages/signer`, `services/evidence` clean for my files (remaining tsc errors are in `packages/core` and `services/recovery-agent`, other lanes). biome clean for my packages.

## Flipped tests (tests/system)
wiring: records.bundle, bar.dealLink, zk.verify routes; deal.state producer; watcher; release-gate; zk port; TSA port; checkpoint job. sys: SYS-R1b (keys in files). SYS-11: prerequisites present (kept as a probe test; the flow itself needs the UIs). SYS-I3a drives `records.bundle` and the verifier CLI and expects exactly the two `KEY_UNKNOWN` events that `stack.pin` writes with an unregistered signer, until keys.register exists (I-W-1).

## Known gaps / requests
- **I-W-5 partial.** `deal.state` and `signature.request` rows are written (by the pump, `deal_id` NULL) but not in the per-deal feed: the outbox `seq` of a deal is the evidence seq, one row per seq, gap-free (SYS-I1, and `stack.pin` writes rows with that seq), so a second writer in the same stream breaks it. **Request F1:** write them inside the coordinator transaction with a separate gap-free outbox seq (and have `stack.pin` use the API), then the pump part can be deleted. The `signature.request` pin stays `it.fails`: `deals.create` creates no request.
- **I-W-6 partial:** kinds `attorney.credential.issued` and `checkpoint.anchored` still have no producer.
- **I-W-13 open** (agents still use `MemoryEvidence` and a refusing proof port).
- **Request F1:** serve keys.register, firmHsm.sign, ledger.*, presence.* (new contract routes); mount the firm cosigner at `/deals/{dealId}/firm-hsm/sign`.
- **Request F2:** `DSSE_CONTEXT` is not exported from `@legx/core/hybridEnvelope` (I-W-15 root cause is a test helper, fixed locally).
- **Request F4:** `scripts/dev.ts` should pass nothing new: the server reads `demo/state.json` itself.
- zk.verify: the release stage takes the bound value from the request's own `originalQuery.bind.custom_data` (the presence statement is the lawyer's secret); the full check is the lawyer console's (OD-32). Untested with a real proof (no phone).
- SYS-I2 cannot run with my container names (`docker exec legx-sys-pg`); it passes with the standard names.
- Production: the checkpoint key is a mounted secret file (no KMS signer for ML-DSA-44 exists in `@legx/signer`); issuer and anchor accounts come from seeds in env; bar registries are the operator path only (no real registry adapter exists).
- `services/watcher/test-int` and `services/evidence/test-int` hold no tests.

## Files created
`apps/server/src/{stack,production,gate,wiring,zk,verifyScript}.ts`, `apps/server/test/{production,gate}.test.ts`, `scripts/demo/sign.ts`; edited: `apps/server/src/{compose,routes,demo,live(no net change),main,evidence,agents?}.ts`, `services/evidence/src/{tsa,events,keys,pq/keyring}.ts`, `services/verifier/src/signing.ts`, `tools/verifier-cli/src/*`, `packages/signer/src/{file,index}.ts`, `scripts/demo/{lib,seed,dry-run}.ts`, tests as listed.

## Update after F1 (final)
- Applied F1's requests: `records.ts` refuses non-primary holder roles (`NOT_PRIMARY_HOLDER`, 403; I-S-A1); live feed uses the coordinator's observer auth (`observerKeys` in the coordinator deps) and `canReadDeal`; watcher `notify` is a no-op (migration 0003 trigger sends the NOTIFY); test-int support no longer creates `outbox_notify`; production test updated. `ledger.snapshot` served (`gate.ts releaseInputJson`). Coordinator routes (keys.register, presence, ledger.*, deals.mine) are served by `registerCoordinator`.
- Not done: `firmHsm.sign` (no FirmCosigner composed: it is the firm's own process, needs an HSM identity, vault, relay); `frost.session` producer. Demo log is rebuilt from `evidence_log_entry` at start (in-memory log must extend published checkpoints).
- vault `observerSigner` has a mistyped ML-DSA PKCS#8 prefix (`...0422802` for `...04228020`): request F4; `scripts/demo/sign.ts` reads the seed itself.
- Dry run (`node scripts/demo/dry-run.ts`, own stack): 10/13 steps pass; the 3 failures are tools/zk-prove, recorded proofs, backup video (I-D-5..8, not wiring).
- System (my ports): sys.test 19 pass + 12 expected-fail + 12 todo, 1 fail (SYS-I2, container-name artifact); wiring.test 77 pass, 10 expected-fail, 3 fail (OutboxTopic `ledger.validated` (F1), event kinds `frost.recovery.signed`, `release_code.handed_over` have no producer string (F1/F2)). Run each file alone: both start the mock registry on 7080.
