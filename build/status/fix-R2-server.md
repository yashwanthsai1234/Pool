# fix-R2-server (lanes F1 + F3, round 2)

State: done, with the gaps below.

## Done (test first)
1. `ledger.validated` was already in `OutboxTopic` (contracts 1.1.0); the wiring pin is now a plain `it`. Producers: `frost.recovery.signed` (recovery agent `onSigned`, `recoverySignedData`) and `release_code.handed_over` (coordinator `ACTORS`: lawyer B).
2. `deal.event`, `deal.state`, `signature.request` rows are written in the coordinator transaction with one gap-free per-deal seq (`OutboxRepo.enqueueNext`, advisory lock). The pump's derived rows are deleted. Outbox seq is no longer the evidence seq. `signature.request` pin stays `it.fails` (deals.create makes no request).
3. `demoFirmDeps` (apps/server `agents.ts`): real `FirmCosigner`, own key pair in the data folder, own signer file, `firmHsm.sign` mounted at its contract path; `demoAgentDeps` has durable evidence (coordinator-signed `frost.*`), `alert` notices, real deal facts and key lists. `build/tmp/firm-hsm-ready` touched.
4. I-W-13 partly: recovery proof port still refuses (I-21); no route runs the HSM DKG. I-W-14: allow-listed (KEM-only `hybrid.js`), because core's `ShareCipher` is synchronous. Request F2: async `ShareCipher` in core, then drop `cipher.ts` from the list.
5. SYS-I2 container names: `LEGX_SYS_PG_CONTAINER`, `LEGX_SYS_LEDGER_CONTAINER` (also `LEGX_SYS_SERVER_PORT`, `LEGX_SYS_REGISTRY_PORT`). REGRESSION.md regenerated; catalogue test green.
6. OD-34: `attest.ts` (core, cross-lane edit, 4 lines) accepts `face_match_passed: false` only in demo for a `dev_mode` record; `releaseGate.ts` adds finding `DEMO_NO_FACE_MATCH` (`level: warn`, `ok: true`, detail = sides); contracts `GateWarnCode` (1.2.0, JSON schemas regenerated); production refuses; xrpl `zkFlow.ts` records false; DESIGN 6.15 line. Tests changed for it: `zkIdentity.attest.test.ts` P1.17-04, `e2e-paper-deal.test.ts` Z-13 (now "absent").
7. OD-36 (b): `identityBox.put` (client, own side) and `identityBox.get` (that side's lawyer console key) in contracts and coordinator; migration 0004 `identity_box` (insert-only); examples, snapshots and pg_dump regenerated. `scripts/demo/sign.ts` uses the vault `observerSigner` again.
Rows marked: I-W-5, I-W-13 (partly), I-W-14, I-DOC-1, I-2.9-f.

## Tests (ports 5550 / 6150, containers legx-r2-*, stopped)
- unit: contracts, db, coordinator, recovery-agent, firm-cosigner, renewal, apps/server, core: green (load flakes seen alone-pass: evidence anchor/pq, server gate "not minted").
- integration: db, coordinator, recovery-agent, firm-cosigner, renewal, apps/server: green (coordinator model.int failed once on a random run, passed on rerun).
- tests/system one file at a time: catalogue 3, wiring 83 + 9 expected-fail, sys 20 + 12 expected-fail + 12 todo, ui 3 + 3 expected-fail (`I-W-2` pin flipped to `it`).
- dry run (own stack): 10/13 (3 missing assets: zk-prove, recorded proofs, backup video).
- Not run: `packages/xrpl/test-int/zk` (needs Sepolia and the circuit CDN); edited only.

## Requests
- F4: web gate code treats `!f.ok` as failure, so the warning (`ok: true`) is safe; show `DEMO_NO_FACE_MATCH` in the console. The console should post boxes to `identityBox.put`.
- F2: see I-W-14.
