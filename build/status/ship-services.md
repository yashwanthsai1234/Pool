# ship-services (OD-37/OD-38: coordinator, server, evidence, verifier, demo, tests, Quint)
State: done, with the gaps below.

## Done
- Coordinator (`services/coordinator/src/events.ts`): `shipment.signed` bob only, `receipt.signed` alice only (primary-holder rule unchanged); verified with core `verifyShipment` (maxAge 20) / `verifyReceipt` inside the lock; order enforced by state (VERIFIED -> SHIPPED -> RECEIVED); `release.gate.passed` and `release.performed` only from RECEIVED. A damaged or missing receipt is refused (`refused_receipt`), the deal stays SHIPPED (DQ-OD37-2).
- Server gate (`apps/server/src/gate.ts`): feeds `records.shipments` / `records.receipts`. `agents.ts` fills `SealedDeal.dealId`.
- Evidence bundle: `delivery/` folder and a `delivery` category in checks/report.json; both events are also in events/.
- `legx-verify`: `SHIPMENT_SIGNED_OK` and `RECEIPT_SIGNED_OK` report under check `delivery`; delivery DSSE files get their signatures checked.
- Demo attacks: `forged-receipt`, `swapped-manifest`, `release-before-receipt` (12 scenes). Each runs a control first, defeated with RECEIPT_SIGNED_OK (BAD_SIGNATURE / MANIFEST_MISMATCH / MISSING; the last also checks the machine refuses RELEASE_ESCROW in SHIPPED).
- `scripts/demo`: seed adds `slot-a`, `slot-b` demo keys and the demo delivery; dry-run has 3 new steps (shipment, receipt + forged receipt, attacks on the server).
- Quint `spec/deal.qnt`: SHIPPED, RECEIVED, `ship`, `receive`, gate actions and `release` only in RECEIVED; `toReceivedTest`; quint.test.ts name sets and count (34). `spec/check.sh run` (10,000 runs x 30 steps, all invariants): no violation (build/tmp/ship-quint.log). Apalache/TLC not run (5 minute box).
- Cross-package change that was unavoidable: `packages/db/migrations/0005_ship_receipt_states.sql` (the `deal_state_check` refused SHIPPED/RECEIVED, HTTP 500) plus `schema.snapshot.txt` and `schema.pg_dump.sql` lines. Please review as the db owner.

## Tests (all run with the PATH from AGENT_RULES)
- `pnpm vitest run --project unit services apps/server tools/verifier-cli packages/db`: all pass, except 7 load timeouts when run all together (db snapshot was real and is fixed; the rest pass when rerun alone: apps/server gate, evidence anchor/pq).
- New: `services/coordinator/test/ship.test.ts` (12), `tests/break-it/machine/ship.break.test.ts` (4: Bob-signed receipt, replay from another deal, damaged, missing; run from tests/break-it with `pnpm exec vitest run machine`), `tools/verifier-cli/test/gate.test.ts` (delivery fail rows, 17 codes), `tests/system/test/shipment.test.ts` (SYS-SR1..SR4: 4 pass, one file, containers legx-sys-*).
- Integration (ledger 6200, pg 5600): coordinator flow.int walks VERIFIED->SHIPPED->RECEIVED->release->FUNDED, passes. Three new demo-attacks scenes pass. The other scenes and model.int fail only when another job loads the shared ledger (tefMAX_LEDGER / tefPAST_SEQ / expired genesis payment); not rerun to green.
- tsc: coordinator, evidence, server, verifier-cli, firm-cosigner, recovery-agent clean (apart from existing vault DOM-type errors). tests/system and tests/break-it show errors that already existed (sys.test.ts:299, recovery.break).
- biome: my files clean; existing warnings and unrelated format errors in scripts/demo/product-e2e.ts remain.

## Known gaps
- SYS-SR1 cannot drive the whole deal through the UIs (no SYS flow does yet). It checks the state walk, the real gate (17 passing codes) and the offline verifier on a core gate world; SR2 to SR4 run on the live demo routes.
- `pnpm demo:dry-run`: the stack was not running here; the new offline steps pass (2 of 2), the server step needs the stack (6 of 16 steps pass without it).
- Walkthrough integration tests (`demo-walkthrough`, `demo-product`) fail at "Bob signs the shipment" (owner: walkthrough agent, `apps/server/src/demo-walkthrough/`, not touched).
- `tests/system` other files not rerun by me.

## Design questions / requests
- DQ-OD37-2 stands: a damaged receipt is not stored, so there is no event for the dispute path to hang on.
- Request (db owner): own the migration 0005.
