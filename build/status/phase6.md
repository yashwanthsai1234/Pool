# Phase 6: system tests and wiring audit (status)

**State:** done (find-and-record wave; no other package edited).

## Tests (Node 24.22.1; containers `legx-sys-pg` 5520 and `legx-sys-xrpld` 6120, removed at the end)
| Run | Command | Result |
|---|---|---|
| unit | `pnpm vitest run --project unit` | 2837 passed, 7 failed, 2 skipped, 15 todo (143 files, 358 s) |
| integration | `pnpm vitest run --project integration` with `XRPLD_WS`, `LEGX_PG_URL`, `LEGX_32/37/39/310_*`, `LEGX_45_LEDGER_WS`, `LEGX_PG_CONTAINER` pointed at the sys containers | 224 passed, 1 failed, 4 skipped, 1 todo (45 files, 726 s) |
| browser | `LEGX_BROWSER=1 pnpm vitest run --project browser --project vault-browser --project core-browser --project vault-host-browser` | 728 passed, 1 failed, 8 skipped (67 files, 96 s) |
| system (new) | `pnpm vitest run --project system` | 71 passed, 42 expected-fail (`it.fails`, each with an issue ID), 12 todo (4 files, 4 files green) |

Failures (all recorded in `build/ISSUES.md`):
- unit: `services/renewal/test/noNoble.test.ts` x2 (I-W-14); `packages/signer/test/signers.test.ts` x3 (I-W-15); `packages/core/test/mutation-releaseGate.test.ts` IDS_DISTINCT 5 s timeout and `services/evidence/test/anchor.test.ts` P3.4-07b (both load flakes, I-W-17).
- integration: `services/coordinator/test-int/flow.int.test.ts` `stale_ledger_index`, deterministic, also on a fresh ledger (I-W-16).
- browser: `apps/web/test/frost/dkg.browser.test.tsx` P4.7-02 on WebKit, 40 s timeout under load; 14/14 alone (I-W-17).

`tsc -p tests/system` and `biome check tests/system` are clean.

## What was built
- `tests/system` (`@legx/system-tests`): `support/stack.ts` (the real `apps/server/src/main.ts` process, demo profile, fresh database, signed-request client, live-feed client, key pinning, restart/kill), `support/deal.ts`, `support/probes.ts` (prerequisite probes), `support/web.ts` (Vite dev server), `support/regression.ts` (catalogue generator).
- `test/wiring.test.ts` (72): every contract route, signature purpose, outbox topic, event kind and port.
- `test/sys.test.ts` (44): SYS-01 to 12 as prerequisite pins, SYS-A1 to A6, A9 to A11 and SYS-13 through the nine demo attack scenes on a real ledger, SYS-A8, SYS-R1, R2, R4, SYS-I1, I2, I3. SYS-14 to 17, A7, A12 to A16, R3 are `it.todo` with their package-level tests named in REGRESSION.md.
- `test/ui.test.ts` (6): Playwright Chromium against the Vite dev server and the live server.
- `test/catalogue.test.ts` (3): REGRESSION.md complete and current; named I-W IDs exist.
- Root edits (needed to host the package): `pnpm-workspace.yaml` (`tests/*`), `vitest.config.ts` (project `system`).
- `tests/system/REGRESSION.md`: every ID of `build/ISSUES.md` mapped to its system or package test, plus "Pin needed".

## Wiring audit: broken links (IDs in build/ISSUES.md)
- Routes: `keys.register` 501 and no caller of `pinEnrollmentKey`, so no party key can ever authenticate (I-W-1); `bar.manualEvidence`, `bar.dealLink`, `zk.verify` 501 (I-3.7-d); `records.bundle` 501, bundle deps never composed (I-W-8); no operator key (I-W-9); purposes `ticket_create`, `signer_list_update`, `seal_update`, `escrow_finish` 501 (I-14).
- Topics: `deal.state`, `signature.request` have no producer (I-W-5); `ledger.validated` is pushed but not in the contract (I-3.7-b); no `pg_notify` from outbox writers, the 1 s poll carries the feed (I-3.7-a).
- Event kinds with no producer: `attorney.credential.issued`, `checkpoint.anchored` (I-W-6), `bar.deal_linked` (I-3.7-d).
- Ports: release gate is a stub (I-3.7-g); watcher `deals: () => []`, evidence sink no-op (I-W-4); no TSA port (I-W-7); checkpoint job never registered, `pgBossJobs` unused (I-W-6); demo keys regenerated at each start and the log is in memory (I-W-12); agents are stubs (I-W-13); `createZkAdapter` result discarded.
- Web: dev proxy has the wrong port (8787 vs 8710) and keeps the `/api` prefix (I-W-2); `PartyProvider` (I-31), `ConsoleProvider` (I-W-10) and the observer key (I-W-11) are never provided outside tests; the server serves no static files.
- Unused exports (heuristic, `build/tmp/sys/unused.mjs`): 65 exported values used by nothing, 172 used only by tests. Left for Phase 7 knip. Examples: `FrostScreensProvider`, `xrplPublicLedger`, `pgBossJobs`, `SUPPORTED_PURPOSES`, `SLOT_OF_ROLE`.

## Verified working end to end
Signed requests and single-use nonces; a key of another deal is refused (SYS-A8); deal events and `ledger.validated` reach a signed socket; kill -9 and restart lose, double or gap no event (SYS-R1); a 10 s ledger stall recovers (SYS-R2, `docker pause`); all nine attack scenes are defeated on the real ledger; evidence and outbox sequences are gap-free (SYS-I1); no secret key, MRZ or salt in Postgres, the data folder or the log (SYS-I2).

## Notes and known gaps
- SYS-01 to 12 are prerequisite pins, not flows: they flip when the blockers are fixed and must then be strengthened to drive the whole flow.
- SYS-R2 pauses the container instead of dropping the WebSocket for 60 s (a restart would reset the standalone ledger).
- The system tests take the ports 8787 (the port the web proxy expects), 7080 and 5199. They need `legx-sys-pg` and `legx-sys-xrpld`.
- `ci.yml` does not yet run the system project and misses several integration env vars (I-W-18).
