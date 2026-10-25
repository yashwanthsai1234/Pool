# fix-F5 (ledger)

State: done, with open rows that need other lanes (below).

## Fixed (marked `fixed (F5)`)
- I-2.5-a: `extract-harness.ts` writes only `harness.ts` (test `test/extractHarness.test.ts`).
- I-2.5-b: `build5dUnauthorize`, `build5Domain`, and `signers` on `build5d` (fee base x (1 + signers)); tests in `test/builders/builders.test.ts`; `deal.ts` `swapLawyer` uses them.
- I-2.5-d: `slotSign` default pick rotates through the six holder pairs (no `Math.random`).
- I-2.6-b / I-2.9-b: `attacks/chain.ts` and `zk/zkChain.ts` are merged into `openChain` in `roles.ts` (`attempt`, `attemptMulti`, `pause`, `resume`, `idle`, `accept`, `lcl`, `rawSubmit`, `placed`, `advance`); `attacks/deal.ts` moved to `test-int/deal.ts`; `full-flow.int.test.ts` now runs on `Deal` (the 460-line `runFlow` copy is gone). The P6/P7 snapshot writer went with it; the recorded fixtures stay and P2.5-01 still reads them.
- I-2.6-d: `ci/xrpld.cfg` `online_delete` and `ledger_history` = 20000. Test `I-2.6-d` in `ledger.int.test.ts` (failed with `ledgerNotFound` before, 600 closes later passes). Source: https://xrpl.org/docs/infrastructure/configuration/data-retention/configure-online-deletion
- I-2.6-e: documented on `submitReliable`.
- I-2.9-a: `ci/nightly-zk.yml` (copy to `.github/workflows/` to enable).
- I-27: T-N-01 in `network.int.test.ts` (runs only with `LEGX_TESTNET=1`; `openChain(env)` works on Testnet via the faucet and `advance`). NOT run live (20+ minutes, public faucet).

## Also changed because core moved under us
- Key rows in `roles.ts` carry `pair` (I-S-P1) and onboarding records carry `distinct_tag` (OD-29), in `roles.ts` and `zk/zkFlow.ts` (zk flow not re-run: needs network).
- P2.5-04 now expects `PASSPORT_B_OK`, `ONBOARDING_OK`, `SLOT_SETUP_OK` (records signed by lawyer B's holders rest on its DKG record, OD-21).

## Requests to other lanes
- F2 (core): export `refreshSlot` and `repairShare` from `packages/core/test/helpers/frost.ts` (I-2.8-d); the copies in `test-int/frost/support.ts` stay until then. Export `makeSlot` from `core/test/helpers/gate.ts` (I-2.5-c). Give `NONCE_USED` the message "signing nonces already used" (I-2.8-b). Pick `ZK_RESULT_MISSING` or `NO_RECORDED_RESULT` (I-2.9-c). Add kind/event `release-code-handover` (I-2.6-a, with F1 for contracts).
- Orchestrator (DESIGN/IMPLEMENTATION text, not my folders): I-2.5-e, I-2.5-f, I-2.6-c, I-2.8-a, I-2.8-c, I-2.9-d, I-2.9-e, I-2.9-f.
- tsc: `packages/core/src/releaseGate.ts(448)` has a type error (holders lack `holder`, `role`, `deviceId`); F2's file; xrpl itself has no errors.

## Tests
- `pnpm vitest run --project unit packages/xrpl`: 181 passed.
- Integration on port 6140 (container `legx-f5-xrpld`, now removed): full-flow 3/3; frost, ledger, read, submit, multisig, watcher 54 passed, 1 skipped; unhappy + attacks all passed (17 files). zk and the Testnet flow not run (network).
- biome: no errors, 20 warnings (non-null assertions already present). tsc: only the core error above.
