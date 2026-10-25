# final-services
State: partial. Fixed: I-2, I-3.7-e, I-3.7-f. Partial: I-14, I-15. Open: I-12, I-13 (see build/ISSUES.md).

## Changes
- I-2: mock registry uses `XA-DM`; path pattern equals contract `Jurisdiction` (test `I-2 jurisdiction code`; failed before, 25/25 after).
- I-3.7-e: evidence uses the coordinator's `<pair>#ed25519` / `<pair>#ml-dsa-65`, imported from `@legx/coordinator/keys` (new workspace dep). Service keys keep plain ids. `authenticate` also accepts the legacy bridged ids until apps/server drops `evidenceKeyIds`. `apps/server/test/wiring.test.ts` 85/85.
- I-3.7-f: recovery-agent authenticates before parsing the body; deal comes from the recovery (no dealId query/body needed). Test `an unsigned request is 401 ...`.
- I-14: nightly T-P-06 runs 200 (verified); escrow_finish wontfix (DESIGN D23); other three purposes need contract inputs.
- I-15: nightly LEGX_LIVE_SEPOLIA=1 verified; P3.11-19..25 open.

## Gates
- tsc clean for the 5 packages; biome: no errors (warnings only).
- Unit (evidence, coordinator, zk-verifier, recovery-agent, mock registry): all pass; evidence pq/anchor tests time out at 5 s when run in parallel under load, pass alone.
- Integration (XRPLD_WS 6200, PG 5600): 6 passed; rotation.int hit a genesis-account race (tefPAST_SEQ) when files ran in parallel, 7/7 when alone.

## Requests
- apps/server: `demo.ts:116` drop the `XA-DEMO` mapping; `routes.ts` `evidenceKeyIds` becomes identity; `dealRegistry` can use `registryFromRows`.
- contracts: `PqBinding` attachment (I-12); signer-list and seal inputs for `signatures.create` (I-14).
