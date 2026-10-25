# Cleanup C2 (services: coordinator, recovery-agent, firm-cosigner; apps/server)

State: stopped at the deadline, no source change in my lane.

## Baseline (before; containers legx-c2-pg 5560, legx-c2-xrpld 6170, now removed)
- Unit (services, apps/server, mock-bar-registry): 51 files, 589 passed, 3 failed, 2 skipped, 1 todo.
  Failures (pre-existing): evidence events.test 4 KB rule, zk-verifier adapter CJS load, evidence pq/hybrid KMS half.
- Integration (same scope): 13 files passed, 1 skipped; 52 passed, 1 skipped.
- tests/system, one file at a time: catalogue 2 pass 1 fail (REGRESSION.md stale), console 2/2, sys 20 pass 12 expected-fail 12 todo, ui 2 pass 1 fail 3 expected-fail (dashboard waiting screen), wiring 83 pass 9 expected-fail.
- tests/break-it: counts not captured. Demo dry run: not run.
- After: not measured (no code change in my lane).
- Line counts (before = after): coordinator+recovery-agent+firm-cosigner+apps/server below.

## Changes
Only outside my new lane (hand to C2c): `scripts/dev.ts`, `scripts/demo/lib.ts`, `scripts/demo/check.ts` now read ports from `PORTS` and container names from `CONTAINERS` (`LEGX_DEV_PREFIX`, default `legx-3.7`), so a second stack can run (I-D-7 part). Defaults unchanged; untested.

## Not done
- I-3.7-e plan: evidence adopts `<pair>#ed25519` / `<pair>#ml-dsa-65` (services/evidence keys.ts, records.ts, its tests), apps/server drops `evidenceKeyIds` and builds `dealRegistry` from evidence `registryFromRows`. Touches C2b's evidence. Better home for the suffix helpers and `registryOf`: core (C1).
- I-W-13, I-W-14 (needs async ShareCipher from C1), I-S-A3, I-S-X1, I-3.7-f, I-12 (needs contracts change, C1), I-13, I-14, I-15, I-8, I-4, I-D-5, I-D-9: untouched, still open.
- knip, jscpd, dependency-cruiser never run (tools not ready); no dead-code or duplication pass.
- Regenerate tests/system/REGRESSION.md (catalogue test fails before any change).
services/coordinator 5547
services/recovery-agent 4978
services/firm-cosigner 1836
apps/server 4259
