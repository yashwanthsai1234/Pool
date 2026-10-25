# final-libs

State: done (integration result below).

Closed: I-7, I-18, I-19 (verified), I-S-A3, I-S-X1 (verified) in build/ISSUES.md.
Cleanup items: FROST helper dedupe in xrpl/test-int (refreshSlot/repairShare now re-exported from core/test/helpers/frost.ts); I-6 stays wontfix (tile tree); I-D-6 already closed.
knip "unused deps" @legx/fixtures and @legx/zk-verifier in xrpl: wontfix, evidence: both are imported by test-int/zk/*.ts and test-int/roles.ts, which knip does not scan.
jscpd: 75 clones remain in test-int attacks/zk (not touched, test scaffolding).

Contract change (I-18): `LedgerSnapshot.missing?`, `LedgerPort.snapshot(..., options?)`. Request to 3.12/compose: pass `cosign` to `tesseraLog` in production.
Config: `assertNotSepoliaChain` wired in apps/server/src/main.ts (one call).
Not mine: compose.ts has unused imports (other agent mid-edit).
