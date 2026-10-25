# Cleanup C1 (core, contracts, chip-link, zk, root config)

State: partial (deadline).

## Done
- Installed at root (exact): knip 6.42.1, jscpd 5.4.2, dependency-cruiser 18.7.0, @swc/core 1.16.18 (dep-cruiser has no TypeScript 7 support, so `parser: 'swc'`). Config: `knip.json`, `.jscpd.json` (minTokens 30), `.dependency-cruiser.cjs` (no-circular, OD-27 core rules, OD-24, apps vs service internals). `build/tmp/cleanup-tools-ready` touched.
- Research: https://knip.dev/features/monorepos-and-workspaces , https://knip.dev/reference/configuration , dependency-cruiser rules https://github.com/sverweij/dependency-cruiser/blob/main/doc/rules-reference.md , v16 release https://github.com/sverweij/dependency-cruiser/releases/tag/v16.0.0 (no jscpd page found by search; config follows its README).
- I-9 (core, zk): explicit 60 s budgets on mutation-releaseGate IDS_DISTINCT block, P1.15-22, zk offline P1.17-18. Those load-timeouts now pass.
- Biome: 0 errors in my packages (the 2 mutation-frost errors were already gone); tsc core clean. Dependency-cruiser: no violations in packages/*.

## Tests (before to after)
- Before, one run of unit over core, contracts, chip-link, zk, xrpl, fixtures, db, signer, storage, observability, tools, spec: 2471 pass, 9 fail (load timeouts: 4 core, 1 zk, 4 fixtures), 12 todo.
- After, core, contracts, chip-link, zk only: 49 files, 1819 pass, 0 fail, 11 todo.
- xrpl integration (port 6160, XRPLD_WS=ws://127.0.0.1:6160): baseline run did not finish within my budget, no after run (code untouched). py-ref: 22 pass. core-browser baseline: 7 pass.
- Lines in lane after: 27164 (no source lines removed; no before count for the 4 packages alone).

## Not done
- knip: unused exports in core test helpers (e2e/slots.ts, e2e/world.ts, helpers/gate.ts), unused deps (@opentelemetry/resources, @zkpassport/registry, @zkpassport/utils, @vitest/coverage-v8, @aztec/bb.js, @noir-lang/noir_js, @legx/fixtures and zk-verifier in xrpl).
- Duplication: `core/test/e2e/world.ts` vs `helpers/gate.ts` (hundreds of lines), attest/dealseal/lockcheck test setups, mutation-lockcheck vs lockcheck.
- I-W-14 async ShareCipher in core, I-1 (CredentialDelete to @legx/xrpl, then C2b removes verifier copy), I-6, I-7, I-16, I-18, I-19, I-2.5-c, I-E3, I-E5, I-17 (already done): not touched.
- FROST duplicated helper merge: not touched.

## Findings for others
- C3: `apps/web/src/routes/lawyers/-console/ports.ts:20` has `type { ... };` (invalid TS; swc rejects it).
- C2: dependency cycles: recovery-agent holder.ts <-> policy.ts; apps/server compose.ts <-> routes.ts.

## Handover (C1b)
- xrpl, fixtures, db, signer, storage, observability, fuzz, tools, spec, .github: not touched by me. Open: I-1, I-6 (storage/merkle.ts vs core), I-7, I-18 (contracts), I-19 (xrpl), jscpd clones in xrpl test-int attacks and db suite, knip unused deps listed above. Run xrpl int with `XRPLD_WS=ws://127.0.0.1:<port>` (default 6101).
