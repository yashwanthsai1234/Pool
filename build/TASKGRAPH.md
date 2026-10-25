# Task graph and dependency graph (the build schedule)

Read `build/AGENT_RULES.md` first. Task numbers match IMPLEMENTATION.md. A wave starts only when every dependency of its tasks is `done` in `build/status/<task>.md`. The orchestrator (not the agents) starts each wave.

## Dependency graph (by waves)

```
WAVE A  (scaffold 1.1 is done)
  1.2 contracts ─┬─────────────────────────────────────────────┐
  1.3 starting code + vectors ──┐                              │
  1.8 test PKI + fixture passports ─────┐                      │
  2.1 ledger environments + harness ──┐ │                      │
  4.1 web foundation (scaffold part)  │ │                      │
  3.3a mock bar registry              │ │                      │
  5.1 Quint model                     │ │                      │
  5.3a Python reference (from DESIGN) │ │                      │
                                      ▼ ▼                      ▼
WAVE B  (needs 1.2 and 1.3)
  1.4 → 1.5 → 1.6 → 1.7        (one agent, in order)
  1.9  passport attestation        (needs 1.8)
  1.10 bar records
  1.13 evidence primitives + 1.14 state machine
  1.15 FROST (core)
  1.16 post-quantum (core)
  1.17 zero-knowledge identity (core)
  2.2  reliable submit + one-ledger reads   (needs 2.1)
  3.1  database
  3.6  signer, storage, observability
                                      │
WAVE C  (needs wave B)
  1.11 lock checker → 1.12 release gate   (1.12 needs 1.5, 1.7, 1.9, 1.10, 1.11, 1.15 to 1.17)
  2.3  transaction builders (needs 1.5, 1.6)
  2.4  multisig + slot S (needs 2.2, 1.4)
  2.7  watcher client (needs 2.2)
  3.2  coordinator (needs 3.1, 1.14)
  3.3  verifier service (needs 3.1, 1.10, 3.6, 2.3)
  3.4  evidence service (needs 3.1, 1.13, 3.6)
  3.11 ZK verifier adapter (needs 1.17)
  3.12 post-quantum in services (needs 1.16, 3.6)
  4.2  key vault (needs 4.1, 1.15)
  5.2  fuzzing (needs wave B core)
                                      │
WAVE D  (needs wave C)
  2.5  full flows T-I-01 / T-I-10 → 2.6 unhappy paths + attacks
  2.8  FROST on the ledger (needs 2.5)   2.9 ZK flow on the ledger (needs 2.5)
  3.5  watcher service (needs 2.7, 3.1)
  3.9  FROST relay + recovery agent (needs 3.2, 1.15, 1.16)
  3.10 firm HSM co-signer (needs 3.6, 3.9)
  3.7  server composition (needs 3.2 to 3.6, 3.9 to 3.12)
  3.8  offline verifier CLI (needs 3.4, 1.12, 3.11, 3.12)
  4.7  FROST in the browser (needs 4.2, 3.9)
  4.9  post-quantum keys in the browser (needs 4.7)
  4.10 signing-code integrity (needs 4.2)
                                      │
WAVE E  (needs wave D)
  4.3 party app, 4.4 lawyer console, 4.5 dashboard + attack mode, 4.8 ZKPassport flow, 4.6 chip reader (protocol side)
  5.3b differential vs xrpl-py, 5.4 mutation testing, 5.5 Testnet nightly
                                      │
WAVE F  : 5.6 demo profile and runbook, 5.7 security review
WAVE G  : Phase 6 system tests and regression catalogue (SYS-*)
WAVE H  : 3 to 4 "wiring and break-it" agents  ->  issue list  ->  fix fleet  ->  re-run
WAVE I  : Phase 7 cleanup (dead code, duplication, simplification, architecture rules)
WAVE J  : A/B tests (implementation A vs B, before vs after cleanup) and the full regression run
```

## Task table

| Task | Title (IMPLEMENTATION section) | Wave | Model | Owns | Ports (ledger WS / Postgres) |
|---|---|---|---|---|---|
| 1.1 | Repo scaffold | done | orchestrator | root config | none |
| 1.2 | Shared contracts freeze | A | Opus | `packages/contracts/` | none |
| 1.3 | Starting code (DESIGN Appendix A) + vectors | A | Sonnet | `packages/core/` (initial), `packages/core/vectors/` | none |
| 1.8 | Test PKI and fixture passports | A | Opus | `packages/fixtures/` | none |
| 2.1 | Ledger environments and harness | A | Sonnet | `packages/xrpl/` (harness, env) | 6101 |
| 4.1 | Web foundation | A, finished in C | Sonnet | `apps/web/`, `packages/ui/` | none |
| 3.3a | Mock bar registry | A | Haiku | `apps/mock-bar-registry/` | none |
| 5.1 | Quint model | A | Opus | `spec/` | none |
| 5.3a | Python reference from DESIGN | A | Sonnet | `tools/py-ref/` | none |
| 1.4 to 1.7 | Strict verify, signed-contract seal, deal seal, ops binding | B | Opus | `packages/core/src/{verify,signedContract,dealcore,opsBinding}.ts` | none |
| 1.9 | Passport attestation | B | Opus | `packages/core/src/{attest.ts,passport/}` | none |
| 1.10 | Bar records | B | Sonnet | `packages/core/src/bar.ts` | none |
| 1.13 + 1.14 | Evidence primitives, state machine | B | Sonnet | `packages/core/src/{evidence,checkpoint,machine}.ts` | none |
| 1.15 | FROST core | B | Opus | `packages/core/src/frost.ts` | none |
| 1.16 | Post-quantum core | B | Opus | `packages/core/src/pq.ts` | none |
| 1.17 | Zero-knowledge identity core | B | Opus | `packages/core/src/zkIdentity.ts`, `packages/zk/` (ports) | none |
| 2.2 | Reliable submit and reads | B | Opus | `packages/xrpl/src/{submit,read}.ts` | 6102 |
| 3.1 | Database | B | Sonnet | `packages/db/` | 5501 |
| 3.6 | Signer, storage, observability | B | Sonnet | `packages/{signer,storage,observability}/` | none (MinIO 9101) |
| later waves | see IMPLEMENTATION.md | C to J | per IMPLEMENTATION | per IMPLEMENTATION section 2.3 | assigned at launch |

## Shared conventions decided by the orchestrator
- Workspace package names: `@legx/contracts`, `@legx/core`, `@legx/fixtures`, `@legx/xrpl`, `@legx/db`, `@legx/signer`, `@legx/storage`, `@legx/observability`, `@legx/zk`, `@legx/vault`, `@legx/ui`. Services: `@legx/coordinator`, `@legx/verifier`, `@legx/evidence`, `@legx/watcher`, `@legx/recovery-agent`, `@legx/firm-cosigner`. Apps: `@legx/server`, `@legx/web`, `@legx/mock-bar-registry`. Tools: `@legx/verifier-cli`, `@legx/fuzz`.
- No shared index files. Every package uses subpath exports: `"exports": { ".": "./src/index.ts", "./*": "./src/*.ts" }`. Import modules as `@legx/core/frost`, `@legx/core/dealcore`, and so on. A package's `index.ts` is written only by that package's first owner (task 1.3 for `@legx/core`) and may stay small.
- Hex strings are uppercase in ledger-facing values, and lowercase in internal hashes unless the spec says otherwise. Follow DESIGN.
