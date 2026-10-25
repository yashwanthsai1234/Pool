# Two-Key Deal Wallet: Implementation Plan

Version: 1.0
Date: 24 Oct 2026
Owner: Yash
Builds: `DESIGN.md` version 1.0 (in this repo). Version 1.0 is the only version. Every tag is `/v1` and means the latest recipe.

This document says **how** to build the system in `DESIGN.md`, in what order, with which tools, and how to prove each part works. `DESIGN.md` says **what** the system does and why. If the two disagree about behavior, `DESIGN.md` wins: stop and raise a design question (IMPLEMENTATION Appendix B). If they disagree about tools or order, this document wins.

Everything in the design is built. The demo uses a few local stand-ins for outside services. Section 3 lists each one, and every stand-in sits behind the same interface as the real service.

---

## 1. How to use this document

### 1.1 The work loop for every task

Every task in Phases 1 to 5 follows the same six steps, in this order. A pull request that skips a step is not done.

| Step | What you do | What you leave behind |
|---|---|---|
| **1. Research** | Answer the task's research questions from primary sources: specs, RFCs, rippled source, official docs, changelogs. Check the current version of every library you touch. Look for a simpler or more robust way than the one written here. | A short "Research notes" block in the pull request, with links. If a fact changes the design, raise a DQ (IMPLEMENTATION Appendix B) before you write code. |
| **2. Test** | Write the task's listed tests first. Run them and watch each one fail for the right reason. | Failing tests, committed. |
| **3. Think** | Decide the smallest API and data shape that makes the tests pass. Write it as types first. | Types and function signatures, no bodies. |
| **4. Test in all directions** | Add the tests the list did not name: property tests (fast-check), boundaries (0, 1, max, max + 1, exactly at a deadline), negative and hostile input, concurrency and ordering, a second implementation (differential), and one end-to-end test through the real neighbor component where one exists. | More failing tests. |
| **5. Think hard** | Before you write the body: how could this fail in production? How could an attacker use it? Does it break a hard rule (section 1.3)? Does it read the clock or the network when it should not? Would an arbitrator get the same answer from the evidence alone? | A "Risks" block in the pull request. New tests for each risk you find. |
| **6. Implement** | Write the smallest code that turns every test green. Then refactor with the tests green. Run coverage and the mutation check for the files you changed. | Green tests, coverage and mutation numbers in the pull request. |

### 1.2 Definition of done for every task

1. All listed tests, and the tests you added in step 4, pass.
2. `pnpm lint`, `pnpm typecheck` and the task's test project pass in CI.
3. Branch coverage is at least 90% on the files you changed (95% on `packages/core`).
4. No **[CHECK]** is left without a test that pins it.
5. The pull request has the Research notes and the Risks blocks.
6. No file outside the task's "Owns" list changed, except through an approved contracts change (section 2.4).

### 1.3 Hard rules (from DESIGN section 0, enforced in code)

1. Never touch Mainnet. The ledger package refuses Mainnet hosts and Mainnet network IDs (task 2.1).
2. No service holds a whole slot key, a party or lawyer key, the release code or a raw passport. A service may hold one FROST share only when DESIGN 6.4 names it (the recovery agent and the firm co-signer). The verifier attestation key, the verifier issuer account key and the evidence log key live behind `SignerPort`, which returns an Ed25519 and an ML-DSA-65 signature (KMS in production, a local demo key file in the demo profile).
3. Every hash and signed message uses a versioned tag and `tupleHash`. DSSE envelopes sign their PAE and carry two signatures, Ed25519 and ML-DSA-65 (DESIGN 6.13).
4. Strict Ed25519 everywhere (`zip215: false`), through one function: `verifyXrplKeySig`.
5. Trust only validated ledgers. All reads for one decision come from one validated ledger. Time comes from ledger `close_time` through `ClockPort`, never from `Date.now()` in decision code.
6. Read amounts from `meta.delivered_amount`.
7. Never delete a test. Change it only when the design changes, and say why in the commit.
8. Plain words, short sentences and no em or en dashes in both documents.

---

## 2. Phases, lanes and parallel work

### 2.1 The seven phases

| Phase | Name | What it delivers | Exit gate |
|---|---|---|---|
| 1 | Foundation and core library | Repo, toolchain, shared contracts, all of `@legx/core` (including FROST slot keys, zero-knowledge identity checks and post-quantum hybrid signatures), test PKI, fixture passports and ZKPassport mock-passport fixtures | G0 (after 1.1 and 1.2), then G1 |
| 2 | Ledger layer | `@legx/xrpl`: builders, reliable submit, one-ledger reads, multisig, watcher client, all real-ledger tests, including FROST-signed multisig (T-I-11) and the ZKPassport mock flow (T-I-12) | G2 |
| 3 | Platform services | Database, coordinator with FROST relay, verifier service with the ZK verifier adapter, evidence service, watcher service, recovery agent and firm co-signer, post-quantum signing (KMS ML-DSA-65), mock bar registry, observability, offline verifier CLI, one server for the demo | G3 |
| 4 | Web clients | Party app (phones), lawyer console (laptop), dashboard and attack mode (projector), key vault with FROST shares, recovery and signing-code integrity, ZKPassport request flow and zero-knowledge proofs, post-quantum keys in the browser, native chip reader helper | G4 |
| 5 | Hardening and demo readiness | Quint model, fuzzing, Python reference, mutation testing, Testnet nightly, FROST, ZK and post-quantum vector and fuzz checks, demo seeding and runbook, security review | G5 |
| 6 | System test and regression | Whole-system tests through the UI, attack scenes, resilience, invariant monitor, privacy scan, the frozen regression suite | G6 |
| 7 | Cleanup | Dead code, duplication, architecture rules, simplification, documents in sync | G7 |

### 2.2 Dependency graph

```
                    ┌──────────────────────────────┐
                    │ G0: 1.1 scaffold + 1.2       │
                    │     contracts freeze         │
                    └──────────────┬───────────────┘
        ┌──────────────┬───────────┼─────────────┬──────────────┐
        ▼              ▼           ▼             ▼              ▼
 ┌────────────┐ ┌────────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐
 │ PHASE 1    │ │ PHASE 2    │ │ PHASE 3  │ │ PHASE 4  │ │ PHASE 5    │
 │ core       │ │ ledger     │ │ services │ │ web      │ │ 5.1, 5.3   │
 │ (rest)     │ │ (starting  │ │ (stub    │ │ (MSW     │ │ (model,    │
 │            │ │  code      │ │  ledger) │ │  mocks)  │ │  py-ref)   │
 └─────┬──────┘ └─────┬──────┘ └────┬─────┘ └────┬─────┘ └─────┬──────┘
       ▼              ▼             │            │             │
      G1 ─────────▶  G2 ───────────▶│            │             │
                                    ▼            │             │
                                   G3 ──────────▶│             │
                                                 ▼             │
                                                G4             │
                                                 └──────┬──────┘
                                                        ▼
                                                 G5: rest of Phase 5
                                                        ▼
                                                 G6: Phase 6
                                                        ▼
                                                 G7: Phase 7
```

What each gate needs from the others:
- **G1** (core done) needs only Phase 1.
- **G2** (ledger done) needs G1, because T-I-01 is the full flow and uses the whole core: FROST (1.15, no stubs), the post-quantum bindings and hybrid envelopes (1.16) and the release gate (1.12). T-I-01 uses chip fixtures, so it does not need the ZK checks (1.17). The ZK path is task 2.9 (T-I-12), which needs 1.17. Everything else in Phase 2 starts with the starting code from DESIGN Appendix A, changed to match DESIGN 6.
- **G3** (services done) needs G2, for its end-to-end suite on a real ledger. Its unit and API tests run earlier against a stub `LedgerPort`.
- **G4** (web done) needs G3, for its end-to-end suite. Its component and flow tests run earlier against MSW mocks built from the frozen contracts.
- **G5, G6 and G7** run in order at the end.

### 2.3 Lanes for parallel agents

A lane is one agent's stream of work. Lanes in the same column can run at the same time. Each lane owns a set of folders and touches nothing else.

| Lane | Tasks | Owns | Starts after |
|---|---|---|---|
| L0 | 1.1, 1.2 | root config, `packages/contracts/` | now (1.2 after 1.1) |
| L1 | 1.3, 1.4, 1.5, 1.6, 1.7, 1.11, 1.12 | `packages/core/src/` except `attest.ts`, `bar.ts`, `evidence.ts`, `machine.ts`, `frost.ts`, `pq.ts`, `zkIdentity.ts` | 1.3 after 1.1; the rest after G0 and in order; 1.11 after 1.6; 1.12 after 1.9 and 1.10 (from L2) and 1.15, 1.16, 1.17 (from L13 to L15) |
| L2 | 1.8, 1.9, 1.10 | `packages/fixtures/`, `packages/core/src/attest.ts`, `bar.ts` | G0; 1.9 after 1.4 and 1.6 (from L1) and 1.8; 1.10 after 1.6 |
| L3 | 1.13, 1.14 | `packages/core/src/evidence.ts`, `machine.ts` | G0; 1.13 after 1.3 (from L1) |
| L4 | 2.1 to 2.5 | `packages/xrpl/` except `watcher/` and `test-int/frost/` | 2.1 after 1.1; 2.3 after 1.5 and 1.6 (from L1); 2.4 after 2.2 and 1.4; 2.5 after 2.2 to 2.4 and 1.5 to 1.12, 1.15, 1.16 |
| L5 | 2.6, 2.7 | `packages/xrpl/test-int/attacks/`, `packages/xrpl/src/watcher/` | 2.7 after 2.2; 2.6 after 2.5 |
| L6 | 3.1, 3.2, 3.7 | `packages/db/`, `services/coordinator/`, `apps/server/` | 3.1 after G0; 3.2 after 3.1, 1.14 and 2.2 to 2.4; 3.7 after 3.2 to 3.6 and 3.9 to 3.12 |
| L7 | 3.3, 3.4, 3.8 | `services/verifier/`, `services/evidence/`, `apps/mock-bar-registry/`, `tools/verifier-cli/` | 3.3 after 3.1, 1.10, 2.3 and 3.6; 3.4 after 3.1, 1.13 and 3.6; 3.8 after 3.4, 1.12, 3.11 and 3.12 |
| L8 | 3.5, 3.6 | `services/watcher/`, `packages/observability/`, `packages/signer/` (classical parts), `packages/storage/` | 3.6 after G0; 3.5 after 3.1 and 2.7 |
| L9 | 5.1 to 5.5 | `spec/`, `tools/fuzz/`, `tools/py-ref/`, mutation and nightly config | 5.1 after G0; 5.2 and 5.4 after G1; 5.3 after G0, 1.15 and 1.16; 5.5 after G2, G3, 2.8 and 2.9 |
| LW1 | 4.1, 4.2, 4.7, 4.9, 4.10 | `apps/web/src/lib/`, `packages/ui/`, `packages/vault/` | 4.1 after G0; 4.2 after 1.3, 1.15 and 4.1; 4.7 after 1.15, 3.9, 3.10 and 4.2; 4.9 after 1.16 and 4.7; 4.10 after 4.1 and 4.2 |
| LW2 | 4.3, 4.8 | `apps/web/src/routes/party/` | 4.3 after 4.1, 4.2 and 4.7; 4.8 after 1.17, 3.11 and 4.3 |
| LW3 | 4.4, 4.5 | `apps/web/src/routes/lawyers/`, `routes/dashboard/` | 4.5 after 4.1; 4.4 after 4.1, 4.2, 4.7 and 4.8 |
| LW4 | 4.6 | `apps/chip-reader-android/` | 1.9 |
| L10 | 5.6, 5.7 | `demo/`, `docs/RUNBOOK.md` | G3, G4 |
| L11 | Phase 6 | `e2e/` | G4 |
| L12 | Phase 7 | any, through review | G6 |
| L13 | 1.15, 2.8 | `packages/core/src/frost.ts`, `packages/xrpl/test-int/frost/` | 1.15 after 1.2, 1.4 and 1.6 (from L0 and L1); 2.8 after 1.15, 2.4 and 2.5 |
| L14 | 1.16, 3.12 | `packages/core/src/pq.ts`, `packages/signer/` post-quantum parts (`KmsMlDsaSigner`, Node ML-DSA file signer) | 1.16 after 1.2, 1.3 and 1.13; 3.12 after 1.16, 3.4 and 3.6 |
| L15 | 1.17, 2.9, 3.11 | `packages/core/src/zkIdentity.ts`, `packages/zk/`, `tools/zk-prove/`, `tools/record-zk/` | 1.17 after 1.2, 1.6 and 1.9 (from L2); 2.9 after 2.5 and 1.17; 3.11 after 1.17, 3.1 and 3.6 |
| L16 | 3.9, 3.10 | `services/recovery-agent/`, `services/firm-cosigner/` | 3.9 after 3.2, 1.15 and 1.16; 3.10 after 3.6, 3.9 and 1.15 |

The "Starts after" column is generated from each task's Depends column. When a Depends column changes, regenerate this table.

At the widest point (after G0), up to 16 lanes run at once: L1 to L9, L13 to L15 and LW1 (4.1). L16, LW2 and LW3 wait on Phase 3 services and on 4.7. The new lanes own separate files, so they do not collide with L1.

### 2.4 Rules that keep parallel work safe

1. **One git worktree per lane.** Branch name `lane/<id>/<task>`. Rebase on `main` daily.
2. **Contracts are frozen at G0.** A change to `packages/contracts` is its own pull request. Every lane owner who imports the changed file must approve it. The change log goes in `packages/contracts/CHANGELOG.md`.
3. **Merge order** follows the dependency graph. A lane never merges code that another lane owns.
4. **Shared fixtures are read-only.** Golden vectors and fixture passports live in `packages/fixtures` (L2). Other lanes import them and never copy them.
5. **Stubs, not waiting.** If you need a component that is not built yet, code against its port from `packages/contracts` with a stub. Mark the test `stubbed:<port>`. Gate G3 or G4 removes the last stubs. One exception: task 2.5 uses no FROST stub; it waits for 1.15.
6. **One integration owner per gate.** The gate's owner (L1 for G1, L4 for G2, L6 for G3, LW1 for G4) runs the phase's end-to-end suite and merges.

### 2.5 Model and effort guide

Use the cheapest agent that can do the task well. The tables in each task give the pick. This is the general rule:

| Kind of work | Model | Effort | Examples |
|---|---|---|---|
| Mechanical: copy, extract, configure, rename, scan | Haiku | low | 1.1, 1.3, 3.7, 7.1 to 7.3 |
| Standard build against a clear spec | Sonnet | medium | 1.6, 1.7, 1.10, 2.3, 4.3 to 4.5, 5.4 (killing mutants means writing tests) |
| Integration, concurrency, real-ledger tests | Sonnet | high | 2.4 to 2.7, 3.2, 3.4, 3.5, Phase 6 |
| Security-critical logic, cryptography, PKI, formal model | Opus | high or xhigh | 1.2, 1.4, 1.5, 1.8, 1.9, 1.11, 1.12, 1.15 (xhigh), 1.16, 1.17, 2.2, 4.2, 4.7 (xhigh), 5.1 |
| Final security review | Opus | max | 5.7 |

Sizes are estimates for one agent with a human reviewer: **S** is up to 3 hours, **M** is 4 to 6 hours, **L** is 8 hours or more.

**Critical path.** It is recomputed from the Depends columns of every task (2 days counts as 16 hours, and the Phase 4 end-to-end suite as 6 hours). The longest chain is 1.1 (2 h), 2.1 (4 h), 2.2 (6 h), 2.4 (4 h), 3.2 (16 h), 3.9 (16 h), 3.10 (6 h), 4.7 (16 h), 4.3 (8 h), 4.8 (8 h), 4.4 (8 h), then E2E-P4 (6 h). That adds up to 100 agent hours, which is 12.5 days at 8 hours per day. The chain runs through the services, not through the core: 3.9 and 3.10 (the FROST relay and the firm co-signer) must finish before 4.7 (FROST in the browser), and 4.3, 4.8 and 4.4 follow one after the other. The other long chains are shorter: through the release gate it is 1.8, 1.9, 1.17, 1.12 and 2.5 (about 60 hours after G0 starts) and the Phase 3 evidence chain is under 50. With all lanes busy and one reviewer, Phases 1 to 4 take about 13 working days, and 15 to 16 once review waits are counted. Phases 5 to 7 take about 6 more. Review time, not agent time, is usually the limit: plan one human review slot per lane per day.

Spend tokens where mistakes are expensive. A Haiku agent that copies DESIGN Appendix A wrongly is caught by test P1.3-01 in seconds. An error in the release gate can move money. That is why the gate gets Opus with xhigh effort, and the copy job gets Haiku with low effort.

### 2.6 If the demo comes before the full build

Everything in this plan is built. If the demo date comes first, build this subset first, in this order, and finish the rest after the demo:

| Order | Tasks | Gives the demo |
|---|---|---|
| 1 | 1.1 to 1.14 (in 1.13, the checkpoint signed note can wait), plus 1.15, 1.16 and 1.17 | every check the judges will see, FROST signing, ZK mock passports and hybrid signatures |
| 2 | 2.1 to 2.5, 2.8 and 2.9 (with the ZKR mock passports), and from 2.6: T-A-07, T-A-12, T-A-17 | the real Testnet flow, FROST-signed multisig, the ZK flow and the ledger attack scenes |
| 3 | 3.1, 3.2, 3.3 (demo adapter), 3.4 (events, chain, in-process log, bundle), 3.7, 3.8, 3.9, 3.11 and the hybrid part of 3.12 (Node ML-DSA file signer, hybrid envelopes) | live updates, evidence, the offline verifier, the FROST relay, the ZK verifier and hybrid signatures in the evidence log |
| 4 | 4.1, 4.2 (key creation and signing; recovery later), 4.3, 4.4, 4.5, 4.7 (without the recovery screens), 4.8, 4.9 and 4.10 (the hash check; the separate origin can be a second port on the demo server) | the three screens, attack mode, two-share FROST signing on the phone and the ZKPassport request flow |
| 5 | 5.6 | seeding, prestart, checks and the fallback |
| 6 | SYS-01, SYS-A1 to A5, SYS-I2 from Phase 6 | a rehearsal that proves the demo |

FROST signing and the ZK mocks are visible on screen, so they stay in the subset. The post-quantum hybrid signatures (1.16 and the hybrid part of 3.12) are cheap and show up in the evidence log, so they stay too. The firm co-signer (3.10) can be a local process, and the recovery agent (3.9) can be a teammate's laptop.

Deferred until after the demo: the checkpoint signed notes from 1.13, 2.7 and 3.5 (the watcher; the coordinator polls in the meantime), 3.4 production adapters (Tessera, RFC 3161, WORM on S3), 3.6 KMS, 3.12 KMS ML-DSA-65 and the RFC 4998 renewal job, 4.2 recovery, the recovery and refresh screens in 4.7, the native chip helper 4.6, 5.1 to 5.5, 5.7, the rest of Phase 6, and Phase 7.

### 2.7 What this plan does not build, and how unhappy outcomes show

- **DESIGN 7.6 Batch (open decision O5) is not built in this plan.** The lock steps stay separate transactions, and the lock checker (task 1.11) covers the gap between them. If O5 is decided for Batch, it needs a new task in Phase 2 and a change to the lock tests.
- **How O9 shows in the tests.** O9 is a stall at release: a party refuses to sign a seal update, or refuses the release-time passport check. The plan does not try to force a signature. It tests that the refusal is recorded as evidence and that the money stays put: SYS-07 in Phase 6, and the ledger tests P2.6-03 (identity method change) and T-I-05 (rotation).
- **T-P-01 moves to milestone M0b.** DESIGN lists it with the core (FROST) tests, so it is part of G1 and not part of M0. Task 1.3 leaves it as a todo until task 1.15 completes it.

---

## 3. Demo profile and production profile

The system has two run profiles, set by `LEGX_PROFILE`. Both run the same code. Only the port implementations differ (section 7). The production profile refuses to start if any demo port is configured, and the demo profile shows a "DEMO" banner on every screen.

| Part | Production profile | Demo profile | Why it is safe for the demo |
|---|---|---|---|
| XRP Ledger | Mainnet, only after legal review (DESIGN O6) | **XRPL Testnet (real, public)**; local standalone ledger as the offline fallback | The ledger part is real. The judges can open every transaction in the explorer. |
| Bar registry | One adapter per jurisdiction, plus `manual` | **Mock bar registry** with 4 fake lawyers | The same adapter interface; no real person's data; no registry terms broken |
| Passports | A real chip, read by the native helper (task 4.6) | **Fixture passports** from `@legx/fixtures`, signed by a test CSCA | They pass the same passive authentication code |
| CSCA trust list | ICAO PKD or a country master list (DESIGN O10) | **Test CSCA** from `@legx/fixtures` | Real lists cannot check fake passports |
| Verifier and evidence keys | AWS KMS Ed25519 or Vault Transit | `FileSigner` with a local key file | Same `SignerPort` contract tests |
| Post-quantum service keys | AWS KMS `ML_DSA_65` (with `EXTERNAL_MU`) | A file signer using Node's built-in ML-DSA or `@noble/post-quantum` | Same hybrid `SignerPort` contract tests |
| ZKPassport (identity proofs) | The real ZKPassport app, with registry roots read on mainnet chains through our own RPC | ZKR (Zero Knowledge Republic) mock passports with `devMode` and the Sepolia registry | The same `ZkVerifierPort` and the same proof check; only the trust roots differ (mock certificates exist only in Sepolia). The release gate refuses Sepolia roots, mock identifier types and `devMode` in the production profile |
| ZKPassport domain | `legx.app`, passed explicitly to `new ZKPassport(domain)` | The same: `legx.app` | The identifier depends on the domain string, so a tunnel host name or app URL change must not change it |
| ZKPassport test tooling | Not shipped | `createMockPassport` from `@zkpassport/utils` 0.40.0-beta.2 (nested under SDK 0.19.2) and ZKPassport's headless prover `packages/e2e/src/prove.ts`, vendored as a development tool (`tools/zk-prove/`): about 10 s to prove, 0.65 s to verify | Makes and re-verifies mock proofs without a phone; the ZKPassport app on the demo phones is still used for the live scene |
| Client share 2 (second authenticator) | A FIDO2 security key with the PRF extension, or a second device, for every client | **One FIDO2 security key per client phone** (bring a spare for each). If a key is missing, the client slot runs in "single-device mode" (a same-phone passkey), and every screen and the evidence show that label | The signing path is the same two-of-three FROST path; single-device mode only loses the theft protection, and the label says so |
| Signing-code origin | A separate origin that the coordinator cannot change, serving the reproducible bundle with its published hash | A second port or host name on the demo laptop that serves the same bundle; the vault checks the hash before it runs | The same hash check (task 4.10); the demo only shortens the hosting |
| Recovery agent (client share) | An independent custodian that holds one FROST share | A teammate's laptop, marked "recovery agent" on screen | Same FROST relay and the same two-of-three signing path |
| Firm HSM co-signer (lawyer share) | An HSM that checks the transaction against the seal before it signs a share | A local process (`services/firm-cosigner/`) with the same check | Same check, same relay messages |
| Lawyer keys | Hardware token (DESIGN O7) | Browser vault key (non-extractable WebCrypto) | Same signing path for the ledger |
| WORM evidence storage | S3 Object Lock, compliance mode | A local folder, checked by hash | Same `ObjectStorePort` contract tests |
| Transparency log | Trillian Tessera sidecar | In-process RFC 9162 tree | Same proofs and checkpoint format |
| Time stamps (RFC 3161) | Commercial timestamp authority | A free public authority if it answers; otherwise skipped (the ledger `close_time` is the second clock) | DESIGN 8.4 already has two clocks |
| Postgres | Managed Postgres 18 | Postgres 18 in Docker on the laptop | Same migrations |
| Traces | OTel Collector, then Tempo, Loki, Prometheus | Jaeger all-in-one in Docker (optional) | Same spans and redaction rules |
| Arbitrator | A real arbitrator | A teammate presses "Record award" | Same award event and exit flow |
| Network path to phones | Public HTTPS hosting | Tailscale Funnel (first choice) or cloudflared quick tunnel (backup) | Browsers need HTTPS for WebCrypto |

**Demo-day dependencies that stay outside and can fail:** XRPL Testnet, the Testnet faucet (fund all accounts the day before), the Testnet explorer (keep screenshots), the tunnel (test it on the event Wi-Fi), the optional timestamp authority, the ZKPassport relay (the phone app and the web page talk through it), the Sepolia RPC (the registry roots), the ZKPassport CDNs (circuit files and certificate lists), and the ZKPassport app on both phones (it must be installed, updated and switched to developer mode with the mock passports loaded), and one FIDO2 security key per client phone with a spare (check on the demo phones that the browser passes PRF through to the key; if not, switch that client to the labeled single-device mode). Task 5.6 builds a check for each one, and a fallback for each one.

**Waiting time in the demo:** expiry after `CancelAfter` and the 256-ledger wait before `AccountDelete` need real time on Testnet. Task 5.6 starts one deal 30 minutes before the demo for those two scenes. On the standalone fallback, time is moved forward instead.

---

## 4. Tech stack

Eight research passes on 24 Oct 2026 chose this stack (five for the stack and XRPL, three for FROST, ZKPassport and post-quantum). Each one checked the npm registry for exact versions and dates, read the official docs and changelogs, and, where it mattered, ran a small prototype. The full notes, with a source for every decision, are kept with the project research files. This section gives the decisions and the reasons.

**Version policy.**
- Pin exact versions and commit the lockfile. The xrpl.js 4.2.1 to 4.2.4 supply-chain attack (CVE-2025-32965) is the reason.
- pnpm enforces a minimum release age of 14 days (`minimumReleaseAge: 20160`, in minutes). A newer version needs a written reason in the pull request.
- Two exceptions are allowed now, each with a reason: StrykerJS 10.1.1 (the first version that supports Vitest 5) and Vite 8.3.5 (one patch release; Vite 8 itself has been stable since March).

### 4.1 Summary

| Area | Pick | Version | Why |
|---|---|---|---|
| Runtime | Node.js LTS | 24.22.x (CI also runs 26.x) | Meets every tool's engine floor. Node 26 becomes Active LTS on 28 Oct 2026; move to it after the demo. The local machine has Node 22.14, which is too old (task 1.1 upgrades it). |
| Package manager | pnpm | 12.11.2 | Strict installs, catalogs for shared versions, and a built-in minimum release age |
| Task runner | Turborepo | 2.11.7 | Per-package caching in CI; about 10 packages do not need Nx |
| Compiler | TypeScript 7 for `tsc`, plus a TypeScript 6 alias for tools that need the compiler API | 7.0.2 and 6.0.2 | TS 7 is stable and fast, but ships no compiler API yet |
| Lint and format | Biome | 2.5.15 | No dependency on the TypeScript API; one tool for both jobs |
| Unit, property and browser tests | Vitest, @vitest/coverage-v8, @vitest/browser-playwright, fast-check, @fast-check/vitest | 5.0.5, 4.10.2, 0.5.0 | Projects, browser mode with real WebCrypto, model-based tests |
| End-to-end and visual tests | Playwright | 1.64.x | One context per role; phone device emulation; screenshots |
| Database tests | PGlite (unit), testcontainers with Postgres 18 (integration) | 0.5.11, 12.2.x | In-process Postgres 18.6 for speed; a real server for roles, locks and NOTIFY |
| API mocks | MSW | 3.0.3 | REST and WebSocket mocks for the web app |
| Mutation testing | StrykerJS with the Vitest runner | 10.1.1 | Mutation score gates on `@legx/core` |
| Fuzzing | fast-check properties as the main fuzzer; Jazzer.js on byte parsers | 4.10.2, 4.0.0 | Jazzer.js is quiet and Jest-only, so it is a supplement |
| Formal model | Quint | 0.33.0 | Model checking with Apalache and TLC |
| Dead code, duplication, architecture | knip, jscpd, dependency-cruiser | 6.41.0, 5.4.1, 18.5.0 | The Phase 7 toolset; ts-prune is legacy |
| Git hooks | lefthook | 2.2.1 | Parallel hooks, filtered by staged files |
| HTTP server | Fastify | 5.12.7 | `inject()` tests the whole app without a network; official WebSocket and OTel plugins; pino built in |
| API contract | oRPC (contract-first) | 1.16.x, pinned | End-to-end types, OpenAPI output, TanStack Query integration |
| Validation | Zod | 4.6.7 | JSON Schema export, Standard Schema, small `zod/mini` for the browser |
| Live updates | WebSocket (`@fastify/websocket`) with replay by per-deal `seq` | latest 2-week-old | Works through both tunnels (server-sent events do not pass the cloudflared backup) |
| Database | Postgres | 18.6 (`postgres:18.6-trixie`) | `uuidv7()`; supported to 2030 |
| Query layer and migrations | Kysely with `pg`; kysely-ctl running raw `.sql` files | 0.29.7, 8.23.x, 0.22.0 | `bytea`, raw SQL for `SKIP LOCKED` and `ON CONFLICT`, a PGlite dialect |
| Jobs | pg-boss, plus a hand-written outbox | 12.38.0 | Retries for signature expiry, RFC 3161 and anchors; the outbox is also the replay log |
| Logs and traces | pino; OpenTelemetry JS 2.x line (sdk-node 0.223, auto-instrumentations 0.81, @fastify/otel 0.21) | 10.4.0 | OTel 3.0 is 4 days old and @fastify/otel has not moved to it |
| Trace viewer (demo) | Jaeger all-in-one | 2.22.0 | One container |
| Production keys | AWS KMS Ed25519 (or Vault Transit) | client-kms 3.x | Ed25519 in KMS since 7 Nov 2025 |
| Web framework | React with Vite, one single-page app | 19.3.x, 8.3.5 | All sensitive work runs in the browser, so server rendering adds nothing |
| Routing and server state | TanStack Router, TanStack Query | 1.170.x, 5.104.x | Typed routes; live events update the query cache |
| UI state | Zustand | 5.0.x | UI-only toggles; never keys |
| UI kit | Tailwind CSS and shadcn/ui (Base UI) | 4.3.x, CLI 4.22.x | Fast to build; clear on a projector |
| PWA | vite-plugin-pwa | 2.0.0 | Installable phone app; never cache `/api` or `/ws` |
| Passkeys and security keys | @simplewebauthn/browser | 14.0.0 | WebAuthn PRF for the client's share 2: a FIDO2 security key with PRF, or a second device. A same-phone passkey is only the labeled "single-device mode" |
| QR codes | uqr | 0.1.3 | No dependencies; SVG |
| XRPL | xrpl.js, ripple-binary-codec; xrpl-py for differential tests | see 4.5 | The official libraries |
| Curves and hashes | @noble/curves, @noble/hashes, @scure/base | 2.4.0 | Audited; the same family xrpl.js uses |
| PKI and CMS | @peculiar/asn1-* and @peculiar/x509 to build; PKI.js with asn1js to verify | 2.11.0, 2.2.0, 3.4.3, 3.1.0 | PKI.js 4.0.0 is incompatible with the @peculiar packages today |
| JSON canonicalization | canonicalize | 5.1.0, exact | RFC 8785 |
| HPKE | @hpke/core | 1.9.0 | Backups and share transport (task 4.2) |
| Threshold signatures (FROST) | `ed25519_FROST` in `@noble/curves` | 2.4.0 (no new dependency) | Slot keys by DKG, two-share signing, strict Ed25519 output (DESIGN 6.4) |
| FROST reference | ZF `frost-ed25519` (Rust) | 3.0.0 | Cross-tests (`tools/frost-ref/`) and an optional HSM co-signer; has `refresh` and `repairable` |
| ZK passport proofs | `@zkpassport/sdk` | 0.19.2 (pinned) | Pre-1.0, no external audit; load with CommonJS `require` or a bundler, not plain ESM under Node |
| ZK mock passports | `@zkpassport/utils` | 0.40.0-beta.2 (nested under SDK 0.19.2) | `createMockPassport` for fixtures. It is NOT in 0.39.0. We do not choose this beta; the SDK depends on it, so pin it through the lockfile and a `pnpm.overrides` entry, and record why in the pull request (its age against the 14-day rule is a [CHECK]) |
| ZK headless prover | ZKPassport repo script `packages/e2e/src/prove.ts`, vendored as `tools/zk-prove/` | pinned upstream commit | A development tool: about 10 s to prove and 0.65 s to verify in Node, so mock proofs are made and recorded without a phone |
| ZK domain | the string `legx.app` | n/a | Passed explicitly to `new ZKPassport(domain)`; the identifier depends on it, so it is never the page origin |
| Post-quantum signatures and KEM | `@noble/post-quantum` | 0.7.1 | `ml_dsa65`, `ml_kem768`, `ml_kem768_x25519` (X-Wing); not audited, not constant-time |
| Post-quantum in Node | Built-in ML-DSA and ML-KEM (`node:crypto`, WebCrypto) | Node 24.7 or later (Node 24.22 already meets this) | Fast service-side signing, no dependency |
| X-Wing HPKE | `@hpke/hybridkem-x-wing`, or noble's `ml_kem768_x25519` | 0.7.0 | Backups and share transport (X-Wing is a draft, KEM ID 0x647a) |
| Production post-quantum keys | AWS KMS `ML_DSA_65` with `EXTERNAL_MU` | client-kms 3.x | RAW messages work up to 4 KB; larger ones need `EXTERNAL_MU` |
| Transparency log (production) | Trillian Tessera, POSIX sidecar | v1.0.4 | Production-ready; same C2SP formats as our in-process tree |
| Tunnel (demo) | Tailscale Funnel; cloudflared quick tunnel as backup | n/a | Stable HTTPS name, no warning page |

### 4.2 Toolchain and testing details

**TypeScript 7 with a TypeScript 6 alias.** TypeScript 7.0 ships no compiler API. Tools that read types through the API (dependency-cruiser's TypeScript parser, StrykerJS's type checker) need TypeScript 6. Use the official workaround in the root `package.json`:
```json
"devDependencies": {
  "@typescript/native": "npm:typescript@7.0.2",
  "typescript": "npm:@typescript/typescript6@6.0.2"
}
```
Run `tsc -b` from `@typescript/native` as its own Turborepo task. Do not use typescript-eslint (it requires TypeScript below 6.1). Biome lints without the API. In CI, oxlint with `oxlint-tsgolint` may add type-aware rules such as `no-floating-promises`.

**`tsconfig.base.json`:**
```json
{
  "compilerOptions": {
    "target": "ES2023", "lib": ["ES2023"],
    "module": "nodenext", "moduleResolution": "nodenext",
    "strict": true, "noUncheckedIndexedAccess": true, "exactOptionalPropertyTypes": true,
    "verbatimModuleSyntax": true, "erasableSyntaxOnly": true, "rewriteRelativeImportExtensions": true,
    "isolatedModules": true, "skipLibCheck": true, "types": ["node"], "composite": true
  }
}
```
Web packages override `module: "preserve"`, `moduleResolution: "bundler"` and `lib: ["ES2023", "DOM", "DOM.Iterable"]`. `packages/core` adds `isolatedDeclarations: true`. Use `#` subpath imports, not `paths` (TS 7 removed `baseUrl`).

**Run TypeScript without a build step.** Node 24 strips types natively, so services run with `node src/main.ts`. Rules this needs: no `enum`, no runtime `namespace`, no parameter properties, no decorators, and `.ts` in relative imports. `erasableSyntaxOnly` makes the compiler enforce them. The one exception is the `LDSSecurityObject` schema, which uses `@peculiar/asn1-schema` decorators. It lives in `@legx/fixtures` and the passport module, which are compiled by Vite and Vitest, not run raw by Node.

**Vitest 5.** One root config with projects: `unit` (Node), `browser` (Chromium and WebKit through Playwright), `integration` (needs the ledger and Postgres), and `e2e` (Phase 6). Breaking changes to know: `clearMocks` is on by default, and an unawaited `resolves` or `rejects` now fails the test. In CI, Turborepo runs each package's tests separately for caching, and `vitest --merge-reports` joins the coverage.

**fast-check 4.** Use `@fast-check/vitest` 0.5.0 (the first version for Vitest 5). Model-based tests use `fc.commands` with `fc.asyncModelRun`; race tests use `fc.scheduledModelRun` with `fc.scheduler()`.

**Quint 0.33.0.** `quint run --invariants ... --max-steps 30 --max-samples 10000`, and `quint verify --backend apalache` or `--backend tlc --temporal ends`. Both backends need Java in CI.

**CI.** GitHub Actions: `actions/checkout@v7`, `pnpm/action-setup@v6`, `actions/setup-node@v7` with `cache: pnpm`, and `actions/cache` for `.turbo/cache`. Pull requests run `biome ci`, `turbo run typecheck test --affected`, `knip`, and the ledger tests with a standalone xrpld container. The nightly workflow runs StrykerJS, long fuzz runs, Quint, Testnet and Devnet, and the full regression.

### 4.3 Backend details

**Fastify and oRPC.** Contract-first oRPC routes live in `packages/contracts`, so the server and the web client share one route table. The oRPC Fastify adapter bypasses Fastify's body parsing and `bodyLimit`. So two kinds of routes stay plain Fastify routes: signed-request routes (the client records view, DESIGN 8.10), which must read the raw body bytes, and the WebSocket endpoint. Pin every `@orpc/*` package to 1.16.x; oRPC 2 is in beta and its docs are moving.

**Postgres 18 and Kysely.** Use `postgres:18.6-trixie`. The image's data path moved to `/var/lib/postgresql`; a compose file that mounts `/var/lib/postgresql/data` loses data when the container is recreated. Migrations are raw `.sql` files run by the Kysely migrator, so PGlite (unit tests) and Docker (integration) run the same SQL. Use `uuidv7()` as a column default for IDs, but never as an ordering cursor; the per-deal `seq` is the cursor.

**Outbox and live updates.**
1. In one database transaction: the state change, the evidence event (with its per-deal `seq`), an outbox row, and `pg_notify('deal_events', dealId)`.
2. The WebSocket handler wakes on NOTIFY and sends every outbox row after the client's last `seq`.
3. pg-boss handles delayed and retried work: signature-request expiry, RFC 3161 calls, checkpoint anchors. It enqueues inside the same transaction.

**Observability.** pino with `redact` paths for every field branded `Secret<>` in the contracts. OpenTelemetry stays on the 2.x line until `@fastify/otel` supports 3.0. The Collector's redaction processor is beta for traces and alpha for logs, so a test (T-A-32) also checks what leaves the process.

**Keys.** `SignerPort` has three implementations:
- `KmsSigner`: AWS KMS, key spec `ECC_NIST_EDWARDS25519`, algorithm `ED25519_SHA_512`, `MessageType: RAW`, with a 4,096-byte message limit.
- `VaultSigner`: Vault Transit `ed25519`.
- `FileSigner`: demo profile only; it refuses to start otherwise.

Every `SignerPort` is hybrid: it returns an Ed25519 and an ML-DSA-65 signature. In production the second one comes from KMS `ML_DSA_65`; in the demo it comes from a file signer (Node ML-DSA or noble). Slot keys are not behind `SignerPort`: they are FROST shares held by the share holders (4.9).

### 4.4 Frontend details

**One Vite single-page app** with three routes: `/party/$role`, `/lawyers` and `/dashboard`. This was prototyped on 24 Oct 2026 with these results:
- xrpl.js 5.3.0 builds and runs in Vite 8 with no Node polyfills. Do not add a polyfill plugin.
- A non-extractable WebCrypto Ed25519 key signs `encodeForMultisigning(tx, address)` with the same bytes as xrpl.js.
- `encodeForMultisigning` comes from `ripple-binary-codec`; `xrpl` does not export it.
- xrpl 5 adds an optional WASM file (about 1.5 MB gzipped) for confidential MPT. It loads only on demand, so keep it out of the PWA precache.

**Browser facts that shape the design:**
- `crypto.subtle` exists only in secure contexts. Plain `http://` on a LAN IP has no WebCrypto, so phones must use HTTPS (the tunnel).
- WebCrypto Ed25519: Chrome 137+, Firefox 129+, Safari and iOS 17+.
- WebAuthn PRF: iOS and iPadOS 18+ (cross-device bugs until 18.4), macOS Safari 18+, Chrome 132+ on macOS, Android Chrome with Google Password Manager, Windows Hello with Chrome 147+ or Firefox 148+. Chrome's own profile authenticator has no PRF, so a recovery-code fallback is always offered. Which browsers pass PRF through to a USB or NFC FIDO2 security key (the client's share 2) is a [CHECK] for task 4.7; a same-phone passkey is allowed only as the labeled "single-device mode".
- On iOS, the home-screen app and the Safari tab may not share IndexedDB. Call `navigator.storage.persist()`.

**Tunnel.** Tailscale Funnel first: a stable `*.ts.net` HTTPS name, no warning page, and it passes WebSocket. Set it up a day early, because DNS can take up to 10 minutes. The backup is a cloudflared quick tunnel: its URL changes on every restart, so the QR code is drawn from `location.origin`, and it does not pass server-sent events (one reason live updates use WebSocket). Avoid ngrok free, which shows a warning page on the first visit.

**Testing.** Vitest browser mode on Chromium and WebKit for anything that touches WebCrypto or IndexedDB (jsdom has neither). Playwright for flows. Each role is its own browser context, so its key storage is isolated. Playwright's `storageState` does not carry IndexedDB, so keys are made inside each test. Visual baselines are made in Docker, because screenshots differ between operating systems.

### 4.5 XRPL details

These facts were checked on 24 and 25 Oct 2026. Most come from a live run on XRPL Testnet that exercised the transaction types in this design: credentials, an NFT mint with a memo, a conditional escrow, a 4-of-4 signer list, the DisallowIncoming flags, `DisableMaster`, multisigned payments on one slot, escrow cancel and an anchor memo.

**Libraries.**
- **xrpl.js 5.3.0** (16 Sep 2026; needs Node 20.19 or later): the latest version.
- **Helpers it exports:** `multisign`, `getNFTokenID`, `parseNFTokenID`, `encodeForMultiSigning` and `verifySignature`.
- **`verifySignature` still fails on multisigned blobs** ("Transaction is missing a signature"). That is why `verifyMultisigned` in `@legx/core` exists.
- **`Wallet.generate()` makes Ed25519 wallets by default.**
- **xrpl 5.0.0 changed `Wallet.fromSeed`:** it no longer defaults to Ed25519. It infers the algorithm from the seed prefix, so always pass `algorithm: 'ed25519'`.
- **Related packages:** `ripple-binary-codec` 2.11.0, `ripple-keypairs` 3.1.0, and xrpl-py 5.2.0 (for the differential tests in task 5.3; 5.3.0b0 is a pre-release).

**Testnet and Devnet (from `server_info`):**

| | Testnet | Devnet |
|---|---|---|
| Server | xrpld 3.4.1 | xrpld 3.4.1 |
| Network ID | 1 | 2 |
| Base fee | 10 drops | 1 drop |
| Reserves | 1 XRP base, 0.2 XRP per object (the same as Mainnet) | 1 XRP base, 0.2 XRP per object |
| Ledger close | about 3 seconds | n/a |
| Credentials and the other features we use | enabled | enabled |

Retired amendments are confusing on Testnet too: `Escrow`, `MultiSign` and `CryptoConditions` report `enabled: false`, although their code is always on and the live run used them. The startup check (task 2.1) treats retired amendments as active everywhere, and never gates on them.

**Engine results seen on Testnet:**
- Every step returned `tesSUCCESS`.
- `meta.nftoken_id` equals `getNFTokenID(meta)`.
- A multisigned `EscrowCancel` before `CancelAfter` returned `tecNO_PERMISSION`; after it, `tesSUCCESS`.
- Two exits on one slot: the first validated, and the other can only get `tefPAST_SEQ`.
- After cleanup, `account_objects` with `deletion_blockers_only: true` returned an empty list. A Credential and a SignerList do not block `AccountDelete`; an NFT page does.
- A 4-of-4 multisigned `AccountDelete` returned `tesSUCCESS` and was charged one owner reserve (0.2 XRP) plus the autofill margin. `AccountDelete` removed the remaining credential by itself.
- The public server clamps the `account_objects` `limit`: a request for 1 object returned 2 and no marker. Always follow `marker` anyway (P2.2-05 and 06).

**Two kinds of DepositPreauth.** Testnet confirms that with a **credential-based** DepositPreauth (`AuthorizeCredentials`), the submitter of an `EscrowFinish` must hold the credential and pass `CredentialIDs`, or the result is `tecNO_PERMISSION`. Our design uses an **account-based** DepositPreauth (D23), which needs no `CredentialIDs`. This passed in T-I-01 on the standalone ledger. Test P2.3-05 pins it: the finish carries no `CredentialIDs`.

**Faucet.**
- **API:** `POST https://faucet.altnet.rippletest.net/accounts`, with an optional `destination` and `xrpAmount`.
- **Amounts:** 100 XRP by default; up to 1,000 XRP when asked; larger requests are refused.
- **Timing:** about 6 seconds until the balance is validated.
- **Limits:** none are published. Fund the demo accounts once, the day before, and reuse them (task 5.6). Never loop the faucet.

**Explorers.** The dashboard links (P4.5-01) use these patterns:

| Explorer | Transaction | Account | NFT |
|---|---|---|---|
| testnet.xrpl.org | `/transactions/<hash>` | `/accounts/<address>` | `/nft/<id>` |
| test.bithomp.com (backup) | `/en/explorer/<hash>` | `/en/account/<address>` | `/en/nft/<id>` |

**Docker.**
- `rippleci/xrpld:3.4.1` is the latest release, and it is amd64 only. The last arm64 image was 3.1.1. On Apple Silicon, run 3.4.1 with `--platform linux/amd64`.
- Do not run Clio locally: it needs Cassandra or ScyllaDB plus an upstream xrpld.
- For the watcher's second server (DESIGN 8.5), use the public Testnet Clio at `wss://clio.altnet.rippletest.net:51233` (Clio 2.8.0). It also answers `nft_info`, which plain rippled does not. The Devnet Clio certificate had expired on test day.

**Reliable submission.**
- **What `submitAndWait` does:**
  - It sets `LastLedgerSequence` to the validated ledger + 20.
  - It throws at once on `tem` results.
  - For `tef` results, it waits about 20 ledgers before it throws.
  - It returns `tec` results as normal validated responses.
  - It refuses a transaction with no `LastLedgerSequence`.
- **Why we write our own `submitReliable` (task 2.2):** the reasons above, plus that xrpl.js has no rebroadcast loop. Our function:
  - treats `tel` and `ter` as not final;
  - treats `tefPAST_SEQ` on an exit as "the other exit won";
  - proves a transaction is absent only when three things are true: the validated ledger is past its `LastLedgerSequence`, the server's `complete_ledgers` covers the range from the submit ledger to `LastLedgerSequence`, and `tx` with `ledger_index_min` and `ledger_index_max` over that range returns `txnNotFound`. Testnet did not return a `searched_all` field, so the function does not rely on it.

**Slot S.**
- **Read the slot from a validated ledger:** `account_info` with `ledger_index: 'validated'`. xrpl.js `autofill` reads the current ledger, which includes queued transactions.
- **Fee headroom:** sign exits with 5 to 10 times the base fee, so fee spikes cannot strand them.
- **Ticket variant:** use a Ticket only if the deal wallet must send other transactions between signing and exit (DESIGN 7.5). Anchors come from a separate account, so the plain sequence slot is enough for v1.

**NFTokenID layout.**
- **Byte layout:** flags (2 bytes), transfer fee (2), issuer AccountID (20), scrambled taxon (4), mint sequence (4).
- **In code:** `parseNFTokenID(id).Issuer` gives the issuer with no network call. The release gate uses it for `CONTRACT_SEAL_OK`.

**WebSocket limits.** Seven account subscriptions plus the ledger stream is light load on the public Testnet servers. After a reconnect, the subscription is gone: subscribe again and backfill with `account_tx` from the last seen ledger (task 2.7).

### 4.6 Crypto, PKI and evidence details

| Need | Use | Write ourselves |
|---|---|---|
| Ed25519, secp256k1, P-256, brainpool, SHA-2, HKDF | @noble/curves and @noble/hashes 2.4.0 (`.js` import paths) | nothing |
| Test CSCA and Document Signer certificates | @peculiar/x509 2.2.0 | nothing |
| EF.SOD (CMS SignedData with LDSSecurityObject) | @peculiar/asn1-cms 2.11.0 to build; PKI.js 3.4.3 to verify | the LDSSecurityObject schema (about 35 lines), DG1, DG15 and SOD tag wrappers (about 40), the MRZ builder and check digits (about 40) |
| Passive authentication | PKI.js `SignedData.verify({ checkChain: true, trustedCerts })` | the verifier wrapper with the brainpool fallback (about 220 lines) |
| Active Authentication | noble for EC plain `r||s` | RSA ISO/IEC 9796-2 scheme 1 (about 100 lines), DG14 parsing (about 50) |
| DSSE and in-toto | none needed | `pae()` and envelope code (about 70 lines); `@sigstore/core` as a test cross-check |
| Merkle log and checkpoints | none needed in the demo; Tessera in production | RFC 9162 tree (exists), C2SP signed-note checkpoint (about 100 lines); `@cloudflare/*-wasm` as test cross-checks |
| RFC 3161 | PKI.js `TimeStampReq` and `TimeStampResp` | the client (about 130 lines) |
| JSON canonicalization | canonicalize 5.1.0 | nothing |

In total, we write about 1,300 to 1,500 lines of crypto, PKI and evidence code, plus tests.

**Test vector sources** (vendored in task 1.3):
- **Wycheproof** (`C2SP/wycheproof`, folder `testvectors_v1/`): Ed25519, ECDSA P-256 (DER and plain `r||s`), brainpool, RSA-PSS and HKDF. Run Ed25519 with `zip215: false`.
- **Strict Ed25519:** `novifinancial/ed25519-speccheck` `cases.json` (cases 0, 1, 9, 10 and 11), and noble's `test/vectors/ed25519/zip215.json`.
- **HKDF:** RFC 5869 Appendix A.
- **Crypto-conditions:** `rfcs/crypto-conditions` `test-vectors/valid/0000` to `0017`.
- **Merkle:** `transparency-dev/merkle` `testdata/inclusion` and `testdata/consistency`.
- **RFC 8785:** `cyberphone/json-canonicalization` test data.
- **eMRTD:** BSI TR-03105-5 sample data, which includes an RSA Active Authentication key.

### 4.7 Choices we did not make, and why

| Rejected | Reason |
|---|---|
| Self (the audited ZK passport alternative) | Its proofs verify on Celo, which adds a chain we do not otherwise use (research r6). ZKPassport verifies off-chain with our own RPC. |
| SLIP-0039 Shamir recovery | Replaced by FROST recovery: a lost share is repaired from the other two without ever rebuilding the key |
| FROST trusted-dealer setup | The dealer sees the whole key. We use DKG only. The dealer function is allowed in tests |
| Composite single signatures (Ed25519 + ML-DSA in one signature) | The draft is not an RFC. We use two DSSE signatures instead, both required |
| Next.js, TanStack Start, SvelteKit | Server rendering adds nothing when keys live in the browser. TanStack Start (stable 13 Oct 2026) and SvelteKit 3 (1 Oct 2026) are too new for a security demo. |
| Hono | `@hono/node-ws` is deprecated, and its peer range lags `@hono/node-server` 2.x |
| tRPC v11, ts-rest | No OpenAPI output (tRPC); no stable release since March 2025 (ts-rest) |
| Drizzle, Prisma | Drizzle stable has no `bytea` column; Prisma's `latest` tag is a release candidate |
| pg-mem | Its own docs call it experimental; poor support for plpgsql triggers |
| XState | Its saved snapshots can break when the machine changes; our pure transition table is simpler to persist and to model-check |
| Server-sent events | The cloudflared backup tunnel does not pass them |
| ESLint with typescript-eslint | Requires TypeScript below 6.1 |
| PKI.js 4.0.0 | Released 22 Oct 2026; needs asn1js 4, which the @peculiar packages do not use yet |
| OpenTelemetry JS 3.0 | Released 20 Oct 2026; @fastify/otel still depends on 2.x |
| Changesets | Private app packages are not versioned for publishing |

### 4.8 Repository layout

```
legx/
  packages/
    contracts/      shared types, Zod schemas, ports, oRPC route table (frozen at G0)
    core/           @legx/core: every recipe in DESIGN 6 (pure, no I/O)
    fixtures/       test PKI, fixture passports, golden vectors (read-only for other lanes)
    xrpl/           @legx/xrpl: builders, submit, one-ledger reads, multisig, watcher client, harness (`test-int/frost/` for T-I-11)
    zk/             ZkVerifierPort adapter over the ZKPassport SDK (task 3.11), mock-passport helpers (lane L15); this is the only name for this folder
    db/             Kysely schema, SQL migrations, repositories
    signer/         SignerPort (hybrid): KmsSigner, VaultSigner, FileSigner, KMS ML-DSA-65 and Node ML-DSA signers
    storage/        ObjectStorePort (S3 Object Lock, local folder), TransparencyLogPort (Tessera, in-process)
    observability/  OTel setup, span names, redaction lists
    vault/          browser key vault and recovery
    ui/             shared React components
    chip-link/      chip transfer format, encrypted QR session and console receiver (task 4.6)
  services/
    coordinator/  verifier/  evidence/  watcher/
    recovery-agent/   holds one client FROST share (demo: a teammate's laptop)
    firm-cosigner/    holds one lawyer FROST share and checks the seal (demo: a local process)
  apps/
    server/               one Fastify process for the demo
    web/                  /party/$role, /lawyers, /dashboard
    mock-bar-registry/    demo only
    chip-reader-android/  native passport reader helper (task 4.6); an unbuilt Kotlin skeleton
  tests/
    system/    @legx/system-tests: the real server process, demo profile, wiring audit and REGRESSION.md (phase 6)
    break-it/  intended-failing attack tests, one or more per I-S finding (task 5.7)
  tools/
    verifier-cli/  fuzz/  py-ref/  mutation/
    differential/ @legx/differential: A/B tests of core against the second implementations (task 5.3)
    frost-ref/    ZF frost-ed25519 3.0.0 cross-test harness (Rust); the only name for this folder
    zk-prove/     ZKPassport headless prover (prove.ts), vendored dev tool
    record-zk/    records mock proofs, registry answers and circuit files; offline re-verification test (CommonJS)
  spec/deal.qnt
  e2e/
  demo/
  ci/xrpld.cfg
  DESIGN.md  IMPLEMENTATION.md
```

### 4.9 Threshold, zero-knowledge and post-quantum details

Sources are the research notes `research/r6-zkpassport.md`, `r7-frost.md` and `r8-pq.md`, checked on 24 Oct 2026, the prototypes of the same day (`scratchpad/proto-frost/`, `proto-pq/` and `proto-zk/`), plus the standards named below.

**FROST (r7).**
- `@noble/curves` 2.4.0 exports `ed25519_FROST`: trusted dealer, a 3-round DKG with proofs of knowledge, `commit`, `signShare`, `aggregate` and `verifyShare`. We use DKG only. Source: the `@noble/curves` README and `test/` folder.
- noble has no refresh and no repair. We write refresh ourselves (task 1.15) and test it against ZF `frost-ed25519` 3.0.0 `refresh` and `repairable`. ZF refresh and repair are not in the NCC audit scope (NCC audited ZF v0.6.0). noble's FROST has no independent audit. See DQ-14.
- 60 of 60 FROST signatures passed strict `zip215: false` verification, so the group signature works with `verifyXrplKeySig` and the XRPL master-key rules.
- Vectors: RFC 9591 Appendix E.1, and ZF `frost-ed25519/tests/helpers/vectors.json`, `vectors_dkg.json` and `repair-share.json`.
- noble zeroes nonces after use and throws "signing nonces already used". We also keep nonces in memory only, never in storage.
- DKG round 2 sends secret shares, so it needs confidential and authenticated channels (the coordinator relay with HPKE, and enrollment keys from DESIGN 6.3).
- Nobody has published FROST on XRPL multisign, so T-I-11 proves it on standalone and on Testnet. A prototype on 24 Oct 2026 (`scratchpad/proto-frost/`) already did: rippled 3.4.1 standalone validated a 4-slot multisigned Payment with every signature a 2-of-3 FROST signature (`tesSUCCESS`).
- noble API (prototype): `DKG.round1(id, {min: 2, max: 3})`, `DKG.round2`, `DKG.round3` returning `{public, secret}`, then `commit`, `signShare`, `verifyShare` and `aggregate`. The group key is `public.commitments[0]`. Timings: DKG about 88 ms per slot, signing about 25 ms.
- A hand-written refresh worked in the prototype, but the Feldman sub-share checks were not done there. They are written and tested in task 1.15.
- XRPL signers must be sorted by decoded AccountID.
- `xrpl` 5.3.0 plus noble static imports hit `ERR_REQUIRE_CYCLE_MODULE` on Node 22.14. Test the import on Node 24 (our floor) and use a dynamic `import('xrpl')` if needed.
- The key directory is pinned out of band (a QR scan between a client's own devices; a signed list anchored on the ledger for service holders). The `enrollment_key` table is append-only. Key generation is an echo broadcast, and all three pairs test-sign before the seal (DESIGN 6.3 and 6.4).
- Code integrity: the vault and FROST code is a reproducible static bundle with a published hash, served from a separate origin that the coordinator cannot change (task 4.10).

**ZKPassport (r6).**
- Packages: `@zkpassport/sdk` 0.19.2 (Apache-2.0, weekly releases, pre-1.0, no external audit), `@zkpassport/registry` 0.15.3 and `@zkpassport/utils` 0.40.0-beta.2 (nested under the SDK; it has `createMockPassport` and 0.39.0 does not). Pin all three.
- Flow: `request({scope, devMode, validity, ...}).gte('age', 18).bind('custom_data', str).done()` returns a URL for a QR code or a deep link. The phone app proves in about 10 to 50 seconds. `bind` takes at most about 506 bytes, enough for a contract root and a slot key hash. The unique identifier is stable for the same passport, domain and scope, which is why the onboarding and release proofs use one scope per deal. The domain is always the explicit string `legx.app` given to `new ZKPassport(domain)`, never the page origin, so a tunnel or app URL change cannot change an identifier. The bind length (at most 506 bytes) is checked by our code, because the SDK does not check it at request time.
- `verify()` is not network-free. It needs an Ethereum RPC for the registry roots and ZKPassport's CDNs for circuits and certificate lists. Use `verifierMode: "local"` (never the hosted fallback, which sends proofs to a third party), our own RPC and a pinned version. The registry operators are the trust root for which certificates count.
- ZKPassport proves passive authentication only. It has no Active or Chip Authentication, so it does not prove the chip was present. See DQ-15.
- Mocks: the ZKR mock passports in the app's developer mode, with `devMode: true` in both `request` and `verify`. Mock certificates exist only in the Sepolia registry. Mock identifiers DIFFER per passport and per scope, and are stable for the same passport, domain and scope, so the scope and stability tests run in CI on mocks. Only the real (non-mock) identifier formula needs one recorded real-passport run (T-U-28c).
- Headless proving: ZKPassport's repo script `packages/e2e/src/prove.ts` works in Node: about 10 s to prove, 0.65 s to verify, 5 proofs of about 14.7 KB each. We vendor it as a development tool (`tools/zk-prove/`) and use it to record mock proofs.
- Offline verify: `verify({ config })` accepts injected loaders (`rpcUrl`, `circuitManifestUrlGenerator`, `packagedCircuitUrlGenerator` and others). It returned `verified=true` with the network blocked, which is how an arbitrator re-verifies from the bundle.
- The result holds `proof`, `vkeyHash`, `version` and `committedInputs` (the bound data in plain text). The scope is not in the result, so we store it ourselves.
- Whether `verify()` runs in a browser is unknown (`bb.js` has about 4 MB of WASM and needs `SharedArrayBuffer` for threads). Verification runs in Node unless task 4.8 shows the browser works.
- Trust record per attestation: chain ID, block number and hash, registry address, root, circuit manifest version, verification-key hashes, identifier type and `dev_mode`. The production gate refuses Sepolia (chain 11155111), mock identifier types and `devMode`.
- `C_side` is salted: `tupleHash("legx/zk-identity/v1", [zkSalt32, utf8(N_side)])`. The salt is kept with share 2, with an encrypted copy to the client's lawyer.
- A plain ESM import of the SDK fails under Node. Use CommonJS `require` or a bundler (Vite for the browser side).
- Self is the audited alternative but verifies on Celo (rejected, 4.7).

**Post-quantum (r8).**
- `@noble/post-quantum` 0.7.1 has `ml_dsa65`, `ml_kem768` and `ml_kem768_x25519` (X-Wing). It is not audited and not constant-time, so browser use is for the post-quantum binding and enrollment only, and services use Node's built-in implementation or KMS.
- Sizes and speed: ML-DSA-65 public key 1,952 bytes, signature 3,309 bytes, signing about 9 ms. A hybrid JSON envelope is about 4.45 KB larger (base64 of both).
- Node 24.7 and later has ML-DSA and ML-KEM in `node:crypto` and WebCrypto (Node 24.22 meets this; every prototype step passed there). Node accepts a raw public key through `{ format: 'raw-public', asymmetricKeyType: 'ml-dsa-65' }`, and contexts work through `{ key, context }`. Node's default ML-DSA context is EMPTY, so every signer and verifier passes the context explicitly (`legx/dsse/v1`, `legx/pq-binding/v1`, `legx/checkpoint/v1`).
- noble exposes `ml_dsa65.internal.sign(mu, sk, { externalMu: true })`, which the KMS `EXTERNAL_MU` path uses: we compute mu ourselves.
- The algorithms a record must carry are fixed per record type and format version in verifier code, not read from the record.
- The per-slot post-quantum binding is 2 of 3: `pqKeyHash_slot` is the SHA-256 of the slot's three holder ML-DSA-65 enrollment keys, any two holders sign `pqBindMsg`, and the slot key cross-signs. There is no separate single post-quantum key per slot.
- AWS KMS `ML_DSA_65` and `ML_DSA_SHAKE_256` accept RAW messages up to 4 KB; larger messages use `EXTERNAL_MU`. Task 3.12 picks RAW or `EXTERNAL_MU` by message size.
- C2SP signed-note type 0x06 is a timestamped ML-DSA-44 cosignature, used for hybrid checkpoints next to the Ed25519 line (0x01). Standard signed-note verifiers ignore unknown keys, so our verifier requires BOTH lines. We built and verified a 0x06 line in the prototype, but it is untested against another implementation, and the spec names no ML-DSA context (we use the empty one; a [CHECK]).
- `@hpke/hybridkem-x-wing` 0.7.0 is an alternative to noble's `ml_kem768_x25519`. It needs the `Aes256Gcm` and `HkdfSha256` instances passed in, and it interoperates with noble's `ml_kem768_x25519`. X-Wing is an IETF draft (KEM ID 0x647a), so the ciphertext carries an algorithm tag.
- XRPL has no post-quantum keys yet (an ML-DSA-44 draft, discussion 295). The ledger signature stays Ed25519 (FROST); the post-quantum part lives in the evidence, in the per-slot post-quantum binding and in the DSSE envelopes (DESIGN O17). Honest limit: a quantum break of Ed25519 lets an attacker move the money until the ledger migrates.
- RFC 4998-style re-time-stamping keeps old evidence provable after a hash or signature algorithm weakens. It is a scheduled job (task 3.12) and is deferred in the demo subset.

---

## 5. Phase 1: Foundation and core library

**Goal.** One repo, one toolchain, one frozen set of shared contracts, and a complete `@legx/core` that computes every byte in DESIGN section 6: the deal seal, FROST slot keys, post-quantum hybrid crypto and zero-knowledge identity checks included. Nothing in this phase touches a network. Network work (relays, KMS, the ZKPassport verifier) sits behind ports and belongs to Phases 2 and 3.

**Owns:** `package.json`, `pnpm-workspace.yaml`, `tsconfig.base.json`, `biome.json`, `vitest.config.ts`, `.github/`, `packages/contracts/`, `packages/core/`, `packages/fixtures/`.

**Starts:** at once. **Unblocks:** everything. Task 1.1 and task 1.2 form gate **G0**. After G0, Phases 2, 3 and 4 start in parallel.

**Covers DESIGN:** 6.1 to 6.17, 8.1 (envelope shapes), 8.2 (chain), 10.2 (invariants as code), and milestones M0 and M0b. Lanes: L0 to L3 as before, plus L13 (FROST, task 1.15), L14 (post-quantum, task 1.16) and L15 (zero-knowledge, task 1.17).

### 1.1 Repo scaffold and toolchain (gate G0, part 1)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L0 | Haiku | low | S (2 h) | nothing |

**Research.**
- Read section 4 of this doc (the stack). Confirm each pinned version still installs: `pnpm view <pkg> version`.
- Read the Vitest "projects" docs, because one root config runs every package.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P1.1-01 | `pnpm install --frozen-lockfile` on a clean clone | exits 0 |
| P1.1-02 | `pnpm typecheck` with one empty package | exits 0 |
| P1.1-03 | `pnpm test` with one placeholder test per package | runs every project, exits 0 |
| P1.1-04 | `pnpm lint` on a file with an unused import | fails |
| P1.1-05 | CI workflow `ci.yml` on a pull request | runs install, lint, typecheck, unit |
| P1.1-06 | A commit that contains a string matching an XRPL family seed (`s` + 28 base58 chars) | the pre-commit hook refuses it |
| P1.1-07 | `node --version` against `.nvmrc` and `engines.node` (24.22 or later); `pnpm --version` against `packageManager` (12.11.2) | a wrong version fails `pnpm install` with a clear message (the local machine has Node 22.14 today and must be upgraded) |
| P1.1-08 | `pnpm add` of a package version published less than 14 days ago | refused by `minimumReleaseAge` |

**Think.** Keep one root Vitest config with `projects`. Each package has its own `tsconfig.json` that extends the base. Do not add a build step for internal packages. Point `exports` at `src/*.ts` and let Vite and Vitest compile them.

**Test in all directions.** Run P1.1-01 to 03 on Node 22 and Node 24 in CI. Check that a package cannot import another package's `src/` by a relative path; the lint rule `noRestrictedImports` catches it.

**Think hard.** A secret in git is the worst early mistake. The seed pattern hook (P1.1-06) and `.gitignore` entries for `*.seed`, `.env*` and `demo-keys/` go in now, not later.

**Implement.**
1. `pnpm init`, then `pnpm-workspace.yaml` with `packages/*`, `services/*`, `apps/*`, `tools/*`.
2. `tsconfig.base.json` from section 4.2.
3. Root `vitest.config.ts` with projects `unit`, `integration`, `browser`, `e2e`.
4. `biome.json`, `lefthook.yml` (format, lint, seed scan), and `.github/workflows/ci.yml` (copy from DESIGN Appendix D and switch to pnpm).

**Done when** P1.1-01 to 08 pass.

### 1.2 Shared contracts freeze (gate G0, part 2)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L0 | Opus | xhigh | M (6 h) | 1.1 |

This task is the reason parallel work is safe. It writes every type, schema and port that two lanes share. After G0, a change to `packages/contracts` needs a pull request that every lane owner approves.

**Research.**
- DESIGN 6.2 to 6.17, 8.1, 8.10 and 9: list every record, event and field, including the new `deal_key` columns (`slot_policy`, `pq_key_hash`, `pq_binding_sigs` as jsonb with two signatures, `pq_cross_sig`, `id_method`) and the `zk_proof` and `enrollment_key` tables (the second one is append-only).
- `research/r7-frost.md` (what the FROST relay must carry), `research/r6-zkpassport.md` (the shape of a verification result) and `research/r8-pq.md` (key and signature sizes, so schemas set exact lengths).
- Zod 4 docs: `z.toJSONSchema`, and branded types for hex strings and addresses.
- The API style picked in section 4: how routes are declared once and used by the server and the web client.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P1.2-01 | Each schema parses its golden example in `packages/contracts/examples/*.json` | passes |
| P1.2-02 | Each schema rejects one wrong example per field (wrong hex length, bad address, extra key) | fails with a path to the field |
| P1.2-03 | `z.toJSONSchema` output for every schema matches a committed snapshot | snapshot equal; a change is a visible diff |
| P1.2-04 | Type tests (`expectTypeOf`) for each port: `LedgerPort`, `SignerPort`, `EvidenceStorePort`, `ObjectStorePort`, `BarRegistryAdapter`, `TsaPort`, `ClockPort`, `ZkVerifierPort`, `FrostRelayPort` | compile |
| P1.2-05 | The route table: each route has a request schema, a response schema and an auth rule | a test walks the table and fails on a missing one |
| P1.2-06 | `EventKind` equals the list in DESIGN 8.1, including `frost.dkg.completed`, `frost.signed`, `frost.refreshed`, `identity.onboarded` and `pq.bound` | exact set equality |
| P1.2-07 | `SignerPort.signHybrid(msg, ctx)` returns `{ ed25519, mlDsa65, keyIds }`; a type test shows that one signature alone does not satisfy the return type | compiles; the wrong shape does not |
| P1.2-08 | `ZkVerifierPort.verify(req)` returns the recorded-result shape (`verified`, `uniqueIdentifier`, `uniqueIdentifierType`, `queryResultErrors`, `proofSha256`, `vkeyHash`, `version`, `committedInputs`, `scope` (the SDK result has no scope, so our request records it) and the trust record of DESIGN 6.10: `chainId`, `blockNumber`, `blockHash`, `registryAddress`, `root`, `circuitManifestVersion`, `vkeyHashes`, `devMode`); `FrostRelayPort` carries only commitments, signature shares and encrypted DKG packages, never a secret share in the clear | schema and type tests pass; a schema with a plain-text share field fails review |
| P1.2-09 | `PublicDealData` has exactly the 29 seal fields of DESIGN 6.6, and `PassportAttestation.method` accepts only `"zkpassport"` and `"nfc-chip"` | a golden example parses; a 30th key or a third method is rejected |

**Think.** The contracts package holds:
- **Value types:** `Hex32`, `XrplAddress`, `XrplPubKey` (`ED` + 64 hex), `Drops` (string of digits), `RippleTime` (number), `Role`, `Side`.
- **Public deal data:** every field that goes into the deal seal (DESIGN 6.6, 29 fields), as one `PublicDealData` type.
- **Records:** `PassportAttestation` (a union on `method`), `BarVerification`, `BarDealLink`, `LegxEvent`, `Finding`, `SlotPolicy`, `PqBinding`, `ZkVerification`, `EnrollmentKey`.
- **Ports:** the interfaces that services implement or call. `LedgerPort` hides xrpl.js. `SignerPort` hides KMS or a local key. `ClockPort` returns the validated ledger `close_time`, never `Date.now()`. The three new ports are `ZkVerifierPort` (network proof verification; core only sees its recorded result), `FrostRelayPort` (the coordinator's relay of commitments, signature shares and encrypted DKG packages) and the hybrid `SignerPort`, which returns both an Ed25519 and an ML-DSA-65 signature and has no method that returns only one.
- **API routes** and the server-sent event schema.

**Test in all directions.** Fuzz each schema with `fc.anything()`; a schema must never throw anything but a Zod error. Round trip: `parse(JSON.parse(JSON.stringify(x)))` equals `x` for every golden example.

**Think hard.** Ask of each field: does it ever carry passport data, a name, a bar number, a salt, a FROST secret share or a signing nonce? If yes, it must not be in an API response or an event. Mark such fields with a `Secret<>` brand, so a lint rule can block them from logging calls.

**Implement.** One file per area: `values.ts`, `deal.ts`, `records.ts`, `events.ts`, `ports.ts`, `api.ts`, `sse.ts`. Export the JSON Schemas for documentation.

**Done when** P1.2-01 to 09 pass and the lane owners have signed off the freeze.

### 1.3 Import the starting code (DESIGN Appendix A) and vendor the test vectors

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L1 | Haiku | low | S (2 h) | 1.1 |

**Research.** Find the vector files and their licenses (section 4.6 lists them; FROST and post-quantum vectors are vendored in tasks 1.15 and 1.16): RFC 8032 section 7.1, RFC 5869 Appendix A, Wycheproof `ed25519_test.json` and `hkdf_sha256_test.json` (HKDF stays for the evidence and HPKE paths, not for slot keys), the crypto-conditions minimal preimage vector, the transparency-dev Merkle test data, and the RFC 8785 test data.

**Test first.** DESIGN Appendix A is already changed to match DESIGN 6. Two of its tests pin old values and get new ones here: T-U-06 (the seal test takes the new golden value from task 1.6) and the old test of a client's x-key signing in the deal (it turns into T-P-01, "every 2-of-3 pair signs; one share alone cannot", which task 1.15 completes). Until 1.15 lands, T-P-01 is a placeholder that fails on purpose (`it.todo` with the task number). T-P-01 now belongs to milestone M0b (the core with FROST), not to M0.

| ID | Test | Expected |
|---|---|---|
| P1.3-01 | The extraction script writes DESIGN Appendix A byte for byte (a SHA-256 of each code block matches) | passes |
| P1.3-02 | The existing tests (DESIGN T-U-01 to 11, T-P-02 to 05, T-A-01 to 25 checker cases; T-U-06 with its new golden value) | all pass; T-P-01 shows as a todo for task 1.15 |
| P1.3-03 | T-U-12: every vendored vector file | passes through our functions |

**Think.** The starting code is not a frozen v1. It matches DESIGN 6 and nothing else is kept from earlier drafts. Keep `scripts/extract-appendix.ts` in the repo. If DESIGN Appendix A changes, rerun it and diff.

**Test in all directions.** Run the vectors against both our code and a second implementation where one exists: Node `crypto` for SHA-256, HKDF and Ed25519 (`crypto.verify` with Ed25519 keys).

**Think hard.** Wycheproof marks some Ed25519 cases "acceptable" or "invalid" for different reasons. Under strict verification, our result for each case must match Wycheproof's `result` field. List any case where it does not, and explain each one in the test file.

**Implement.** Copy, then move `test-int/` to `packages/xrpl/test-int/` (Phase 2 owns it). Add `vectors/` with a README that names each source and license.

**Done when** P1.3-01 to 03 pass.

### 1.4 Strict signature checks: `verifyXrplKeySig` (W3, first half)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L1 | Opus | high | S (3 h) | 1.3 |

**Research.**
- The noble-curves README: the `zip215` option, and secp256k1 `verify` options in v2 (`prehash`, `format`, `lowS`).
- rippled `STTx.cpp`: how a multisigned transaction's signer message is built, and the rule that `Signers` are sorted by AccountID.
- Strict Ed25519 vectors (section 4.6): ed25519-speccheck `cases.json` cases 0, 1, 9, 10 and 11 are accepted under ZIP-215 and rejected under strict RFC 8032; noble's `test/vectors/ed25519/zip215.json` has 196 such cases; Wycheproof `testvectors_v1/ed25519_test.json` runs with `zip215: false`.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| T-U-20a | A non-canonical Ed25519 signature that ZIP-215 accepts | `verifyXrplKeySig` returns false |
| T-U-20b | The same signature inside a multisigned blob | `verifyMultisigned` returns `ok: false` |
| P1.4-01 | A good Ed25519 signature, with and without the `ED` prefix in `pubHex` | the prefixed form passes; the bare 32-byte form is rejected (wrong length) |
| P1.4-02 | A good secp256k1 signature, DER, low S | passes |
| P1.4-03 | The same secp256k1 signature with high S | fails |
| P1.4-04 | A secp256k1 signature in compact (64-byte) form | fails |
| P1.4-05 | A key of an unknown type (first byte `04`, uncompressed) | fails with a typed error, never throws an untyped one |
| T-U-07, T-U-08 | the existing multisig tests | still pass |

**Think.** One function, three branches: Ed25519, secp256k1, anything else. It returns a boolean and never throws on bad input. Only programmer errors (a wrong argument type) throw.

**Test in all directions.**
- Property: for random keys and messages, sign then verify is true. Flipping any one bit of the message, the signature or the key gives false.
- Differential: verify each Ed25519 case with Node `crypto.verify` too. Where Node and noble strict disagree, the test prints the case. Node follows RFC 8032 strictly for some cases and not others, so record the differences; do not assume them.

**Think hard.** A signature check that throws on hostile input becomes a denial of service in the coordinator. Wrap only parsing in `try`; never wrap the verify result.

**Implement.**
```ts
export function verifyXrplKeySig(pubHex: string, msg: Uint8Array, sigHex: string): boolean {
  let pub: Uint8Array, sig: Uint8Array;
  try { pub = hexToBytes(pubHex); sig = hexToBytes(sigHex); } catch { return false; }
  if (pub.length !== 33) return false;
  if (pub[0] === 0xed) return sig.length === 64 && ed25519.verify(sig, msg, pub.subarray(1), { zip215: false });
  if (pub[0] === 0x02 || pub[0] === 0x03)
    return secp256k1.verify(sig, sha512(msg).subarray(0, 32), pub, { prehash: false, format: 'der', lowS: true });
  return false;
}
```
Then use it inside `verifyMultisigned`, which removes that function's own branch.

**Done when** the tests above pass and `verifyMultisigned` has no signature code of its own.

### 1.5 Signed-contract seal and mint memo (W1)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L1 | Opus | high | M (4 h) | 1.4 |

**Research.** DESIGN 6.12. The NFTokenMint URI limit (256 bytes) and the memo limit (1 KB). How xrpl.js returns `Memos` from a validated `tx` lookup (as hex `MemoType` and `MemoData`).

**Test first.**

| ID | Test | Expected |
|---|---|---|
| T-U-13a | `verifySignedContract` with the sealed keys, the memo and the URI from `buildSignedContractSeal` | passes |
| T-U-13b | Change any one byte of: root, wallet address, either key, either signature | fails, with a reason code for each |
| T-U-13c | Swap LA and LB (keys and signatures) | fails |
| T-U-13d | A memo with keys that are not the sealed lawyer keys | fails with `KEYS_NOT_SEALED` |
| T-U-13e | A client's x-key signs in place of a lawyer | fails with `KEYS_NOT_SEALED` |
| T-U-15a | `decodeMintMemo(encodeMintMemo(x))` equals `x` | passes |
| T-U-15b | Encoded memo length | exactly 195 bytes; total serialized `Memos` field under 1024 bytes |
| P1.5-01 | A memo whose version byte is not `0x01`, or whose length is not 195 | `decodeMintMemo` returns an error result |
| P1.5-02 | URI prefix is not `legx:sc:v1:`, or the hex has lower case | fails |
| P1.5-03 | Golden vector: fixed keys and root give a fixed seal, URI and memo | equals the committed hex |

**Think.** Return a result type, `{ ok: true } | { ok: false; code }`, not a boolean. The release gate needs the reason, and so does the dashboard.

**Test in all directions.**
- Property: for random roots, wallet addresses and lawyer keys, the full round trip passes, and each single-field mutation fails.
- Golden vector P1.5-03 is also checked by the Python reference in Phase 5 (task 5.3).

**Think hard.** The gate reads the memo from the validated mint transaction, not from our database. An attacker who changes our database cannot change the ledger, so the gate must never accept a memo passed in by the caller without the transaction hash.

**Implement.** About 60 lines. Reuse `tupleHash`, `verifyXrplKeySig` and the hex helpers.

**Done when** the tests above pass.

### 1.6 Deal seal and the Domain value (W2)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L1 | Sonnet | medium | S (3 h) | 1.3 |

**Research.** DESIGN 6.6 (the 29 fields, in order, and the `01` prefix), 6.2 (what `C_side` is for each method), 6.4 (`slotPolicy`) and 6.13 (`pqKeyHash`). The `payoutBytes` format in DESIGN Appendix A. `C_side` for the zero-knowledge method is salted (`tupleHash("legx/zk-identity/v1", [zkSalt32, utf8(N_side)])`); the seal takes the result as 32 bytes and never sees the salt.

**Test first.** T-U-14a has one test case per field of DESIGN 6.6, so 29 cases.

| ID | Test | Expected |
|---|---|---|
| T-U-14a | Change any one of the 29 fields (contract root, signed-contract seal, wallet, `xPubA`, `xPubB`, `C_A`, `C_B`, `idMethodA`, `idMethodB`, `identityPolicy`, `lawyerPubA`, `lawyerPubB`, `LC_A`, `LC_B`, `lawyerOpsA`, `lawyerOpsB`, `releaserAccount`, four slot policies, four `pqKeyHash` values, `signerAccounts`, `quorum`, `payoutA`, `payoutB`) | the seal changes (29 cases, named by field) |
| T-U-14b | Shuffle `signerAccounts` | the seal is the same |
| T-U-14c | `releaserAccount !== lawyerOpsB` | throws |
| T-U-06 | Swap A and B, change the quorum, change a payout address or a payout tag | the seal changes each time; the same inputs give the same seal |
| P1.6-01 | `domain(root, seal)` | 65 bytes, first byte `0x01`, then the root, then the seal |
| P1.6-02 | Golden vector for a fixed input | equals the committed hex (the same value as the starting code's new T-U-06 vector) |
| P1.6-03 | `idMethod` other than `"zkpassport"` or `"nfc-chip"`; `identityPolicy` other than `"zk"`, `"zk-or-chip"` or `"chip"` | throws |
| P1.6-04 | `idMethod_side` that the `identityPolicy` does not allow (for example `"nfc-chip"` under `"zk"`) | throws |
| P1.6-05 | A slot policy or `pqKeyHash` that is not 32 bytes | throws |
| P1.6-07 | Two seals built from the same inputs except that `C_A` uses another `zkSalt32` | the seals differ (the salt changes `C_side`, and the seal commits to `C_side`) |
| P1.6-06 | A payout tag with a leading zero, a negative sign, or above 4294967295 | throws; `rAddr:0` and `rAddr:4294967295` pass |

**Think.** Keep the field order exactly as DESIGN 6.6. Put the order in one array of getters, so the code reads like the spec. There is one seal, one tag (`legx/dealseal/v1`) and one `Domain` form. Nothing here knows about versions.

**Test in all directions.** Property: a random permutation of two different fields (for example, swap `lawyerOpsA` and `lawyerOpsB`, or `slotPolicyA` and `slotPolicyB`) changes the seal. Property: the seal depends on nothing except its 29 inputs (run it in a fresh process with another locale and time zone).

**Think hard.** The payout string format is `rAddr` or `rAddr:tag`. The review found that tags are not validated. Validate here: a tag is an integer from 0 to 4294967295, written in base 10 without leading zeros. Also think about the new fields. `slotPolicy` and `pqKeyHash` are computed in tasks 1.15 and 1.16; this task takes them as 32-byte inputs, so there is no cross-dependency. The seal must still change when only a slot policy changes, because the arbitrator relies on it to know which shares could sign.

**Implement.** Replace the seal function in `dealcore.ts` so that it takes the 29 fields, and add `domain(root, seal)`, about 40 lines. The field list is one array, in DESIGN order, so a reviewer can compare it line by line.

**Done when** the tests above pass.

### 1.7 Operations-account binding (W3, second half)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L1 | Sonnet | medium | S (3 h) | 1.4 |

**Research.** DESIGN 6.14. Which keys may sign for an XRPL account: the master key unless `lsfDisableMaster` is set, or the `RegularKey` ([cryptographic keys](https://xrpl.org/docs/concepts/accounts/cryptographic-keys)).

**Test first.**

| ID | Test | Expected |
|---|---|---|
| T-U-19a | Ed25519 operations account: both signatures verify; the account's master key is on | passes |
| T-U-19b | secp256k1 operations account | passes |
| T-U-19c | The operations key is the account's `RegularKey`, and the master key is off | passes |
| T-U-19d | A swapped operations account in the message | fails |
| T-U-19e | A key that is neither the master key (master on) nor the `RegularKey` | fails |
| P1.7-01 | The master key signs, but `lsfDisableMaster` is set | fails |
| P1.7-02 | The lawyer signature is missing or by another lawyer's key | fails |

**Think.** The function takes the validated `account_info` result as input. It does no network read itself. Phase 2 provides the read.

**Test in all directions.** Property: random account types (Ed25519, secp256k1, regular key) all pass; any single swapped field fails. Differential: sign with an xrpl.js `Wallet` and verify with our function.

**Think hard.** A firm may rotate its `RegularKey` after binding. The gate checks the binding against the validated ledger at release time, so a rotated key makes `OPS_BINDINGS_OK` fail. That is correct: the firm must bind again.

**Implement.** `opsBindMsg` and `verifyOpsBinding(accountInfo, binding)`, about 40 lines.

**Done when** the tests above pass.

### 1.8 Test PKI and fixture passports (`@legx/fixtures`)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L2 | Opus | xhigh | L (8 h) | 1.2 |

This is the hardest part of Phase 1. It must make passports that pass real ICAO checks, without a real passport.

**Research.**
- ICAO 9303 Part 10 (the LDS: DG1 tag `61` with `5F1F` holding the MRZ, the EF.SOD layout), Part 11 (passive authentication, Active Authentication) and Part 12 (CSCA and Document Signer certificate profiles).
- The libraries in section 4.6. No `@peculiar/asn1-*` schema exists for `LDSSecurityObject` (checked 24 Oct 2026), so write one (about 35 lines) with `@peculiar/asn1-schema` decorators; `@li0ard/tsemrtd` (MIT) has one to compare with. Build certificates with `@peculiar/x509`, build the SignedData with `@peculiar/asn1-cms`, and verify with PKI.js pinned at 3.4.3 with asn1js 3.1.0. PKI.js 4.0.0 needs asn1js 4, which the `@peculiar` packages do not use yet; pass raw bytes between the two libraries, never parsed objects.
- ICAO 9303 Part 10: `LDSSecurityObject.dataGroupHashValues` must hold **2 to 16** entries. A fixture with only DG1 is not valid; hash DG1 and DG15.
- DG1 for a TD3 passport is `61 5B 5F1F 58` followed by the 88 MRZ bytes. Use the ICAO sample country code `XXA` (the `mrz` package rejects `UTO`).
- An independent checker for the differential test: `openssl cms -verify` on the SOD, and a maintained eMRTD parser if one exists (section 4.6).

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P1.8-01 | `makeTestPki({ seed })` | a CSCA (self-signed, `keyCertSign`) and a Document Signer certificate signed by it; the same seed gives the same bytes |
| P1.8-02 | `makePassport({ pki, mrz, seed })` | DG1, EF.SOD and DG15 (an Active Authentication key) |
| P1.8-03 | The SOD's `LDSSecurityObject` holds the SHA-256 of DG1 and DG15 (at least 2 entries, as ICAO Part 10 requires) | the hashes match; a fixture with 1 entry is refused by our parser |
| P1.8-04 | `openssl cms -verify -CAfile csca.pem` on the SOD (when `openssl` is on the PATH; skipped otherwise) | verifies |
| P1.8-05 | Each bad variant (wrong signature, wrong CSCA, changed DG1, expired document) | differs from the good fixture in exactly that one way |
| P1.8-06 | MRZ check digits in the fixture MRZ | valid (checked by the `mrz` package or our own check-digit function) |
| P1.8-07 | `chipAnswerAA(dg15Key, challenge8)` | a signature that verifies with the DG15 public key |
| P1.8-08 | Every fixture shows `DEMO / TEST ONLY` in the name fields | true |
| P1.8-09 | A second set of fixtures signed with RSA-PSS (CSCA and Document Signer), and an RSA Active Authentication key | verifies like the P-256 set |
| P1.8-10 | Cross-check: `@li0ard/tsemrtd` parses our DG1 and SOD | same fields |

**Think.**
- Use ECDSA P-256 for the main CSCA and Document Signer set, and RSA-PSS for a second set. Both are common in real passports. Real passports also use brainpool curves, which WebCrypto does not support; task 1.9 handles that.
- Make the fixtures deterministic from a seed, so tests and the demo produce the same passports every run. The private keys never leave `@legx/fixtures`.
- Put 4 named demo passports in `packages/fixtures/demo/` (Alice, Bob, plus 2 bad ones for attack mode).

**Test in all directions.**
- Differential with OpenSSL (P1.8-04).
- Property: for random MRZ data, building then parsing a passport round-trips.
- Negative: truncate the SOD at every byte position; the parser must return an error, never throw out of the module.

**Think hard.** A fixture that passes our own verifier but fails a real one is worse than no fixture. That is why P1.8-04 exists. If OpenSSL rejects our SOD, fix the fixture, not the test.

**Implement.** `makeTestPki`, `makePassport`, `chipAnswerAA`, the bad-variant factory (about 12 variants) and the `LDSSecurityObject` schema. Every key, serial number and date comes from a deterministic stream seeded by the test (HKDF over the seed), so fixtures are the same on every machine.

**Done when** P1.8-01 to 08 pass, including P1.8-04 on CI (install OpenSSL in the job).

### 1.9 Passport attestation and passive authentication (W4a)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L2 | Opus | xhigh | L (8 h) | 1.2, 1.4, 1.6, 1.8 (zero-knowledge path: task 1.17 builds on this one; 1.15 is not needed, because the presence signature is a plain strict Ed25519 check) |

**Research.** DESIGN 6.15 and 6.10. `research/r6-zkpassport.md` (ZKPassport and Self prove passive authentication only, so the chip checks below stay the only route to Active or Chip Authentication). ICAO 9303 Part 11 section 5.1 (passive authentication steps) and section 6.1 (Active Authentication with an 8-byte nonce; our challenge is the first 8 bytes of `presenceMsg`, and whether each native reader library lets us pass our own nonce is a [CHECK] for task 4.6). DESIGN 6.15 for the rules that changed in the audit: `presenceMsg` now holds `lawyerNonce` (32 random bytes chosen by the client's own lawyer, single use), freshness is 1 hour by default (at most 24 hours), and `face_match_passed` is required (default on, O12). Facts checked on 24 Oct 2026 (section 4.6):
- noble v2 rejects high-S ECDSA signatures on every curve by default. Passport chips and Document Signers do not normalize S, so pass `lowS: false` for every passport, CSCA, Document Signer and timestamp signature. (Only XRPL secp256k1 signatures use `lowS: true`.)
- WebCrypto, and so PKI.js, has no brainpool curves. Verify brainpool signatures with noble's brainpool curves (`@noble/curves/misc.js`) as a fallback.
- Active Authentication on EC chips returns a plain `r||s` signature (BSI TR-03111), with the hash named in DG14 `ActiveAuthenticationInfo`. On RSA chips it is ISO/IEC 9796-2 scheme 1 with partial message recovery (trailer `BC` for SHA-1, `34CC` for SHA-256). No JavaScript library does the RSA scheme, so write it (about 100 lines with `BigInt`), and test it with the BSI TR-03105-5 sample data, which includes an RSA Active Authentication key.

**Test first.** T-U-16 split into one test per reason:

| ID | Case | Expected reason code |
|---|---|---|
| T-U-16a | the good fixture | pass |
| T-U-16b | wrong CSCA | `DS_NOT_CHAINED` |
| T-U-16c | bad SOD signature | `SOD_SIGNATURE_INVALID` |
| T-U-16d | changed DG1 | `DG1_HASH_MISMATCH` |
| T-U-16e | expired document (by ledger `close_time`, not the clock) | `DOCUMENT_EXPIRED` |
| T-U-16f | commitment does not open | `COMMITMENT_MISMATCH` |
| T-U-16g | signed by the other side's lawyer | `WRONG_SIGNER` |
| T-U-16h | presence signature missing | `PRESENCE_MISSING` |
| T-U-16i | presence signature by a different key | `PRESENCE_INVALID` |
| T-U-16j | attestation from another deal (`deal_id`, `contract_root` or `deal_seal` differs) | `WRONG_DEAL` |
| T-U-16k | ledger anchor 1 h + 1 s older than the current validated `close_time` (the default limit) | `STALE` |
| T-U-16l | ledger anchor hash does not match the ledger at that index | `ANCHOR_MISMATCH` |
| T-U-16m | chip has DG15, but `chip_authentication` is `"none"` | `CHIP_AUTH_REQUIRED` |
| T-U-16n | Active Authentication signature over a different challenge | `CHIP_AUTH_INVALID` |
| P1.9-01 | wrong `payloadType` on the envelope | `WRONG_PAYLOAD_TYPE` |
| P1.9-02 | a check field is `false` | `CHECK_FALSE:<name>` |
| P1.9-03 | `passiveAuth` with a high-S ECDSA SOD signature (valid under ICAO) | passes (`lowS: false`) |
| P1.9-04 | `passiveAuth` with a brainpoolP256r1 Document Signer | passes through the noble fallback |
| P1.9-05 | RSA Active Authentication with the BSI TR-03105-5 sample key | passes; one changed byte fails |
| P1.9-06 | ECDSA Active Authentication, plain `r||s`, hash from DG14 | passes |
| P1.9-07 | `method` is neither `"zkpassport"` nor `"nfc-chip"` | `METHOD_UNKNOWN` |
| P1.9-08 | `method` is not allowed by the sealed `identityPolicy` (`"nfc-chip"` under `"zk"`, `"zkpassport"` under `"chip"`) | `METHOD_NOT_ALLOWED` |
| P1.9-09 | `method` differs from the sealed `idMethod_side` | `METHOD_MISMATCH` |
| P1.9-10 | An `nfc-chip` attestation whose `checks` object has the `zkpassport` shape (or the reverse) | `CHECKS_SHAPE_WRONG` |
| P1.9-11 | The chip-only rules (`CHIP_AUTH_REQUIRED`, `CHIP_AUTH_INVALID`, the SOD checks) are not applied to a `zkpassport` attestation | a good `zkpassport` attestation passes without any chip field |
| P1.9-12 | The `presence_sig` check under the sealed client slot key (strict, a FROST signature is a plain Ed25519 signature) | passes for both methods; a signature by a lawyer key fails `PRESENCE_INVALID` |
| P1.9-13 | Freshness limit: an anchor exactly 1 h older than the current validated `close_time` passes; 1 h + 1 s fails `STALE`. A configured limit of 24 h is accepted; a configured limit above 24 h is refused when the config is built | `STALE`, and `FRESHNESS_LIMIT_TOO_HIGH` |
| P1.9-14 | `presenceMsg = tupleHash("legx/passport-presence/v1", [dealSeal, utf8(side), ledger_hash, lawyerNonce])` against a golden vector; a `lawyerNonce` that is not 32 bytes; a `presence_sig` made over a `presenceMsg` built with another nonce | equal to the golden hex; `NONCE_LENGTH`; `PRESENCE_INVALID` |
| P1.9-15 | Single-use nonce: `checkFreshNonce(nonce, usedNonces)` with a nonce that is already in the set (a second attestation by the same lawyer with the same nonce) | `NONCE_REUSED`; a new nonce passes. The lawyer console and the evidence service keep the set (tasks 3.4 and 4.4); core only supplies the pure check |
| P1.9-16 | Active Authentication challenge: `aaChallenge(presenceMsg)` is exactly the first 8 bytes of `presenceMsg`; an AA signature over any other 8 bytes; a challenge of 7 or 9 bytes | the first 8 bytes (golden); `CHIP_AUTH_INVALID`; refused at input |
| P1.9-17 | `face_match_passed` on a `zkpassport` attestation: `false`, or absent (the check is on by default) | `CHECK_FALSE:face_match_passed` in both cases |
| P1.9-18 | Onboarding attestation (the record the client's own lawyer signs at P5, `identity.onboarded` for the zero-knowledge method): wrong signer (the other side's lawyer), a deal field that differs, `method` that differs from the sealed `idMethod_side` | `WRONG_SIGNER`, `WRONG_DEAL`, `METHOD_MISMATCH`; the zero-knowledge specifics are tested in task 1.17 |

The zero-knowledge checks (`proof_verified`, `identifier_matches`, `bound_value_is_presence_msg`, `document_not_expired` and `proof_sha256`) are tested in task 1.17 (T-U-28), which uses recorded verification results. This task owns the dispatch by `method` and the chip path.

**Think.** The attestation is a union on `method` (DESIGN 6.15). The shared rules (signer, presence, deal, freshness, method allowed and equal to the sealed one) run first, then the rule set for that method. Split the work into two pure functions:
1. `passiveAuth({ dg1, sod, trustList, atTime }) -> Result`. This runs inside the lawyer's console when the chip is read.
2. `verifyAttestation({ envelope, deal, sealedKeys, ledgerLookup, now }) -> Result`. This runs in the release gate and in the arbitrator's verifier. It cannot repeat passive authentication, because it never sees the passport. It checks the signer, the presence signature, the deal binding, freshness and the check flags.

The chip attestation proves that the client's own lawyer ran `passiveAuth` and the client's device was present. The zero-knowledge attestation proves that the lawyer verified the client's proof locally (task 1.17); it does not prove that a chip was present (DESIGN 10.1). The gate trusts the lawyer's signature for the checking part; that is the design (D21). Contracts that need chip presence seal `identityPolicy: "chip"`.

**Test in all directions.**
- Property: for random valid inputs, `verifyAttestation` passes, and any single mutation fails with exactly one reason code.
- Boundary: freshness at exactly 1 h passes; at 1 h + 1 s it fails (and the same pair at a configured 24 h limit).
- Replay: an attestation from deal X, presented in deal Y with the same people, fails.

**Think hard.**
- Never parse the passport inside `verifyAttestation`. That keeps raw passport data out of the platform (I7).
- The time for `document_not_expired` is the validated ledger `close_time` at check time, passed in. Never `Date.now()`.
- `lawyerNonce` is what stops a replayed presence signature inside the 1-hour window. The attestation carries it as `lawyer_nonce` (DESIGN 6.15), so a verifier can rebuild `presenceMsg` from the attestation alone. The single-use check stays with the lawyer console and the evidence service.
- Both identity methods have one onboarding record: the method-tagged `identity.onboarded` attestation (DESIGN 8.1, 6.17 `ONBOARDING_OK`). For `nfc-chip` it holds the lawyer's passive-authentication result at P5 and the opened commitment.
- The AA challenge must come from `presenceMsg` and from nothing the chip reader chooses, or a relayed chip could answer for another session.

**Implement.** `src/passport/passiveAuth.ts` (the only module that parses an SOD), `src/passport/activeAuth.ts`, and `src/attest.ts` (shared rules, then one function per method; the `zkpassport` function is filled in by task 1.17). Keep passport parsing out of `attest.ts`, so the release gate never imports a passport parser.

**Done when** T-U-16a to n and P1.9-01 to 18 pass.

### 1.10 Bar records (W4b, pure part)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L2 | Sonnet | medium | M (4 h) | 1.2, 1.6 |

**Research.** DESIGN 6.16 and the ISO 3166-2 code format.

**Test first.**

| ID | Case | Expected |
|---|---|---|
| T-U-17a | a good `BarVerification` and `BarDealLink` | pass |
| T-U-17b | signed by a key that is not the verifier key | `WRONG_SIGNER` |
| T-U-17c | wrong bar commitment | `COMMITMENT_MISMATCH` |
| T-U-17d | wrong operations account | `OPS_MISMATCH` |
| T-U-17e | wrong lawyer key | `LAWYER_KEY_MISMATCH` |
| T-U-17f | a link for another deal | `WRONG_DEAL` |
| T-U-17g | status is not `active` | `NOT_ACTIVE` |
| T-U-17h | verification older than 30 days by ledger time (boundary: exactly 30 days passes) | `STALE` |
| P1.10-01 | `verification_sha256` does not match the named envelope | `VERIFICATION_HASH_MISMATCH` |
| P1.10-02 | `openBarCommitment(salt, jurisdiction, barNumber)` equals `LC` from 6.2 | passes; a jurisdiction that contains `:` is refused at input |

**Think.** Three functions: `verifyBarVerification`, `verifyBarDealLink` and `openBarCommitment`. The age check uses ledger close times passed in.

**Test in all directions.** Property: every single-field mutation fails with exactly one code. Boundary: exactly 30 days passes, 30 days plus 1 second fails.

**Think hard.** The review found that `jurisdiction + ":" + barNumber` is ambiguous if the jurisdiction contains `:`. Validate the jurisdiction as an ISO 3166 code with an optional subdivision (`US-CA`), which never contains `:`. This keeps the hash recipe unchanged.

**Implement.** `src/bar.ts`, about 80 lines.

**Done when** the tests above pass.

### 1.11 Lock checker (seal rules) (W6)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L1 | Opus | high | M (4 h) | 1.6 |

**Research.** DESIGN 6.9 and 6.6. The current list of ledger entry types in rippled's `ledger_entries.macro`, so the allow-list tests cover every type.

**Test first.**

| ID | Case | Expected |
|---|---|---|
| P1.11-01 | all checker tests from the starting code (DESIGN Appendix A), with their `Domain` values updated to the `01` form | pass |
| T-A-01 | Setup key left on (`lsfDisableMaster` clear) | `MASTER_DISABLED` fails |
| T-A-02 | Regular key planted | `NO_REGULARKEY` fails |
| T-A-03 | Delegate entry planted | `UNEXPECTED_OWNED_DELEGATE` fails |
| T-A-04 | Ticket left on the wallet | `TICKET_ALLOWED` fails |
| T-A-05 | One signer swapped | `SIGNERS_MATCH_KEYS` fails |
| T-A-06 | Quorum lowered to 2 | `QUORUM_MATCH` fails |
| T-A-08 | Escrow condition differs | `ESCROW_AMOUNT_AND_CONDITION` fails |
| T-A-09 | Escrow amount short | `ESCROW_AMOUNT_AND_CONDITION` fails |
| T-A-10 | `CancelAfter` too soon | `CANCEL_AFTER_MARGIN` fails |
| T-A-16 | `Domain` seal changed by one byte | `DOMAIN_IS_SEAL` fails |
| T-A-19 | NFT buy offer owned by the wallet | `UNEXPECTED_OWNED_NFTOKENOFFER` fails |
| T-A-20 | Alice pre-approved as a depositor | `PREAUTH_ONLY_RELEASER` fails |
| T-A-21 | Authorized NFT minter set | `NO_NFTOKENMINTER` fails |
| T-A-22 | A stranger's escrow to the wallet | a warning only; the release is not blocked |
| T-A-23 | Incoming checks still allowed | `DISALLOW_CHECK` fails |
| T-A-24 | `OwnerCount` higher than the objects seen (a hidden object) | `OWNER_COUNT_MATCHES` fails |
| T-A-25 | Credential not accepted | `CREDENTIAL_ACCEPTED` fails |
| P1.11-02 | a good wallet | no blocking findings |
| P1.11-03 | `Domain` does not start with `01`, or is not `01 \|\| contractRoot \|\| dealSeal` | `DOMAIN_IS_SEAL` fails |
| P1.11-04 | `Domain` is 64 or 66 bytes | `DOMAIN_IS_SEAL` fails |
| P1.11-05 | `releaserAccount !== lawyerOpsB` | `RELEASER_IS_OPS_B` fails (always checked) |
| T-A-28a | DepositPreauth for an account that is not the sealed releaser | `PREAUTH_ONLY_RELEASER` fails |
| P1.11-06 | Property: any random extra object type owned by the wallet | some blocking finding (fail closed) |
| P1.11-07 | Property: shuffle the order of `objects` | the same findings |

**Think.** There is one `DOMAIN_IS_SEAL` rule and the `RELEASER_IS_OPS_B` rule. The checker has no version switch. Change nothing else. Keep the code a flat list of rules, like the table in the spec.

**Test in all directions.** Properties P1.11-06 and 07. A table test over every ledger entry type in rippled's macro list: each one, when owned by the wallet, blocks unless it is on the allow-list.

**Think hard.** Two known design gaps from the review, recorded in IMPLEMENTATION Appendix B (DQ-1 and DQ-2): the checker fails after funding because the escrow is gone, and the credential check passes when no credential exists. Do not change behavior silently. Implement exactly DESIGN 6.9, and add the two tests marked `it.todo` with the DQ number, so they show in every run until the design decides.

**Implement.** About 25 changed lines in `lockcheck.ts`: the `DOMAIN_IS_SEAL` rule and `RELEASER_IS_OPS_B`.

**Done when** the tests above pass, and every ID from T-A-01 to T-A-25 that the checker owns (all except T-A-07, T-A-11 to T-A-15, T-A-17, T-A-18 and T-A-26, which need a real ledger) appears by name in this task's test file.

### 1.12 Release gate (W5)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L1 | Opus | xhigh | L (8 h) | 1.5, 1.7, 1.9, 1.10, 1.11, 1.15, 1.16, 1.17 (the new gate codes call `slotPolicy`, the post-quantum binding check and the zero-knowledge trust rules) |

**Research.** DESIGN 6.17 (the 15 codes), 6.10 (the trust record and the production refusals), 6.13 (the 2-of-3 post-quantum binding), 6.4 (key generation records), D22 and D23. The NFTokenID byte layout (flags, transfer fee, issuer, taxon, sequence), so the issuer is decoded locally (section 4.5).

**Test first.**

| ID | Case | Expected |
|---|---|---|
| T-U-18a | every input good | no blocking findings |
| T-U-18b | each of the 15 codes in DESIGN 6.17 (`LOCK_OK`, `CONTRACT_SEAL_OK`, `PASSPORT_A_OK`, `PASSPORT_B_OK`, `BAR_A_OK`, `BAR_B_OK`, `ATTORNEY_CREDENTIAL_A_OK`, `ATTORNEY_CREDENTIAL_B_OK`, `RELEASER_SEALED`, `OPS_BINDINGS_OK`, `ONBOARDING_OK`, `IDS_DISTINCT`, `IDENTITY_POLICY_OK`, `PQ_BINDINGS_OK`, `SLOT_SETUP_OK`): break only its input | exactly that code fails (plus `LOCK_OK` when the input is a lock input). A test compares the code list with the DESIGN 6.17 table, in its order |
| T-P-07 | Property: random valid inputs, then a random subset of components broken | the gate passes if and only if the broken subset is empty |
| T-A-27 | one passport attestation missing, stale, or without the presence signature | the gate refuses |
| T-A-28b | `submitter !== releaserAccount` | `RELEASER_SEALED` fails |
| T-A-29 | the `LEGX_ATTORNEY` credential is missing, not accepted, expired, or from the wrong issuer | `ATTORNEY_CREDENTIAL_*` fails |
| T-A-30 | NFT URI or memo mismatch, or the NFT issuer is not `lawyerOpsA` | `CONTRACT_SEAL_OK` fails |
| P1.12-01 | `buildGatePassedRecord` lists the ledger index and hash, and the SHA-256 of every input record (attestations, onboarding attestations, bar records, post-quantum bindings, `frost.dkg.completed` events); it is a hybrid envelope and also carries a FROST signature by lawyer slot B over the record hash | the list equals the inputs; either signature missing fails |
| P1.12-02 | `gateMemo(leafHash)` | `MemoType` and `MemoData` exactly as DESIGN D22 |
| P1.12-03 | the gate is run twice on the same input | the same findings in the same order (deterministic) |
| P1.12-04 | the gate with a `zkpassport` attestation for one side and an `nfc-chip` attestation for the other (policy `"zk-or-chip"`) | no blocking findings; the same pair under policy `"zk"` fails `PASSPORT_B_OK` |
| P1.12-05 | `ONBOARDING_OK`: the onboarding attestation is missing; signed by the other side's lawyer; its method differs from the sealed `idMethod_side`; (zero-knowledge) the identifier and the salt do not give the sealed `C_side`; its trust record fails the production rules | only `ONBOARDING_OK` fails, each time |
| P1.12-06 | `IDS_DISTINCT`: `C_A` equals `C_B`; (zero-knowledge) the two identifiers are equal even though the salts differ | only `IDS_DISTINCT` fails; the same pair with different people passes |
| P1.12-07 | `IDENTITY_POLICY_OK`: policy `"chip"` with a zero-knowledge release attestation; policy `"zk"` with a chip attestation; a release method that differs from the onboarding method | only `IDENTITY_POLICY_OK` fails (`PASSPORT_x_OK` also fails with `METHOD_NOT_ALLOWED` where the attestation rules say so) |
| P1.12-08 | A release attestation whose method is allowed by the policy `"zk-or-chip"` but differs from the sealed `idMethod_side` | `PASSPORT_x_OK` fails with `METHOD_MISMATCH` |
| P1.12-09 | `PQ_BINDINGS_OK`: only one holder signature; the same holder signing twice; the cross-signature missing; a `pqKeyHash` that differs from the seal; an ML-DSA signature from a key of another slot | only `PQ_BINDINGS_OK` fails, each time; any two distinct holders plus the cross-signature pass |
| P1.12-10 | `SLOT_SETUP_OK`: a holder missing from the transcript signatures; one of the three test signatures invalid under the slot key; only two pairs test-signed; roles that give a `slotPolicy` other than the sealed one | only `SLOT_SETUP_OK` fails, each time |
| P1.12-11 | `face_match_passed` is `false` or absent in a `zkpassport` release attestation (the check is on by default) | `PASSPORT_x_OK` fails with `CHECK_FALSE:face_match_passed` |
| P1.12-12 | Production profile: a trust record with chain ID 11155111 (Sepolia), a mock identifier type, or `dev_mode: true`, in an onboarding or a release attestation | `ONBOARDING_OK` or `PASSPORT_x_OK` fails, each time; the same records pass under the demo profile |

**Think.** The input is one plain object: `{ ledger: { index, hash, closeTime, account, objects, mintTx, nftIssuer, credentials, opsAccounts }, records: {...}, deal: PublicDealData, submitter }`. Phase 2 builds the ledger part from one validated ledger. The gate itself never reads the network. That makes it easy for an arbitrator to rerun.

**Test in all directions.** T-P-07 (property). P1.12-03 (determinism). When task 2.5 has recorded real-ledger snapshots, a gate input built from them gives the same result as the synthetic input.

**Think hard.** The NFT issuer comes from decoding the NFTokenID locally (its issuer field). Do not trust an issuer field from our database. A mock or Sepolia proof accepted in production is the worst failure of the new codes, so P1.12-12 runs in both profiles and the production default is the strict one. The gate needs the recorded trust record, not a live check, so an arbitrator gets the same answer offline (task 1.17, T-U-32).

**Implement.** `checkRelease`, `buildGatePassedRecord` and `gateMemo`. One small pure function per code, in the order of the DESIGN table. About 250 lines. The shape keeps the code as readable as the spec:
The gate input also carries `profile: 'production' | 'demo'`, so the production refusals are an input and not a global.
```ts
type Rule = { code: Code; check: (i: ReleaseInput) => Result };
const RULES: readonly Rule[] = [
  { code: 'LOCK_OK',          check: i => noBlocking(checkLock(i.ledger.account, i.ledger.objects, lockExpected(i.deal))) },
  { code: 'CONTRACT_SEAL_OK', check: i => contractSealOk(i) },
  { code: 'PASSPORT_A_OK',    check: i => verifyAttestation(passportArgs(i, 'A')) },
  { code: 'PASSPORT_B_OK',    check: i => verifyAttestation(passportArgs(i, 'B')) },
  // ... BAR_A_OK, BAR_B_OK, ATTORNEY_CREDENTIAL_A_OK, ATTORNEY_CREDENTIAL_B_OK, RELEASER_SEALED, OPS_BINDINGS_OK,
  // ONBOARDING_OK, IDS_DISTINCT, IDENTITY_POLICY_OK, PQ_BINDINGS_OK, SLOT_SETUP_OK  (the full DESIGN 6.17 list, 15 codes by the audit's count)
];
export const checkRelease = (i: ReleaseInput): Finding[] =>
  RULES.map(({ code, check }) => { const r = check(i); return { code, level: 'block', ok: r.ok, detail: r.ok ? undefined : r.code }; });
```

**Done when** the tests above pass and mutation testing (task 5.4) later scores at least 85 on `releaseGate.ts`.

### 1.13 Evidence primitives

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L3 | Sonnet | medium | M (4 h) | 1.2, 1.3 |

**Research.** DSSE v1.0.2 PAE; the C2SP signed-note and tlog-checkpoint formats; RFC 9162 consistency proofs.

**Test first.**

| ID | Case | Expected |
|---|---|---|
| T-U-10, T-U-11 | the existing chain and PAE tests | pass |
| P1.13-01 | `signAttestation` and `verifyAttestationEnvelope` with the attest `payloadType` | pass; an event-type envelope fails here, and an attest-type envelope fails `verifyEnvelope` |
| P1.13-02 | Checkpoint as a C2SP signed note (origin, size, root) | signs and verifies; one changed byte fails |
| P1.13-03 | Inclusion and consistency proofs for sizes 1 to 64 | all verify; a wrong index fails |
| P1.13-04 | `verifyClientRecords(records, keys)` | reports each record's signature, chain position and ledger link |
| P1.13-05 | A gap in `seq` with recomputed hashes | fails (the existing T-U-10 drop case, extended to the attest type) |

**Think.** Both payload types share one envelope code path, with the type as a parameter.

**Test in all directions.** Cross-check PAE with `@sigstore/core` `preAuthEncoding`, checkpoints with `@cloudflare/signed-note-wasm`, and Merkle proofs with the transparency-dev test data.

**Think hard.** Never re-serialize an envelope. Compute leaf hashes over stored bytes only. A test stores, reloads and hashes an envelope.

**Implement.** Extend `evidence.ts`, and add `checkpoint.ts` (about 100 lines).

**Done when** the tests above pass.

### 1.14 State machine (release-gate guard)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L3 | Sonnet | medium | S (2 h) | 1.2 |

**Research.** DESIGN 5.1 (invariant I8) and DESIGN Appendix C.

**Test first.**

| ID | Case | Expected |
|---|---|---|
| T-P-04 | existing property: I1, I2, I6 | pass |
| P1.14-01 | `RELEASE_ESCROW` without `gatePassed: true` | throws |
| P1.14-02 | Property, new invariant I8: `FUNDED` is reached only by an event that carries `gatePassed: true` | holds for any event sequence |
| P1.14-03 | `AWARD` from `DISPUTED` to Bob or to Alice | `PAID_OUT` or `REFUNDED` |

**Think.** `RELEASE_ESCROW` gains a field `gatePassed: boolean`.

**Test in all directions.** An exhaustive table test over every state and every event: the result is either the expected next state or an `illegal` error.

**Think hard.** The Quint model (task 5.1) replays traces through this function, so it must stay pure and total.

**Implement.** About 10 changed lines in `machine.ts`.

**Done when** the tests above pass.

### 1.15 FROST slot keys: DKG, signing, aggregation, refresh (core)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L13 | Opus | xhigh | L (2 days) | 1.2, 1.4, 1.6 |

Every signer slot is a FROST 2-of-3 group key (DESIGN 6.4). The client's share 2 sits on a separate authenticator (a FIDO2 security key with PRF, or a second device); a same-phone passkey is only a labeled "single-device mode". This task writes `packages/core/src/frost.ts`: a thin, strict layer over noble, plus the parts noble lacks. It replaces the old `dealSecret`, HKDF key derivation and deal stamps.

**Research.**
- `research/r7-frost.md`. Facts to use: `@noble/curves` 2.4.0 exports `ed25519_FROST` (trusted dealer, 3-round DKG with proofs of knowledge, `commit`, `signShare`, `aggregate`, `verifyShare`). It has no refresh and no repair. noble's FROST is not independently audited. In a recorded run, 60 of 60 signatures from 2-of-3 groups passed strict `zip215: false` verification, and a second `signShare` with the same nonces threw "signing nonces already used".
- RFC 9591: section 7.3 (sign only what you checked; never reuse a nonce), Appendix E.1 (Ed25519, SHA-512 vectors).
- ZF `frost-core` 3.0.0 `keys/refresh.rs` (the reference for refresh: a dealing of zero added to each share; it cannot change the threshold; the caller must authenticate senders) and its vector files: `frost-ed25519/tests/helpers/vectors.json`, `vectors_dkg.json`, `vectors-big-identifier.json` and `repair-share.json`. NCC audited ZF v0.6.0 for dealer, DKG and signing. Refresh and repair were added after that audit, so they are not in its scope.
- DESIGN 6.3 (enrollment keys pinned out of band, the append-only `enrollment_key` table), 6.4 (key generation rules, signing rules, recovery rules, refresh, repair and rotation, `slotPolicy`), 6.8 (strict check) and 6.13 (X-Wing for DKG round 2).
- Prototype facts from 24 Oct 2026 (scripts in `scratchpad/proto-frost/`):
  - rippled 3.4.1 standalone validated a 4-slot multisigned Payment in which every signature was a 2-of-3 FROST signature (`tesSUCCESS`).
  - The noble API is `DKG.round1(id, {min: 2, max: 3})`, `DKG.round2`, `DKG.round3` (returns `{public, secret}`), `commit`, `signShare`, `verifyShare` and `aggregate`. The group key is `public.commitments[0]`.
  - Timings: DKG about 88 ms per slot, signing about 25 ms.
  - A hand-written refresh worked, but the prototype did NOT check the sub-shares against the Feldman commitments. That check is new work here and must be tested.
  - XRPL signers must be sorted by decoded AccountID (the ledger layer, task 2.4, sorts them; this task only produces the signatures).
  - `xrpl` 5.3.0 plus noble static imports hit `ERR_REQUIRE_CYCLE_MODULE` on Node 22.14. Test the import on Node 24, and use a dynamic `import('xrpl')` if needed.
- Check the exact noble `d.ts` for the DKG and signing calls before writing the wrapper. The sketches below show the shape, not the final names.

**Test first.** DESIGN tests T-U-21, T-U-22, T-U-23, T-U-29, T-U-30, T-U-31 (its core parts) and T-P-01 come first, then ours. The service and ledger parts of T-U-31 (the firm HSM service, the recovery agent, the coordinator relay, the notices) are built and tested in Phase 3 (tasks 3.9 and 3.10); the browser flows are in task 4.7. This task owns the pure rules they all call.

| ID | Test | Expected |
|---|---|---|
| T-U-21a | RFC 9591 Appendix E.1 vectors through our wrapper (key shares, commitments, signature shares, final signature) | every byte equal |
| T-U-21b | ZF `vectors.json` and `vectors-big-identifier.json` through our wrapper | every byte equal |
| T-U-21c | ZF `vectors_dkg.json` (DKG with fixed randomness) through our DKG wrapper | the same group key and verifying shares |
| T-U-22a | Every 2-of-3 pair of a DKG slot signs a message | each aggregate passes `verifyXrplKeySig` (strict, 6.8) |
| T-U-22b | A signer calls `signShare` a second time for the same commitment | throws `NONCE_USED`; no share is returned |
| T-U-22c | The coordinator sends one signer a different message, or a different commitment list, for a commitment it already holds | the signer refuses with `SESSION_MISMATCH` |
| T-U-22d | One participant sends a corrupted signature share | `verifyShare` names that participant; `aggregate` is not called |
| T-U-22e | A DKG or signing message with a bad enrollment signature | refused with `ENROLLMENT_SIG_INVALID`, before any use of its content |
| T-U-23a | Refresh a 2-of-3 slot, with every received sub-share checked against the sender's Feldman commitments | the group key is unchanged; every pair still signs |
| T-U-23b | Combine one old share with one refreshed share | the result does not verify (old and new shares do not mix) |
| T-U-23c | Refresh output compared with ZF's refresh on the same inputs | the same refreshed shares and verifying shares |
| T-U-29a | Key directory: the coordinator swaps the recovery agent's (or the firm HSM's) enrollment key for its own before key generation; or a holder's key was never pinned | refused `KEY_NOT_PINNED` before any DKG message is used; the swap is detected |
| T-U-29b | Pinning: two of a client's own devices pin each other through a QR code (the code carries both enrollment key hashes and a short authentication string); a service holder's signed key list is checked against the hash anchored on the ledger from its own XRPL account, and the list must be signed from the firm's operations account | a wrong QR code or a list whose hash is not the anchored one fails `PIN_MISMATCH`; a list signed by another account fails `LIST_SIGNER_WRONG` |
| T-U-29c | The `enrollment_key` registry is append-only: pinning a second, different key for the same holder and role; removing a key; using a key before its hash is in the evidence log | `KEY_CHANGED`, `REGISTRY_APPEND_ONLY`, `KEY_NOT_LOGGED` |
| T-U-29d | Echo broadcast: after round 1 every holder signs the hash of the full round-1 transcript; one holder was shown a different round-1 message | every holder aborts with `TRANSCRIPT_MISMATCH`; the DKG finishes only with three signatures over one hash |
| T-U-29e | Round-2 complaints: a holder sends a bad share; the receiver publishes a signed complaint that carries the ciphertext. A false complaint against an honest sender | the bad sender is named and everyone can verify it; the false complaint is detected and its author named |
| T-U-29f | Test-signing before the seal: the slot signs one fixed message with each of its three pairs; one pair has a broken share | `SLOT_SETUP_FAILED`; the `frost.dkg.completed` record is not built, so no seal can include the slot; with all three pairs good the record holds the transcript hash, all signatures, the verifying shares and the three test signatures |
| T-U-30a | Repair: two holders help a new device rebuild a share without the old share | the new share signs with the group key together with any other holder; the old share is never an input |
| T-U-30b | A helper sends a wrong repair contribution | the new holder detects it against the verifying shares and names the helper; no share is installed |
| T-U-30c | Repair compared with ZF `frost-ed25519` 3.0.0 `repairable` and its vector `repair-share.json` | the same repaired share |
| T-U-31a | Approvals: a holder that guards a lawyer share (the firm HSM) is asked to sign without a user-verified WebAuthn approval by the lawyer over the same message hash; with an approval whose user-verified flag is clear; with an approval over a different hash | `APPROVAL_MISSING`, `APPROVAL_NOT_UV`, `APPROVAL_HASH_MISMATCH`; no nonce is used |
| T-U-31b | Message allow-list: a holder is asked to sign an XRPL transaction of a type that is not allowed, one whose destination or amount does not match the seal, a multisign message for another wallet, and a tagged `tupleHash` message whose tag is not on the list; then each allowed kind (the matching XRPL multisign, binding, contract signature, presence statement, post-quantum cross-signature, operations binding, gate record) | `MESSAGE_REFUSED` for each bad one; every allowed one is signed |
| T-U-31c | Server holders mark nonces used atomically: two concurrent requests for the same commitment id against the `NonceLedger` contract (an in-memory implementation here; Phase 3 runs the same contract test against Postgres) | exactly one signature share is released; the other request gets `NONCE_USED` |
| T-U-31d | Recovery rules as a pure state machine: client recovery needs a fresh zero-knowledge proof record with the same identifier as onboarding and a face match; lawyer recovery needs a request signed by the operations account; then a 72-hour delay (72 h minus 1 s refused, 72 h exactly allowed); notices are produced for the old device and both lawyers; the old device cancels during the delay | `IDENTIFIER_MISMATCH`, `FACE_MATCH_MISSING`, `OPS_SIGNATURE_INVALID`, `RECOVERY_DELAY`; `CANCELLED` stops signing; a cancel after the delay is refused; every step is an evidence record |
| T-P-01 | Property: for random seeds, every 2-of-3 pair of a FROST slot makes a signature that passes strict verification; one share alone cannot (every attempt with one share fails) | holds for 100 slots |
| P1.15-01 | DKG round 2 packages are sent only as X-Wing HPKE ciphertexts, each wrapped in a message signed by the sender's enrollment key | the relay-side recording contains no plain share; a plain package is refused |
| P1.15-02 | DKG round 2 package sent to the wrong recipient, or replayed into another DKG session | refused: the session id and recipient id are inside the signed bytes |
| P1.15-03 | A participant whose round 1 proof of knowledge is wrong | DKG aborts and names the participant |
| P1.15-04 | Two DKG runs with the same seed | different group keys (nonces and polynomials are fresh); a run with an injected deterministic source gives the vector result |
| P1.15-05 | Nonce lifetime: after `signShare`, the session object holds no nonce bytes (the buffer is zeroed); `JSON.stringify` and `structuredClone` of the session throw or omit nonces | passes |
| P1.15-06 | A session restored after a "tab reload" (a new object built from serialized state) | impossible: there is no serializer; a test that tries to build one fails to compile |
| P1.15-07 | The same message signed twice in two sessions | the two signatures differ (fresh nonces) and both verify |
| P1.15-08 | `slotPolicy(slot, roles)` against DESIGN 6.4 (it takes the slot name and the role list only, never verifying shares; a type test shows that a third argument does not compile) | equals the committed golden hash; changing the slot name or the role list changes it |
| P1.15-09 | Canonical role order: each slot kind has one order (client: `phone`, `security-key`, `recovery-agent`; lawyer: `console`, `firm-hsm`, `partner`). A shuffled role list, a duplicate role and an unknown role | the shuffled list gives the same hash as the canonical one; a duplicate or unknown role is refused `ROLE_INVALID` |
| P1.15-10 | Aggregate checked with strict verification before it is returned | an aggregate that fails strict verification (a hand-built bad `R`) is rejected with `AGGREGATE_INVALID` |
| P1.15-11 | The group key is `0xED` plus the 32-byte key, and an `xrpl.js` Ed25519 address derived from it matches our address function | equal |
| P1.15-12 | 60 signatures across all 3 pairs, signed with a noble DKG slot | 60 of 60 pass strict `zip215: false` (repeats the r7 run as a regression test) |
| P1.15-13 | Cross-test with ZF Rust: a Rust helper in `tools/frost-ref/` (frost-ed25519 3.0.0) writes a DKG transcript, signing round and refresh output to JSON; our code verifies and reproduces them, and signs a message that the Rust code verifies | both directions pass; the JSON files are committed, and CI reruns the Rust tool only on request |
| P1.15-14 | After a refresh, `slotPolicy(slot, roles)` gives the same hash as before (it holds the threshold and the holder roles only, DESIGN 6.4), the group key is unchanged, and the verifying shares change | `slotPolicy` and `xPub` equal their sealed values; the `frost.refreshed` event carries the old and new verifying shares |
| P1.15-18 | `frost.refreshed` completeness: an event with a signed deletion statement from only some of the remaining holders; one with a statement signed by a key that is not an enrolled holder; one with all of them | the first two are `INCOMPLETE` (the refresh does not count as done); the third is `COMPLETE`; the module comment says that a refresh is hygiene and not revocation |
| P1.15-15 | Refresh that tries to change the threshold, or that adds a dealing with a non-zero constant term | refused; the Feldman commitment to the constant term must be the identity point |
| P1.15-16 | Refresh message from an unauthenticated sender | refused (ZF's `refresh_dkg_part2` skips the proof check, so we add our own) |
| P1.15-17 | A slot that has lost two shares | `canSign` returns false; signing throws `BELOW_THRESHOLD` |
| P1.15-19 | Refresh sub-share check: one dealer sends a sub-share that does not match its Feldman commitments (the prototype never checked this) | that dealer is named and refused (`SUBSHARE_INVALID`); no share is replaced |
| P1.15-20 | Rotation plan: `rotationPlan(slot, reason)` for a share known to be stolen, for a client slot and for a lawyer slot; a `refresh` request for a slot flagged stolen | the client plan is: new DKG, 4-of-4 `SignerListSet`, new seal. The lawyer plan adds new contract signatures and a new NFT. The refresh request is refused `ROTATION_REQUIRED` |
| P1.15-21 | Second authenticator: the client slot's DKG enrollment names two holders with the same device or authenticator id; a client slot with the role `passkey-same-device` instead of `security-key` | refused `SAME_DEVICE_SHARES` unless the slot is declared in single-device mode; the single-device role list gives a different `slotPolicy`, and `isSingleDeviceMode(roles)` is true, so every screen and the evidence can label it |
| P1.15-22 | Budget: one DKG for a 2-of-3 slot and one signing round in Node | under 1 s and under 250 ms (ten times the prototype timings, to catch an accidental slowdown) |
| P1.15-23 | Import check: `frost.ts` and `xrpl` 5.3.0 load in one process on Node 24.22 | no `ERR_REQUIRE_CYCLE_MODULE`; if a static import fails, `frost.ts` uses a dynamic `import('xrpl')` and this test pins that |

**Think.**
- The group key is the slot's XRPL key, so everything else in the repo sees an ordinary Ed25519 key. The module exports: `dkg` (three-round state machines with the echo broadcast, complaints and test-signing), `SigningSession`, `verifyShares`, `aggregateChecked`, `refresh`, `repair`, `slotPolicy(slot, roles)`, `rotationPlan`, `approvalCheck`, `messageAllowed`, `NonceLedger` and `recoveryMachine`.
- DKG state machines are pure: each round is a function from `(state, incoming messages)` to `(state, outgoing messages)`. The relay (task 3.9) and the browser (task 4.7) only move messages.
- A signing session is a class with a private field for the nonces and no way to read them. It is the only object that can produce a signature share.
- Refresh is ours. noble has none, so we write it from the ZF design, and we label it unaudited everywhere (DESIGN 10.1). Repair follows ZF's `repairable` module.
- Recovery, approvals and the message allow-list are pure rules here. A holder never signs on its own say-so: the firm HSM needs the lawyer's user-verified approval over the same message hash, and the client's second authenticator signs only after the client approves on it. The coordinator only relays.

**Test in all directions.**
- Differential: noble against the RFC and ZF vectors (T-U-21), against ZF Rust live output (P1.15-13), and against `ed25519.verify` in strict mode, `@noble/ed25519` 3.2.0 and Node `crypto.verify` (the last one is reported, not required: see task 1.4).
- Property (T-P-01): random slots, random pairs, random messages. Flip any bit in the message, the commitments or a share: verification or `verifyShare` fails.
- Adversarial: a coordinator that reorders commitments, drops a participant after round 1, or offers two messages for one commitment.
- Negative: every wrapper function rejects wrong lengths, the zero scalar, the identity point and a duplicate participant id, with a typed error.

**Think hard.** A refresh is hygiene, not revocation: old shares still combine with each other, and nobody can prove a deletion. The only real revocation is rotating the slot key on the ledger (a new DKG, a 4-of-4 `SignerListSet`, a new seal, and for a lawyer slot new contract signatures and a new NFT), which task 2.6 tests on a real ledger (P2.6-02).
- Nonce reuse leaks the key share. The rule "memory only, used once, zeroed" is enforced by the type of the session object, not by a comment. The sketch:
```ts
export class SigningSession {
  #nonces: SigningNonces | undefined;
  readonly #msgHash: Uint8Array;        // SHA-256 of the message this session was opened for
  readonly #commitmentsHash: Uint8Array; // hash of the sorted commitment list
  private constructor(n: SigningNonces, msgHash: Uint8Array, cHash: Uint8Array) {
    this.#nonces = n; this.#msgHash = msgHash; this.#commitmentsHash = cHash;
  }
  static open(share: KeyShare, msg: Uint8Array): { session: SigningSession; commitment: Commitment } {
    const { nonces, commitment } = ed25519_FROST.commit(share);    // fresh randomness
    return { session: new SigningSession(nonces, sha256(msg), /* set on sign */ new Uint8Array(32)), commitment };
  }
  signShare(msg: Uint8Array, commitments: Commitment[], checkMessage: (m: Uint8Array) => Result): SignatureShare {
    const n = this.#nonces;
    if (!n) throw new FrostError('NONCE_USED');
    if (!equalBytes(sha256(msg), this.#msgHash)) throw new FrostError('SESSION_MISMATCH');
    const ok = checkMessage(msg);                 // decode the XRPL transaction and compare it with the seal
    if (!ok.ok) throw new FrostError('MESSAGE_REFUSED', ok.code);
    this.#nonces = undefined;                      // drop first: even a throw below cannot reuse them
    try { return ed25519_FROST.signShare(this.#share, n, commitments, msg); }
    finally { zeroize(n); }
  }
  toJSON(): never { throw new FrostError('NOT_SERIALIZABLE'); }
}
```
  The signer, not the coordinator, supplies `checkMessage`. A signer never signs bytes it has not decoded and compared with the seal (RFC 9591 section 7.3).
- Refresh sketch (the part to review twice):
```ts
// each of the t participants i deals a random degree-(t-1) polynomial f_i with f_i(0) = 0
const dealing = (i: Id, t: number, ids: Id[]) => {
  const coeffs = [0n, ...randomScalars(t - 1)];
  const commitments = coeffs.map(c => G.multiply(c));       // commitments[0] must be the identity
  const subShares = ids.map(j => [j, evalPoly(coeffs, j)]);   // sent to j encrypted and signed
  return { commitments, subShares };
};
// holder j: verify every received subShare against the sender's commitments, then
// newShare_j = oldShare_j + sum_i subShare_{i->j};   group key = unchanged
```
- **Resolved in DESIGN 6.4 (was OQ-1.15).** `slotPolicy` holds only the threshold and the holder roles, so a refresh never changes the seal. Verifying shares live in the `frost.dkg.completed` and `frost.refreshed` events. Old shares still combine with each other after a refresh, so a refresh counts as done only when every remaining holder has deleted its old share and signed a deletion statement. P1.15-14 pins this.
- Refresh does not cancel old shares among themselves. Two old shares still sign for the group key, because the key did not change. Refresh protects a slot only when the old shares are destroyed, so the refresh flow (tasks 3.9 and 4.7) must say so and ask each old holder to delete. T-U-23b tests the part that holds: an old share plus a new share does not combine. Old shares still combine with each other until they are deleted, and nobody can prove a deletion. That is why P1.15-18 says a refresh is not done until every remaining holder has signed a deletion statement, and why a share known to be stolen needs rotation on the ledger (P1.15-20), not a refresh.
- The noble DKG and signing calls have not been audited. Keep wrapper code small, put every check we can in front of and behind the call, and make the vector tests run on every commit.

**Implement.**
1. `frost.ts`: `dkgRound1/2/3` wrappers, `SigningSession`, `aggregateChecked` (calls `verifyShare` for each share, then `aggregate`, then strict verification), `slotPolicy`, `enrollmentSigned`/`openEnrollmentMessage` for the signed and encrypted envelopes (HPKE itself comes from task 1.16, behind a small interface so this task can use a stub in tests).
2. `frostRefresh.ts`: `refreshDealing`, `refreshApply`, `refreshVerify` (with the Feldman sub-share check), and `frostRepair.ts`; `frostSetup.ts` for pinning, the registry rules, the echo broadcast, complaints and test-signing; `frostRules.ts` for approvals, the allow-list, `NonceLedger` and the recovery machine.
3. `tools/frost-ref/` (Rust, `frost-ed25519` 3.0.0) and the vendored vector files with a README that names each source and licence.
4. Vitest files `frost.vectors.test.ts`, `frost.signing.test.ts`, `frost.refresh.test.ts`, `frost.property.test.ts`.

**Test groups.** In this task, T-U-29 is rows T-U-29a to T-U-29f, T-U-30 is rows T-U-30a to T-U-30c, and T-U-31 is rows T-U-31a to T-U-31d. A DESIGN test ID passes when all its rows pass.

**Done when** T-U-21, T-U-22, T-U-23, T-U-29, T-U-30, the core parts of T-U-31, T-P-01 and P1.15-01 to 23 pass, and `frost.ts` has at least 95% branch coverage.

**As built (1.15).** There is no Rust toolchain, so P1.15-13 compares our code with a hand port of ZF frost-ed25519 3.0.0. The vectors are byte-exact. A real Rust run is a known gap (ISSUES I-10).

### 1.16 Post-quantum hybrid crypto: hybrid envelopes, post-quantum binding, hybrid checkpoints, X-Wing HPKE (core)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L14 | Opus | high | L (16 h) | 1.2, 1.3, 1.13 |

This task writes `packages/core/src/pq.ts` (DESIGN 6.13) and extends `evidence.ts` and `checkpoint.ts` so that every envelope and checkpoint is hybrid.

**Research.**
- `research/r8-pq.md`. Facts to use:
  - `@noble/post-quantum` 0.7.1: `ml_dsa65` (public key 1,952 B, signature 3,309 B, signing about 9 ms), `ml_dsa44`, `ml_kem768` and `ml_kem768_x25519` (X-Wing). Not audited and not constant-time, so it is for browser and tests; servers use Node or KMS.
  - Node 24.7 and later has ML-DSA and ML-KEM in `node:crypto` and WebCrypto (pin `.nvmrc` at 24.7 or later; 24.4 has no ML-DSA).
  - AWS KMS `ML_DSA_65` with `ML_DSA_SHAKE_256`: RAW messages up to 4 KB, else `EXTERNAL_MU`. mu is `SHAKE256(tr || 0x00 || len(ctx) || ctx || M)` with `tr = H(pk)` (FIPS 204 section 6.2). noble exposes `externalMu` only on its internal `sign`.
  - C2SP signed-note type 0x06 is a timestamped ML-DSA-44 cosignature (key ID = first 4 bytes of `SHA-256(name || 0x0A || 0x06 || pubkey)`, public key 1,312 B). A note can reach about 5 KB.
  - X-Wing is a draft (draft-connolly-cfrg-xwing-kem-11, HPKE KEM ID 0x647a). `@hpke/hybridkem-x-wing` 0.7.0 is pre-1.0.
  - DSSE allows several signatures. We use two independent ones over the same PAE bytes, and not a composite format.
- FIPS 203, FIPS 204 (ACVP vectors), DSSE 1.0.2, c2sp.org/tlog-checkpoint, c2sp.org/tlog-cosignature, RFC 4998 (evidence record renewal).
- Prototype facts from 24 Oct 2026 (scripts in `scratchpad/proto-pq/`; every step passed under Node 24.22):
  - Node `ml-dsa-65` accepts a raw public key through `{ format: 'raw-public', asymmetricKeyType: 'ml-dsa-65' }`, and contexts work through `{ key, context }`. Node's `crypto.sign` and `crypto.verify` default to an EMPTY context, so every side must pass the context explicitly.
  - noble exposes `ml_dsa65.internal.sign(mu, sk, { externalMu: true })`, which is what the KMS `EXTERNAL_MU` path needs: we compute mu ourselves.
  - `@hpke/hybridkem-x-wing` needs the `Aes256Gcm` and `HkdfSha256` instances passed in. It interoperates with noble's `ml_kem768_x25519`.
  - The C2SP 0x06 line was built and verified in the prototype, but never tested against another implementation. The spec names no ML-DSA context for it; we use the empty context [CHECK].
  - A hybrid JSON envelope is about 4.45 KB larger than an Ed25519-only one (base64).
- DESIGN 6.3, 6.13 and 8.1. The algorithms a record must carry are fixed per record type and format version in verifier code, and are NOT read from the record. The per-slot binding is 2 of 3: `pqKeyHash_slot` is the SHA-256 of the slot's three holder ML-DSA-65 enrollment keys in role order; any two holders sign `pqBindMsg` (which holds `pqKeyHash_slot`, not a single `pqPub`), and the slot key cross-signs it. There is no separate single post-quantum key per slot.

**Test first.** DESIGN tests T-U-24, T-U-25, T-U-26 and T-U-27, then ours.

| ID | Test | Expected |
|---|---|---|
| T-U-24a | A hybrid envelope with both signatures | passes |
| T-U-24b | The ML-DSA signature removed | fails `PQ_SIGNATURE_MISSING` |
| T-U-24c | The Ed25519 signature removed | fails `ED_SIGNATURE_MISSING` |
| T-U-24d | The two signatures swapped, or the key IDs swapped | fails |
| T-U-24e | `sig_algs` inside the payload lists an algorithm that the envelope does not carry, or the envelope carries one that the list omits | fails `SIG_ALGS_MISMATCH` |
| T-U-24f | An old classical-only envelope presented to the hybrid verifier | fails; the hybrid verifier never downgrades |
| T-U-24g | A record that lists only `ed25519` in its own `sig_algs` and carries one signature | fails anyway: the required algorithms come from the verifier's table for that record type and format version, not from the record |
| T-U-24h | An ML-DSA signature made with the empty context (Node's default) or with another record's context, verified under `legx/dsse/v1` | fails; the verifier never falls back to an empty context |
| T-U-25a | A post-quantum binding for each of the three holder pairs: two holders sign `pqBindMsg = tupleHash("legx/pq-binding/v1", [dealSeal, slotPub, pqKeyHash_slot])` with ML-DSA-65, and the slot key cross-signs the same message | all three pairs verify; `pqKeyHash_slot` equals `SHA-256` of the three holder keys in role order and equals the sealed value |
| T-U-25b | One holder alone; the same holder signing twice; a signature from a key that is not one of the slot's three holder keys | fails (`BELOW_TWO_HOLDERS`, `DUPLICATE_HOLDER`, `HOLDER_KEY_UNKNOWN`) |
| T-U-25c | A wrong seal, a wrong `slotPub` or a wrong `pqKeyHash_slot` in the message; the three keys hashed in another order | fails with the reason for that input |
| T-U-25d | The cross-signature missing, or made by another slot's key | fails |
| T-U-26a | A hybrid checkpoint: C2SP line 0x01 (Ed25519) and line 0x06 (ML-DSA-44) | both verify |
| T-U-26b | One changed byte in the note body, either signature or either key ID | fails (a test case for each) |
| T-U-26c | A checkpoint with only one of the two lines (the 0x06 line stripped, or the 0x01 line stripped) | fails `PQ_LINE_MISSING` or `ED_LINE_MISSING`: our verifier requires BOTH lines and has no setting that allows one |
| T-U-27a | ML-KEM-768 and ML-DSA-65 FIPS 203 and 204 vectors (ACVP key generation, encapsulation, signature verification) | pass |
| T-U-27b | X-Wing round trip: seal a backup and a share-transport package, open it | the plain text equals the input |
| T-U-27c | X-Wing tamper test: flip one byte in the encapsulated key, in the ciphertext, in the tag, or in the associated data | `open` fails every time, with no partial output |
| T-U-27d | noble and Node built-in ML-DSA agree (see P1.16-04) | pass |
| P1.16-01 | `sig_algs` stripping attack: an attacker removes the ML-DSA signature and rewrites `sig_algs` to `["ed25519"]` | the rewrite changes the payload, so the Ed25519 signature fails; the envelope fails |
| P1.16-02 | Context strings: an envelope signature (`legx/dsse/v1`) presented as a binding signature (`legx/pq-binding/v1`), and the reverse | fails; each use has its own ML-DSA context |
| P1.16-03 | KMS `EXTERNAL_MU` equivalence: compute mu locally (with `tr`, the explicit context and the message, FIPS 204 section 6.2) for a 10 KB PAE; a stub KMS that signs a given mu with a noble key returns a signature | `ml_dsa65.verify` accepts it over the original message, with the same context; a RAW signature over a 3 KB message and an `EXTERNAL_MU` signature over the same message both verify |
| P1.16-04 | Node 24.7 and later built-in ML-DSA against noble (Node reads the raw public key through `{format:'raw-public', asymmetricKeyType:'ml-dsa-65'}` and gets the context through `{key, context}`): sign in Node, verify in noble; sign in noble, verify in Node; for messages of 0 B, 200 B and 10 KB, with and without a context | all four directions pass (the test is skipped, with a loud message, on a Node without ML-DSA) |
| P1.16-05 | C2SP 0x06 line format: the line is `-- <name> <base64(keyID(4) || timestamp(8) || signature)>`; the key ID is computed as in the spec; the timestamp is the ledger `close_time`, never `Date.now()`; the signature covers the binary `CosignedSubtree` structure, not the note text or the extension lines | matches the C2SP document's example and our own golden line; a signature over the note text instead fails |
| P1.16-13 | The 0x06 context string: the spec names none, so we use the empty context. The test pins our golden line and carries an `it.todo('CHECK 0x06 context against another implementation')` that shows in every run | the golden line verifies; the todo stays until a second implementation has verified our line |
| P1.16-06 | The Ed25519 0x01 line verifies with `@cloudflare/signed-note-wasm`; the same note with the 0x06 line removed ALSO passes that standard verifier (it ignores unknown keys) | both pass in the standard verifier, which is why our own verifier must require both lines (T-U-26c); the 0x06 line is checked against the spec only |
| P1.16-07 | X-Wing fallback: the suite tag `hpke-xwing-v1` is stored with every sealed package; a package with an unknown tag | refused with `SUITE_UNKNOWN`; opening works after a suite swap in a test that registers a second suite |
| P1.16-08 | `@hpke/hybridkem-x-wing` (given `Aes256Gcm` and `HkdfSha256` instances) against `ml_kem768_x25519` from noble on the draft-11 vectors | both produce and open the same packages, or the test records and explains each difference |
| P1.16-09 | Key registry (the append-only `enrollment_key` table, anchored through the evidence log): an envelope names ML-DSA keys by key ID, and a key ID that is not in the registry, or outside its `validFrom` and `validTo`, or whose hash is not yet in the evidence log, fails | fails with `KEY_UNKNOWN`, `KEY_EXPIRED` or `KEY_NOT_LOGGED` |
| P1.16-10 | RFC 4998 renewal statement builder: `renewalStatement(prevHash, newCheckpoint, pqSig)` is a pure function | the output chains to the previous statement, and a broken chain fails (the scheduled job is task 3.12) |
| P1.16-11 | Sizes: a hybrid envelope for a 1 KB event stays under 6 KB when base64 encoded, and is between 4.3 and 4.6 KB larger than the Ed25519-only envelope; the memo built from a checkpoint stays a hash only | passes |
| P1.16-12 | ML-DSA signing is hedged (random), so two signatures over one message differ | both verify; storage and deduplication use the payload hash, never the signature bytes |
| P1.16-14 | Binding golden vector: `pqBindMsg` and `pqKeyHash_slot` for fixed inputs | equal to the committed hex; changing any one of the three keys changes both |
| P1.16-15 | Explicit contexts: every ML-DSA `sign` and `verify` call in `pq.ts`, `evidence.ts` and `checkpoint.ts` goes through one wrapper that has no default context; a test replaces Node and noble with spies | no call without a context argument; the contexts used are exactly `legx/dsse/v1`, `legx/pq-binding/v1` and `legx/checkpoint/v1` (and the empty context for 0x06, P1.16-13) |
| P1.16-16 | A duplicated signature (the same ML-DSA signature listed twice, or the Ed25519 one twice) | fails; the verifier needs one valid signature of each required algorithm |

**Think.**
- Two independent signatures over the same bytes, both required, with the list of required algorithms inside the signed payload. We do not invent a composite format. The IETF composite draft is X.509-centred and not an RFC.
- `signHybrid` takes a `SignerPort` pair (classical and post-quantum). In the browser the post-quantum signer is noble. On servers it is KMS or Node. Core has no opinion.
- Each use of ML-DSA has its own context string: `legx/dsse/v1`, `legx/pq-binding/v1`, `legx/checkpoint/v1`, and the caller always passes it explicitly (Node defaults to an empty one).
- The required algorithms per record type and format version live in one table in code. A record's own `sig_algs` is only a second check.
- Core exposes `muFor(pk, ctx, msg)` for the KMS path. The adapter (task 3.12) calls KMS with the result.

**Test in all directions.**
- Differential: noble against Node, noble against the KMS stub, noble against the FIPS vectors.
- Property: for random payloads, a hybrid envelope round trips, and any single-bit mutation of the payload, either signature or the `sig_algs` list fails.
- Negative: every verifier returns a typed error on wrong lengths (public key not 1,952 B, signature not 3,309 B), never throws out of the module.
- Compatibility: a hybrid envelope still verifies in a plain DSSE verifier for the Ed25519 signature alone (so old tools can read it); our verifier is the one that requires both.

**Think hard.**
- A stripped signature is the main attack. Defense is the signed `sig_algs` list plus a verifier policy that has no "classical only" mode. Test the policy by trying to configure one: it must not compile.
- The post-quantum binding does not move money. It proves consent if Ed25519 is broken later. State this in the test names and in the module comment, so nobody sells it as on-ledger protection. The honest limit: a quantum break of Ed25519 lets an attacker move the money until the ledger migrates (DESIGN 6.13, O17); evidence made and anchored before the break stays trustworthy.
- A standard signed-note verifier ignores unknown keys, so a stripped 0x06 line passes it. Only our verifier, which requires both lines, catches the strip.
- noble is not constant-time. Keep it out of server signing paths, and put a lint rule (`noRestrictedImports`) that stops `services/*` from importing noble's ML-DSA `sign`.
- X-Wing is a draft. The suite tag makes a swap a data change, not a code change.

**Implement.**
1. `pq.ts`: `pqKeygen`, `signHybrid`, `verifyHybrid`, `pqKeyHash`, `pqBindMsg`, `signPqBinding` (one holder's ML-DSA signature), `verifyPqBinding` (two distinct holders plus the cross-signature), `muFor`, the context wrapper, the record-type algorithm table, `sealPackage`/`openPackage` (X-Wing HPKE with a suite tag), and the key registry type.
2. Extend `evidence.ts` so `signEnvelope` and `verifyEnvelope` are hybrid, with `sig_algs` in the payload. Extend `checkpoint.ts` to write and verify the 0x01 and 0x06 lines.
3. Vendor FIPS 203 and 204 ACVP vector subsets and the X-Wing draft-11 vectors, with licences in the README.
4. Add `renewalStatement` (pure).

**Done when** T-U-24 to T-U-27 and P1.16-01 to 16 pass, `pq.ts` has at least 95% branch coverage, and every earlier evidence test still passes with hybrid signing turned on.

### 1.17 Zero-knowledge identity checks (core): `C_side`, attestation zkpassport path, `ZkVerifierPort` contract, mock-passport fixtures

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L15 | Opus | high | L (12 h) | 1.2, 1.6, 1.9 |

Core stays pure. It never imports `@zkpassport/sdk` and never touches a network. Verifying a proof needs an Ethereum RPC and ZKPassport's files, so that work sits behind `ZkVerifierPort`, which task 3.11 implements. Core checks the recorded result that the port returns.

**Research.**
- `research/r6-zkpassport.md`. Facts to use:
  - `@zkpassport/sdk` 0.19.2 (Apache-2.0, pre-1.0, no external audit), `@zkpassport/registry` 0.15.3, and `@zkpassport/utils` 0.40.0-beta.2, which is nested under SDK 0.19.2 and has `createMockPassport` (it is NOT in 0.39.0, so do not install 0.39.0 for fixtures).
  - `verify()` returns `{ verified, uniqueIdentifier, uniqueIdentifierType, queryResultErrors }` plus, per proof, `proof`, `vkeyHash`, `version` and `committedInputs` (the bound data, in plain text). The scope is NOT in the result, so our request code stores it with the record. It is not network-free. We use `verifierMode: "local"`, our own RPC and a pinned version.
  - `bind` carries `custom_data` as UTF-8, capped at about 506 bytes. The SDK does not check this at request time, so OUR code checks the length before it shows a QR code.
  - Mock identifiers DIFFER per passport and per scope, and are stable for the same passport, domain and scope. The identifier also depends on the domain string given to `new ZKPassport(domain)`, which is always `"legx.app"`, passed explicitly. So the scope and stability tests run in CI on mocks. Only the real (non-mock) formula needs one recorded real-passport run (T-U-28c).
  - A headless prove and verify works through ZKPassport's repo script `packages/e2e/src/prove.ts`: about 10 s to prove, 0.65 s to verify, 5 proofs of about 14.7 KB each. We vendor it as a development tool (`tools/zk-prove/`). Scripts of the prototype: `scratchpad/proto-zk/`.
  - Offline verify works: `verify({ config })` accepts injected loaders (`rpcUrl`, `circuitManifestUrlGenerator`, `packagedCircuitUrlGenerator` and others), and it returned `verified=true` with the network blocked.
  - Whether `verify()` runs in a browser is unknown (`bb.js` has about 4 MB of WASM and needs `SharedArrayBuffer` for threads). So plan to verify in Node (the lawyer console calls a local helper or the coordinator-side adapter of task 3.11), and let task 4.8 prove or disprove the browser option.
  - There is no Active or Chip Authentication in ZKPassport. A plain ESM import fails in Node; use CommonJS `require` or a bundler (the fixtures tool uses `require`).
  - The exact API names for the expiry check (`gt("expiry_date", ...)`) and the strict face match are [CHECK]; the tests below pin whatever the 0.19.2 typings show.
- DESIGN 6.2 (`C_side = tupleHash("legx/zk-identity/v1", [zkSalt32, utf8(N_side)])`; the salt is kept with share 2, with an encrypted copy to the client's lawyer), 6.10 (the two proofs, scopes, bound values, verification settings, trust anchors, offline re-verification, identity method changes, disputes) and 6.15.

**Test first.** The proofs are recorded once, then replayed. `tools/record-zk/` builds mock passports with `createMockPassport` (`@zkpassport/utils` 0.40.0-beta.2), proves them with the vendored headless prover (`tools/zk-prove/`, from ZKPassport's `packages/e2e/src/prove.ts`, about 10 s per proof) and records the SDK's verification output, the proofs and the registry and circuit inputs as files in `packages/fixtures/zk/`. Recording runs on demand and in the nightly job, not on every pull request. Core tests read those files and never load the SDK.

| ID | Test | Expected |
|---|---|---|
| T-U-28a | A good onboarding result (domain `legx.app`, scope `legx/v1/<dealId>`, bound value equal to `hex(tupleHash("legx/zk-onboard/v1", [contractRoot, slotPub_side]))`) and a good release result (same domain and scope, bound value equal to `hex(presenceMsg)`, which holds `lawyerNonce`, strict face match passed) for the same identifier | both pass; `C_side` equals the sealed value |
| T-U-28b | One failure case per reason: wrong scope (`WRONG_SCOPE`), wrong domain (`WRONG_DOMAIN`), wrong bound value (`BOUND_VALUE_MISMATCH`), bound data over 506 bytes (`BOUND_TOO_LONG`, checked by our code), a different identifier on release than on onboarding (`IDENTIFIER_MISMATCH`), an expired document (`DOCUMENT_EXPIRED`), an expiry before `CancelAfter` + 30 days (`EXPIRY_TOO_EARLY`; exactly `CancelAfter` + 30 days plus one second passes, exactly at it fails), a failed or missing face match on release (`FACE_MATCH_FAILED`), `devMode: true` under the production profile (`DEVMODE_REFUSED`), a Sepolia root (chain ID 11155111) or a mock identifier type under the production profile (`SEPOLIA_REFUSED`, `MOCK_IDENTIFIER_REFUSED`), non-empty `queryResultErrors` (`QUERY_ERRORS`), `verified: false` (`PROOF_NOT_VERIFIED`) | each fails with exactly its own code |
| T-U-28c | One recorded real-passport run: same passport and same scope twice, and the same passport under a second scope | the identifier is the same within a scope and different across scopes (a recorded fixture; the test also runs without a phone). It is needed only for the real, non-mock identifier formula; the same three cases already run in CI on mock passports (P1.17-18) |
| T-U-32a | Trust record: every recorded zero-knowledge attestation holds chain ID, block number and block hash, registry address, root, circuit manifest version, verification-key hashes, identifier type and `dev_mode` | all nine present; any one missing fails `TRUST_RECORD_INCOMPLETE` |
| T-U-32b | Offline re-verification: with `fetch` and sockets stubbed to throw, `verify({ config })` runs with loaders injected from the recorded registry answer and circuit files (`tools/record-zk/` holds the test, because core never loads the SDK) | `verified` is true for every recorded proof |
| T-U-32c | A mismatch fails: a changed registry root, a changed verification-key hash, a changed circuit file, another manifest version, one changed proof byte | each fails offline with `TRUST_MISMATCH:<field>` (or `PROOF_NOT_VERIFIED`) |
| T-U-32d | The recorded roots and circuit files are part of the next evidence checkpoint input | the checkpoint input holds their hashes; changing a recorded file changes the hash |
| T-U-32e | Production refusals on the recorded trust record (Sepolia, mock identifier type, `dev_mode`) repeat at re-verification time | refused in the production profile; accepted in the demo profile |
| P1.17-01 | `zkIdentityCommitment(zkSalt32, N)` equals the DESIGN 6.2 recipe `tupleHash("legx/zk-identity/v1", [zkSalt32, utf8(N)])`; golden vector | equal; a different `N` or a different salt gives a different `C_side`; a salt that is not 32 bytes is refused |
| P1.17-02 | `C_side` placed in the seal (task 1.6) with `idMethod: "zkpassport"` | the seal input check passes; with `idMethod: "nfc-chip"` and a zero-knowledge `C_side` the attestation fails `COMMITMENT_MISMATCH` |
| P1.17-03 | The `zkpassport` attestation path in `verifyAttestation` with every check true | passes |
| P1.17-04 | Each of `proof_verified`, `identifier_matches`, `bound_value_is_presence_msg`, `document_not_expired` set to `false` | `CHECK_FALSE:<name>` for that name |
| P1.17-05 | `proof_sha256` differs from the SHA-256 of the proof bytes stored in the evidence log | `PROOF_HASH_MISMATCH` |
| P1.17-06 | A trust record field (chain ID, block number or hash, registry address, root, circuit manifest version, `vkey_hashes`, identifier type, `dev_mode`) missing, empty or not hex | `ZK_RECORD_INCOMPLETE` |
| P1.17-07 | Identity policy: `"zk"` accepts only `zkpassport`; `"chip"` accepts only `nfc-chip`; `"zk-or-chip"` accepts either if it equals the sealed `idMethod_side` | table test over all 9 combinations |
| P1.17-08 | `checkBindLength(value)`, run before a request is shown as a QR code: the bound value for a release proof built from `presenceMsg` (64 hex characters) is at most 506 bytes in its UTF-8 `custom_data` form; 506 passes and 507 is refused | passes; `BOUND_TOO_LONG` (our code checks it because the SDK does not check at request time) |
| P1.17-09 | `ZkVerifierPort` contract test, run against a fake and (in task 3.11) against the real adapter | the same cases pass for both; the fake returns recorded results |
| P1.17-10 | Mock-passport fixtures: `createMockPassport` with an expiry in the past | the recorded result has `document_not_expired` false and `queryResultErrors` non-empty |
| P1.17-11 | The raw passport never appears in any record: a test searches every `PassportAttestation`, event and stored zero-knowledge record for the mock passport's name, document number and date of birth | none found (invariant I7) |
| P1.17-12 | A zero-knowledge attestation presented in a deal that requires `identityPolicy: "chip"` | `METHOD_NOT_ALLOWED`; the chip path is the only one that checks Active or Chip Authentication |
| P1.17-13 | Salt handling: the `zkSalt32` is sealed with X-Wing to the client's own lawyer (`sealSalt`, task 1.16 package format); the lawyer opens it, recomputes `C_side` from the identifier and the salt, and compares it with the sealed value | the lawyer's key opens it and `C_side` matches; another lawyer's key, or a flipped byte, fails with no partial output |
| P1.17-14 | Onboarding disclosure: name, date of birth and nationality are sealed with X-Wing to the client's own lawyer only; the onboarding attestation, the `identity.onboarded` event and the stored proof record hold none of them | the lawyer opens the disclosure; a search of every public record finds no name, date of birth or nationality (extends P1.17-11) |
| P1.17-15 | Domain: the request builder reads the domain only from the config constant `legx.app`; it is given a page origin, a tunnel host name and an empty value | the first is ignored and the domain stays `legx.app`; an empty or different domain is refused `WRONG_DOMAIN`; the request config snapshot shows the domain |
| P1.17-16 | Release proof facts: the release request repeats the onboarding facts, turns on the strict face match by default, and binds `presenceMsg`; the request description is compared with the onboarding one | equal facts; face match on; a request with the face match off is refused unless the deal data says so (O12 [CHECK]) |
| P1.17-17 | Scope not in the result: the stored record holds the scope we requested, and `checkZkResult` compares it with `legx/v1/<dealId>`; a record with no stored scope | `WRONG_SCOPE`; `ZK_RECORD_INCOMPLETE` |
| P1.17-18 | Mock-passport scope tests in CI (`createMockPassport`, recorded with `tools/zk-prove/`): the same passport, domain and scope twice; a second passport; a second scope; a second domain | the identifier repeats for the first case and differs in the other three |
| P1.17-19 | Identity method change mid-deal: a renewed passport (new identifier, so a different `C_side`), a changed circuit version that changes the identifier derivation, and a switch to the chip path | each is refused by the gate against the old seal (`COMMITMENT_MISMATCH` or `METHOD_MISMATCH`) and `identityChangePlan` returns the 4-of-4 seal update that is needed; a slot that refuses to sign the update is recorded as a refusal (O9, a stall at release) |
| P1.17-20 | Dispute: `disputeIdentity(bundle)` for a client whose passport has since expired or been renewed | it returns the client's identity from the onboarding disclosure and attestation in the bundle; it needs no new proof, and a new proof stays optional |

**Think.**
- Three small pure pieces: `zkIdentityCommitment`, `checkZkResult(result, expected)` (scope, bound value, identifier, expiry, profile, query errors) and the `zkpassport` branch of `verifyAttestation`.
- `ZkVerifierPort` is a contract: input is the stored proof set plus the original query; output is the recorded-result shape from task 1.2 (P1.2-08). Core accepts a result only with its roots, circuit IDs and `proofSha256`.
- The production profile and the demo profile are an input (`profile: "production" | "demo"`), not a global.

**Test in all directions.**
- Property: for random scopes, bound values and identifiers, a good result passes and a single wrong field fails with exactly one code.
- Replay: a release result from deal X presented in deal Y fails (`WRONG_SCOPE`).
- Salt: two clients with the same passport number in two deals get different `C_side` values (different salts), and one client in one deal gets the same `C_side` at onboarding and release.
- Replay inside a deal: a release result for an old ledger hash fails `BOUND_VALUE_MISMATCH` because `presenceMsg` contains the fresh ledger hash.
- Fixture integrity: the recorded files are hashed, and the test fails if the hashes change without a new recording note.

**Think hard.**
- What a zero-knowledge proof does not show: it does not show that the chip is present (DESIGN 10.1). The default policy is `"zk-or-chip"` for deals that can accept this, and contracts that need presence use `"chip"`. The tests state this by name (P1.17-12).
- The recorded results are only as good as the recording run. Store the SDK version, the `@zkpassport/utils` version, the circuit manifest hash and the registry roots with each file, and fail the test suite when the pinned SDK version differs from the one in the recording note (a deliberate re-record step).
- The verification can fail for reasons outside our control (the registry or CDN is unreachable). That is task 3.11's job to retry; core only sees a result or no result, and a missing result is `ZK_RESULT_MISSING`.
- Do not put the SDK in `@legx/core`. A lint rule (`noRestrictedImports`) bans `@zkpassport/*` there.

**Implement.**
1. `src/zkIdentity.ts`: `zkIdentityCommitment`, `onboardingBoundValue`, `checkBindLength`, `sealSalt`, `checkZkResult` (with the trust record and the production refusals), `identityChangePlan`, `disputeIdentity`.
2. The `zkpassport` branch in `src/attest.ts` (the dispatch from task 1.9).
3. `tools/zk-prove/` (ZKPassport's `prove.ts`, vendored with its licence and a pinned upstream commit) and `tools/record-zk/` (CommonJS) with the offline re-verification test (T-U-32b and c), and `packages/fixtures/zk/` with the recorded results, proofs, registry answers and circuit files, and a README (versions, dates, what was recorded and how).
4. A contract test file for `ZkVerifierPort` that task 3.11 reuses.

**Test groups.** In this task, T-U-32 is rows T-U-32a to T-U-32e. It passes when all its rows pass.

**Done when** T-U-28a to c, T-U-32a to e and P1.17-01 to 20 pass, `zkIdentity.ts` has at least 95% branch coverage, and no `@zkpassport/*` import exists in `packages/core`.

### Phase 1 end-to-end suite: "paper deal" (E2E-P1)

One test file, `packages/core/test/e2e-paper-deal.test.ts`, runs a whole deal with pure functions only. The ledger is replaced by synthetic JSON snapshots of `account_info` and `account_objects`, built in the test the same way as the Appendix A checker tests. This keeps Phase 1 independent. Later, task 2.5 records snapshots from a real standalone run and adds them as a second fixture set, so the same suite also runs on real ledger data.

The paper deal uses the new features throughout: every slot key comes from a FROST DKG and every binding is signed by the FROST group key (two shares), each slot has a post-quantum binding, every envelope is hybrid-signed, and one client proves identity through the zero-knowledge path (recorded mock-passport results) while the other uses the chip path (fixture passports).

| ID | Scenario | Expected |
|---|---|---|
| E2E-P1-01 | Build the contract that names the wallet; both lawyers sign; build the NFT URI and memo; run four FROST DKGs (client A, lawyer A, client B, lawyer B); make each slot's `slotPolicy` and ML-DSA-65 key and bind them (`pqBindMsg`, two signatures); sign the bindings and ops bindings with FROST (two shares each, strict check on the aggregate); test-sign every slot with all three pairs; seal the 29-field deal seal and build the `01` Domain; bar records; client A passes the zero-knowledge path (onboarding and release results, `C_A` from the identifier and a salt, `lawyerNonce` inside `presenceMsg`) and client B passes the chip path (fixture passport with presence signature); hybrid-sign every evidence envelope and a hybrid checkpoint with both lines; run the lock checker and the gate | every gate code passes (the full DESIGN 6.17 list, including `ONBOARDING_OK`, `IDS_DISTINCT`, `IDENTITY_POLICY_OK`, `PQ_BINDINGS_OK` and `SLOT_SETUP_OK`); the gate record and memo are built |
| E2E-P1-02 | Repeat E2E-P1-01, and break one input at each stage, one at a time (about 65 cases, including: a swapped enrollment key, a DKG transcript seen differently by one holder, a pair that fails test-signing, a reused `lawyerNonce`, a presence signature older than 1 hour, a third share signing alone, a reused nonce, a bad share, a wrong `slotPolicy`, a wrong `pqKeyHash`, a stripped ML-DSA signature, a `sig_algs` mismatch, a wrong ZK scope, a wrong bound value, a `devMode` result in the production profile, a method not allowed by the policy) | the first failing check names the broken input |
| E2E-P1-03 | Recompute everything from public data only, as an arbitrator would: the seal, the slot policies, the post-quantum bindings, the hybrid signatures, the checkpoint lines, the zero-knowledge records and the gate | the same seal, the same gate result |
| E2E-P1-04 | No function in `@legx/core` reads the clock or the network | a test stubs `Date.now`, `fetch` and `WebSocket` to throw, and E2E-P1-01 still passes (the zero-knowledge results are recorded files, so `@zkpassport/sdk` is never loaded) |
| E2E-P1-05 | Refresh client A's slot (replace one share holder) in the middle of the deal | the group key, `xPubA` and `slotPolicyA` are unchanged; the refreshed slot still signs; an old share plus a new share does not combine (old shares still combine with each other until deleted); the `frost.refreshed` event is `COMPLETE` only with every remaining holder's deletion statement, and `INCOMPLETE` with one missing |
| E2E-P1-06 | A recovery path: client A's phone share is lost, and the second-authenticator share and the recovery agent sign, after the 72-hour delay and with the notices produced | the signature verifies under `xPubA`, and the evidence names the share holders that took part; signing one second before the delay ends is refused |
| E2E-P1-07 | A repair: a new device for client A rebuilds a share from two holders, then every pair that includes it signs | each signature verifies under `xPubA` |

**Phase 1 exit gate (G1):** E2E-P1 green, coverage at least 95% branches on `lockcheck.ts`, `releaseGate.ts`, `attest.ts`, `signedContract.ts`, `frost.ts`, `pq.ts` and `zkIdentity.ts`, the FROST, post-quantum and zero-knowledge vector tests green (T-U-21, T-U-27a, T-U-28c), T-U-29 to T-U-32 green (the core parts of T-U-31), the ZF Rust cross-test files committed (P1.15-13), and `tsc` clean. T-P-01 is part of this gate because it belongs to milestone M0b.

---

## 6. Phase 2: Ledger layer (`@legx/xrpl`)

**Goal.** Every XRPL interaction in DESIGN 7 behind one tested package: builders for every step, reliable submission, one-ledger reads, multisig, the watcher client, and real-ledger tests for every flow and every ledger attack.

**Owns:** `packages/xrpl/`, `ci/xrpld.cfg`, `docker-compose.ledger.yml`.

**Starts:** after G0. It uses the starting code from DESIGN Appendix A (task 1.3) at once, and switches to the DESIGN 6 versions of the functions as Phase 1 lands them. **Unblocks:** Phase 3 (services call `LedgerPort`), and the real-data fixtures for E2E-P1.

**Covers DESIGN:** 5.2 to 5.4, 6.4 and 6.10 (as they touch the ledger), 7.1 to 7.7, 8.3 (anchor transaction), 8.5 (watcher client), 11, and milestones M1 and M2.

**Rule for this phase:** every test here runs against a real ledger: standalone in Docker on every pull request, and Testnet nightly. No ledger mocks, except in the unit tests of pure builders.

### 2.1 Ledger environments and harness

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L4 | Sonnet | medium | M (4 h) | 1.1 |

**Research.** Section 4.5 of this doc: the latest `rippleci/xrpld` tag, its platforms, and the Testnet faucet limits. DESIGN 11.2: the amendment facts confirmed on 24 Oct 2026.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P2.1-01 | `pnpm ledger:up` starts standalone xrpld and waits until `server_info` answers | ready in under 60 s |
| P2.1-02 | `assertAmendments(client)`: each required amendment is enabled, or marked `vetoed: "Obsolete"`, or is on the retired list (`Escrow`, `MultiSign`, `CryptoConditions` and the others in DESIGN 11.2), which is accepted without a check | passes on standalone 3.4.1 with the xrpl.js config, and on Testnet and Devnet |
| P2.1-03 | The same check against a config without the Credentials stanza | fails with a message that names Credentials |
| P2.1-04 | `fundAccount(env, n)` on standalone (genesis) and on Testnet (faucet with backoff) | the account exists with at least the reserve |
| P2.1-05 | `advanceCloseTime(client, target)` on standalone | the validated `close_time` passes the target |
| P2.1-06 | `advanceLedgers(client, 260)` | the ledger index moves by at least 260 |
| P2.1-07 | `readFees(client)` returns base fee, base reserve and owner reserve from `server_info` | values match the network: 200 drops, 20 XRP and 5 XRP on the standalone test config; 10 drops, 1 XRP and 0.2 XRP on Testnet (section 4.5) |
| P2.1-08 | Connecting with `NETWORK=mainnet`, or to a known Mainnet URL | throws before any request (hard rule 1) |

**Think.** One `LedgerEnv` type: `{ name: 'standalone' | 'testnet' | 'devnet', wsUrl, clioUrl?, fund, advance? }`. Standalone has `advance`; Testnet does not, and tests that need time travel are tagged `standalone-only`.

**Test in all directions.** Run P2.1-01 to 07 on standalone, and the network parts on Testnet and Devnet (nightly). Start two standalone ledgers at once on different ports, to prove tests do not share state.

**Think hard.** P2.1-08 is a hard rule in code: a denylist of Mainnet hosts plus a check of `server_info.network_id` and the genesis ledger hash. Never rely on a config value alone.

**Implement.** Move the DESIGN Appendix B harness here. Fix the two harness issues from the 24 Oct run: use a default import of `xrpl` (so it runs under plain Node too), and print `engine_result` when a transaction is rejected before it is applied.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 2.2 Reliable submission and one-ledger reads

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L4 | Opus | high | M (6 h) | 2.1 |

**Research.** The xrpl.org reliable submission and transaction malleability pages; section 4.5 notes on what xrpl.js offers in 2026.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P2.2-01 | `submitReliable(blob)` for a good transaction | returns `{ result: 'tesSUCCESS', validated: true, ledgerIndex, hash, meta }` |
| P2.2-02 | a `tec` result | returns it as final, with `validated: true` (money did not move, but the sequence was used) |
| P2.2-03 | a `tem` or `tef` result | returns `{ final: true, applied: false }` with the engine code (never `undefined`) |
| T-A-14 | resubmit an old blob | `tefPAST_SEQ` |
| T-A-15 | `LastLedgerSequence` passes before submit | `tefMAX_LEDGER` on submit, or "expired" after the ledger passes; the caller gets `{ expired: true }` |
| P2.2-04 | the network drops after submit, before the result | the function finds the result by account + sequence once it reconnects |
| P2.2-05 | `snapshot(account)` reads `account_info` and every page of `account_objects` at one `ledger_index` | every page has the same `ledger_index`; the object count matches the sum of the pages |
| P2.2-06 | `snapshot` while 500 junk objects sit on the account (to force paging) | every object is returned once |
| P2.2-07 | `ledgerHeader(index)` returns hash and `close_time` for a past validated ledger | matches `ledger` RPC |
| P2.2-08 | `deliveredAmount(meta)` | reads `delivered_amount`, never `Amount` |
| T-A-13 | a partial payment into the deal wallet | credited from `delivered_amount` only |

**Think.** Track by account plus sequence (or ticket), never by hash (DESIGN 7.5 step 6). A result is final when it is validated, or when the validated ledger is past `LastLedgerSequence`, `complete_ledgers` covers the range, and `tx` over that range returns `txnNotFound` (Testnet does not return `searched_all`, section 4.5). `tel` and `ter` results are never final. Do not build on xrpl.js `submitAndWait`: it waits about 20 ledgers on a `tef` result and refuses blobs without `LastLedgerSequence` (section 4.5).

**Test in all directions.** Concurrency: submit 20 transactions from 20 accounts at once; each gets exactly one final result. Fault: kill the WebSocket during P2.2-04 at random points (a fast-check scheduler).

**Think hard.** A wrong "final" answer is how money moves twice. The function must never say "failed" for a transaction that can still validate.

**Implement.** `submitReliable`, `snapshot`, `ledgerHeader` and `deliveredAmount` in `src/submit.ts` and `src/read.ts`. Follow the account, sequence and `LastLedgerSequence` loop from the xrpl.org reliable submission page.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 2.3 Transaction builders for every step

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L4 | Sonnet | medium | M (6 h) | 2.1, 1.5, 1.6 |

**Research.** DESIGN 7.3, row by row. The xrpl.js `validate()` function and its models for the Credential and NFToken types.

One pure function per row of DESIGN 7.3: `build0a` to `build9`, `buildEscrowCancel` and `buildAnchor`.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P2.3-01 | Each builder's output passes xrpl.js `validate()` | passes |
| P2.3-02 | Each output encodes and decodes with `ripple-binary-codec` | round trip equal |
| P2.3-03 | Snapshot of each builder's output for a fixed input | equals the committed JSON |
| P2.3-04 | `build1` (mint): URI is 75 bytes; the memo is the 195-byte contract-signatures memo | exact |
| P2.3-05 | `build7` (finish): one memo with the gate leaf hash; no `CredentialIDs` | exact |
| P2.3-06 | `build5b`: `Domain` = hex of `01` + root + the single deal seal (65 bytes) | exact |
| P2.3-07 | `build0a`: `Expiration` = validated `close_time` + 90 days; `URI` 76 bytes | exact |
| P2.3-08 | Fees from `fees.ts` for steps 7, 8 and 9 | 350, 50, one owner reserve (at a 10-drop base) |
| P2.3-09 | A builder given a Mainnet address prefix or a wrong network | throws |

**Think.** Builders do not autofill. A separate `prepare(tx, { signers, lastLedgerOffset })` autofills and sets `LastLedgerSequence` (+20 for single-signed, +1800 for signature collection, DESIGN 7.5).

**Test in all directions.** Property: random valid inputs always produce valid transactions, and the binary codec round trip holds. Task 5.3 also checks that xrpl-py encodes the same bytes.

**Think hard.** A builder that silently drops a field, such as a memo, produces a valid transaction that breaks the design. The snapshot tests catch it.

**Implement.** One file per step group. Each builder is a pure function of typed inputs from `packages/contracts`.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 2.4 Multisig collection and exit slot S

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L4 | Sonnet | high | M (4 h) | 2.2, 1.4 |

**Research.** xrpl.js `multisign` and the AccountID sort order; tickets ([tickets](https://xrpl.org/docs/concepts/accounts/tickets)).

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P2.4-01 | Four signers sign one prepared transaction; `combine` sorts them by AccountID | rippled accepts it |
| P2.4-02 | `combine` with three signatures | refused before submit (`verifyMultisigned` fails) |
| T-A-12 | Pay Bob and refund Alice, both fully signed on slot S, submitted together | exactly one validates; the other gets `tefPAST_SEQ` |
| P2.4-03 | An exit fails with a `tec` result (payout account needs a destination tag) | slot S is used; the helper returns the new slot S+1 |
| P2.4-04 | Exit on a Ticket: a 4-of-4 `TicketCreate`, then both candidates on that ticket | one validates; the lock checker allows that ticket only after funding |
| T-A-18 | A single-signed `SignerListSet` or `SetRegularKey` after the lock | rejected |

**Think.** `combine(blobs)` runs `verifyMultisigned` inside it. `nextSlot(account)` reads the next sequence from `account_info` at `ledger_index: 'validated'` (xrpl.js `autofill` reads the current ledger, which includes queued transactions). Exits are signed with 5 to 10 times the base fee, so a fee spike cannot strand them.

**Test in all directions.** A race test with `fc.scheduledModelRun`: 4 signers and 2 exit candidates arrive in random orders.

**Think hard.** A fully signed exit with no expiry must never exist (DESIGN 7.5). `combine` refuses a transaction without `LastLedgerSequence`.

**Implement.** `src/multisig.ts`, about 80 lines.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 2.5 Full flows on a real ledger: T-I-01 and T-I-10

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L4 | Sonnet (Opus review) | high | L (16 h) | 2.2, 2.3, 2.4, and Phase 1 tasks 1.5 to 1.12, 1.15 and 1.16. There are no FROST stubs: the task starts when 1.15 is green. It does not depend on 1.17, because T-I-01 uses chip fixtures (task 2.9 adds the zero-knowledge path) |

**Research.** DESIGN 5.2 and 5.3, and the DESIGN Appendix B harness. Prototype fact from 24 Oct 2026: rippled 3.4.1 standalone already validated a 4-slot multisigned Payment with 2-of-3 FROST signatures, so the FROST signers here are expected to work; XRPL signers must be sorted by decoded AccountID.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| T-I-01 | the full flow, phases P0 to P8 in DESIGN 5.2 and 5.3, with scripted roles, chip fixture passports (`identityPolicy: "chip"`; the zero-knowledge flow is T-I-12 in task 2.9), four FROST DKGs with test-signing, the post-quantum bindings, onboarding attestations and the hybrid evidence envelopes. The DESIGN Appendix B harness ran an earlier, shorter flow; this test replaces it | every step `tesSUCCESS`; the gate passes with every code in DESIGN 6.17 (including `ONBOARDING_OK`, `IDS_DISTINCT`, `IDENTITY_POLICY_OK`, `PQ_BINDINGS_OK` and `SLOT_SETUP_OK`); both memos readable from validated ledgers; `delivered_amount` matches |
| T-I-10 | the full flow with secp256k1 operations accounts, and a lawyer from another firm replaced before release (4-of-4 `SignerListSet`, new share holders by FROST DKG, the lock checker run again) | every step `tesSUCCESS`; the checker passes after the replacement; the release is signed by the new group key |
| P2.5-01 | Record the `account_info` and `account_objects` snapshots at P6 and P7 | written to `packages/core/test/fixtures/ledger/` for E2E-P1 |
| P2.5-02 | Read the NFT issuer by decoding the NFTokenID from the mint metadata | equals `lawyerOpsA` |
| P2.5-03 | Every role signs through a FROST 2-of-3 signer (task 1.15) | the role script has no plain-key signer for any of the four slots; the test fails if one is found |
| P2.5-04 | The gate input is built from the validated ledger plus the evidence records of the run, with the `profile` set to `"production"` for chip fixtures | every code passes; the same input with one `frost.dkg.completed` test signature removed fails only `SLOT_SETUP_OK` |

**Think.** Write T-I-01 as a script of roles. Each role is a small object. Its signer is a FROST 2-of-3 slot: the role signs through a small FROST signer from task 1.15 (DESIGN 6.4), not with a plain key. There is no stub. If 1.15 is late, this task waits, because the slot keys, the bindings and the release signatures all depend on it. E2E-P3 and SYS-01 reuse the same role script.

**Test in all directions.** T-I-10 is the second full run: secp256k1 operations accounts and a replaced lawyer. Run T-I-01 with Ed25519 operations accounts, and T-I-10 with secp256k1 ones, so both curves are covered.

**Think hard.** T-I-01 is long. Split it into steps with named `test.step` blocks, so a failure names the phase and the step from DESIGN 7.3.

**Implement.** `test-int/full-flow.int.ts`, `test-int/replace-lawyer.int.ts` and `test-int/roles.ts`.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 2.6 Unhappy paths and ledger attacks

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L5 | Sonnet | high | L (8 h) | 2.5 |

**Research.** Each test's DESIGN row and expected engine code. Check the code in rippled's source where the doc names one.

Each DESIGN test that needs a real ledger:

**Test first.**

| ID | Scenario | Expected |
|---|---|---|
| T-I-02 | refund path | Alice is paid; the close succeeds |
| T-I-03 | expiry: no release before `CancelAfter`, then `EscrowCancel` | money back to Alice; the shell can close |
| T-I-05 | lawyer key rotation after a share is known to be stolen (new DKG, 4-of-4 `SignerListSet`, `Domain` set again to `01` + root + the single deal seal, new contract signatures, new NFT) | the checker passes with the `DOMAIN_IS_SEAL` rule |
| T-I-06 | dispute and award | the exit named by the award validates |
| T-I-07 | anchor memo on a flagless `AccountSet` at the base fee (set by hand) | `tesSUCCESS`; the memo reads back |
| T-I-09 | `AccountDelete` with 4 signers | charged one owner reserve |
| T-A-07 | a stranger's `EscrowFinish` with the right code | `tecNO_PERMISSION` |
| T-A-11 | finish and cancel at T-1, T and T+1 around `CancelAfter` | at T the finish works and the cancel fails; at T+1 the reverse |
| T-A-17 | a second `EscrowFinish` | `tecNO_TARGET` |
| T-A-26 | the NFT buy-offer drain, on a real ledger | the checker blocks before funds arrive |
| T-A-28b | another account submits the finish | `tecNO_PERMISSION` on the ledger; `RELEASER_SEALED` in the gate |
| P2.6-02 | after the rotation in T-I-05, a transaction signed by the old group key of the rotated slot | rejected by the ledger (the key is no longer in the signer list); a refresh alone would not have stopped it, which is why rotation is the only real revocation |
| P2.6-03 | an identity method change mid-deal (a switch from the zero-knowledge to the chip path): the 4-of-4 seal update is signed and `Domain` is set again | the checker passes with the new seal; when one slot refuses to sign, `Domain` stays and the refusal is recorded (a stall at release, O9, shows as a recorded refusal) |
| P2.6-01 | a stranger opens a trust line to the shell before step 5c (review finding 3) | the checker blocks; recorded as DQ-3 in IMPLEMENTATION Appendix B |

**Think.** One file per test ID. Each starts from a fresh funded deal built by the role script from task 2.5.

**Test in all directions.** Run each attack in every phase where it applies: before the lock, after the lock, and after funding.

**Think hard.** An attack test that passes because its setup failed is a false pass. Each test first asserts its setup state.

**Implement.** Files under `test-int/attacks/`.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 2.7 Watcher client

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L5 | Sonnet | high | M (6 h) | 2.2 |

**Research.** The xrpl.org `subscribe` and `account_tx` pages (forward paging with `marker`), and the Clio endpoints in section 4.5.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P2.7-01 | Subscribe to the `accounts` stream; act only on `validated: true` | proposed transactions are ignored |
| T-I-08 | disconnect for 50 ledgers, then reconnect | backfill finds every transaction once, in (ledger_index, TransactionIndex) order |
| P2.7-02 | the same transaction arrives twice (stream and backfill) | the handler sees it once (idempotent on hash) |
| P2.7-03 | two servers disagree on a validated ledger hash (on Testnet: `s.altnet` and the public Clio server) | an alert event is raised |
| P2.7-04 | Property: random disconnect points during 200 ledgers of traffic | the set of handled transactions equals the ledger's set |

**Think.** The client takes a `cursorStore` and a `handler`. Phase 3 gives it a Postgres cursor and an outbox handler. Here, tests use an in-memory cursor.

**Test in all directions.** P2.7-04 (random disconnects).

**Think hard.** `accounts_proposed` must never be used. A lint rule bans the string.

**Implement.** `src/watcher/` with `WatcherClient({ servers, accounts, cursorStore, handler })`.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 2.8 FROST-signed multisig on the ledger (T-I-11)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L13 | Sonnet | high | M (4 h) | 2.4, 2.5, 1.15 |

**Research.** DESIGN 6.4 and 12.2 (T-I-11); `research/r7-frost.md` (60 of 60 FROST signatures passed strict `zip215: false`; nobody has published FROST on XRPL multisign, so this task proves it). The rippled signature check for a multisigned entry in `Signers`. The slot policy fields in the 29-field deal seal (DESIGN 6.6). Prototype facts from 24 Oct 2026 (`scratchpad/proto-frost/`): rippled 3.4.1 standalone validated a 4-slot multisigned Payment with every signature a 2-of-3 FROST signature (`tesSUCCESS`); the noble calls are `DKG.round1/2/3`, `commit`, `signShare`, `verifyShare` and `aggregate`, with the group key at `public.commitments[0]`; DKG takes about 88 ms per slot and signing about 25 ms; `Signers` must be sorted by decoded AccountID; `xrpl` 5.3.0 plus noble static imports hit `ERR_REQUIRE_CYCLE_MODULE` on Node 22.14, so run on Node 24 and use a dynamic `import('xrpl')` if needed.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| T-I-11 | the lock steps, the exit and the close, each signed by four slots that are 2-of-3 FROST groups, on standalone and on Testnet (nightly) | every transaction `tesSUCCESS`; the slot public keys on the ledger are the group keys |
| P2.8-01 | all three pairs of shares (A+B, A+C, B+C) sign the same prepared transaction, for each slot | each aggregate signature verifies and rippled accepts it; the three runs give three valid but different signatures |
| P2.8-02 | one share alone tries to sign | refused by the signer before any nonce is used |
| P2.8-03 | a signature from a pair that is not in the slot policy (for example a client phone with the lawyer's HSM share) | rejected before submit by `combine`; nothing reaches the ledger |
| P2.8-04 | rippled accepts a FROST Ed25519 signature inside `Signers` | `tesSUCCESS`, with an Ed25519 key prefixed `ED` in the signer entry |
| P2.8-05 | the fee for a 4-signer transaction, and the order of `Signers` by AccountID | the same as the plain-key run in 2.4 (base fee x (1 + 4)); same sort order |
| P2.8-06 | the transaction signing hash is the one the FROST message is built from | the group signature verifies with plain Ed25519 `verify` (strict, `zip215: false`) |
| P2.8-07 | a signing nonce is used twice | the signer throws "signing nonces already used" and keeps no copy of the nonce |
| P2.8-08 | refresh a slot (task 1.15) with every remaining holder's deletion statement, then sign an exit; also try one old share plus one refreshed share | the group key and the signer-list entry are unchanged and the refreshed pairs sign; the old plus new pair does not combine into a valid signature; the refresh is recorded `COMPLETE` only with all deletion statements |
| P2.8-09 | repair: a new device rebuilds a share from two holders (T-U-30), then signs a ledger transaction with another holder | rippled accepts it under the unchanged group key |
| P2.8-10 | `Signers` order: four FROST slots whose AccountIDs sort differently from their slot names | `combine` sorts by decoded AccountID and rippled accepts the transaction |

**Think.** The multisig layer does not know it is talking to FROST. A slot signer is a `SignerPort` that returns one Ed25519 signature, and the signature happens to come from a 2-round FROST protocol. `combine` in task 2.4 stays unchanged. Only the signer behind the port changes: the role script from task 2.5 already uses the real signers from task 1.15 (it has no stubs).

**Test in all directions.** Run P2.8-01 for every slot (client A, client B, lawyer A, lawyer B), with the client pair taken from phone+passkey, phone+recovery agent and passkey+recovery agent, and the lawyer pair from console+HSM, console+partner and HSM+partner. Run T-I-11 with a slot whose group key was made by DKG and with one made by a trusted dealer, to prove both produce keys rippled accepts. Run an exit with a refreshed share set (task 1.15 refresh) and check the public key did not change.

**Think hard.** A key that works in unit tests may still fail on rippled, for example through a point-encoding or malleability check. P2.8-04 and P2.8-06 are the proof; if either fails, stop and report, because every slot in DESIGN 6.4 depends on it. Also check that the signing group key never changes between the lock and the close, or the `SignerListSet` on the ledger would not match the slots.

**Implement.** `test-int/frost-multisig.int.ts` and a `FrostSlotSigner` adapter in `test-int/roles.ts` that implements `SignerPort` over the task 1.15 functions (`commit`, `signShare`, `aggregate`). The tests need no change to `src/multisig.ts`; if a change is needed, record why.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

**As built (2.8).** Slot signers are FROST sessions, never `SignerPort` (OD-4): `signWithPair` in `test-int/frost/support.ts` takes an explicit pair and calls `checkMessage` before any nonce, and there is no `FrostSlotSigner` in `roles.ts`. Step 5g `AccountSet` with `asfDisableMaster` cannot be multisigned (rippled returns `tecNEED_MASTER_KEY`), so the shell's setup key signs 5g (DESIGN 5.2). In particular: T-I-11 passes on standalone on every pull request and on Testnet in one nightly run; every pair of shares works; the non-policy pair is refused before submit; the fee and the sort order match task 2.4.

### 2.9 Zero-knowledge flow on the ledger (T-I-12)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L15 | Sonnet | high | M (6 h) | 2.5, 1.17 |

**Research.** DESIGN 6.2, 6.10, 6.15 and 12.2 (T-I-12, T-U-32); `research/r6-zkpassport.md`. Prototype facts from 24 Oct 2026 (`scratchpad/proto-zk/`) that decide the method:
- ZKPassport's headless prover (`packages/e2e/src/prove.ts`, vendored by task 1.17 as `tools/zk-prove/`) proves in about 10 s and verifies in about 0.65 s, with 5 proofs of about 14.7 KB each. `createMockPassport` comes from `@zkpassport/utils` 0.40.0-beta.2 (nested under SDK 0.19.2; not in 0.39.0).
- Mock identifiers DIFFER per passport and per scope, and are stable for the same passport, domain and scope. The identifier depends on the domain string given to `new ZKPassport(domain)`, which is always `"legx.app"`.
- Mock certificates exist only in the Sepolia registry, so a mock proof carries chain ID 11155111 in its trust record and `devMode` is on.
- Offline verification with injected loaders (`verify({ config })` with `rpcUrl`, `circuitManifestUrlGenerator`, `packagedCircuitUrlGenerator`) returned `verified=true` with the network blocked.
- The result holds `proof`, `vkeyHash`, `version` and `committedInputs`. It does not hold the scope, so we store it.
- Whether `verify()` runs in a browser is unknown.

**Decision.** The headless prover works without a phone, so proofs can be made and re-verified by script. So:

1. Record mock proofs with the vendored prover (`tools/record-zk/` from task 1.17): one onboarding proof and one release proof for each party, bound to the test contract root, slot key and `presenceMsg` (with its `lawyerNonce`). Store the proofs, the query, the scope, the registry answer and the circuit files with each one in `packages/fixtures/zk/`. A hand run in the ZKPassport app (developer mode) covers the demo phones once, and is not needed in CI.
2. Every pull request: verify the recorded proofs through the real SDK (`@zkpassport/sdk`, pinned), offline, with loaders injected from the recorded registry answer and circuit files and the network blocked (T-U-32b). This checks a real proof on every run.
3. Nightly: regenerate the proofs with the prover and verify them against the live Sepolia registry with our own RPC and `verifierMode: "local"`, so an SDK change, a registry rotation or a circuit change shows up within a day.
4. A `ZkVerifierPort` replay adapter fed by recorded results stays for unit tests and for the fault cases that need a verdict the real SDK would not give.

**Trade-off.** Offline verification from recorded inputs does not notice a registry change by itself, so that is the nightly run's job (up to one day late). Recorded proofs age with the registry root, but the recorded root travels with the proof, so they stay verifiable offline. Re-recording is a script, not a phone. The one thing that still needs a phone and a real passport is the real (non-mock) identifier formula (T-U-28c). Task 1.17 owns the recording tools and the offline re-verification test; this task owns the use of them on a ledger.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| T-I-12 | the full flow (P0 to P8) with identity policy `"zk"`: onboarding proofs at P5 (verified by the client's own lawyer, with the disclosure sealed to that lawyer), release proofs at P7, using mock passports (offline real-SDK verification on pull requests) | every step `tesSUCCESS`; the gate passes with every DESIGN 6.17 code; attestations carry `method: "zkpassport"` and a trust record; `C_side` values are the salted zero-knowledge commitments; the domain in every request is `legx.app` |
| P2.9-01 | nightly: every recorded proof verified through the real SDK in `devMode` against Sepolia with `verifierMode: "local"` | all verify; each verdict equals the recorded verdict and the recorded trust record |
| P2.9-02 | the replay adapter is asked about a proof with no recorded result | throws `ZK_RESULT_MISSING` (the same code core's `verifyZk` returns); it never answers "valid" by default |
| P2.9-03 | `devMode` proof offered to a verifier in the production profile | refused (DESIGN 6.10: `devMode` only in the demo profile) |
| P2.9-04 | the release proof's scope or bound `presenceMsg` is changed in a copy | rejected by the verifier; the release is not signed and the escrow stays |
| P2.9-05 | the release identifier differs from the onboarding identifier for the same party | rejected (same scope must give the same identifier) |
| P2.9-06 | identity policy `"zk-or-chip"` with one party on a mock passport and one on the chip fixture | the flow completes; each attestation shows its own method |
| P2.9-07 | the ledger memos and the escrow contain no passport data | only `C_side`, hashes and the attestation digest appear on the ledger |
| P2.9-08 | two parties use the same mock passport | the gate fails only `IDS_DISTINCT` (the identifiers are equal even though the salts differ) |
| P2.9-09 | the same T-I-12 records, run through the gate in the production profile | refused: the trust records show chain ID 11155111, a mock identifier type and `dev_mode: true` |
| P2.9-10 | switching identity method mid-deal (to the chip path) | needs a 4-of-4 seal update, as in P2.6-03 |

**Think.** The zero-knowledge check sits in the gate and the attestation, not on the ledger, so the ledger sees only the final signed transaction and the memos. The point of this test is that the whole flow still ends in a valid release when the identity method is zero-knowledge. Mock identifiers differ per passport, so two parties on two different mock passports pass `IDS_DISTINCT` without any special switch (P2.9-08 tests the opposite case).

**Test in all directions.** Run T-I-12 on standalone on every pull request with offline real-SDK verification. Run it nightly on standalone against the live Sepolia registry and on Testnet. Run the failure cases (P2.9-02 to 05) in both modes. Record for each nightly run the SDK version, the registry root and the circuit IDs.

**Think hard.** A replay adapter that returns "valid" for an unknown proof makes every test pass for nothing; P2.9-02 pins that. The other risk is drift: recorded results and trust records must be regenerated by the nightly job, never written by hand, and the job fails if a recorded result differs from a fresh one. A mock proof must never pass in production (P2.9-09).

**Implement.** `test-int/zk-flow.int.ts`, fixtures in `packages/fixtures/zk/` (owned by task 1.17), and a nightly job file `ci/nightly-zk.yml` that runs P2.9-01 and rewrites the recorded results as an artifact for review. Use CommonJS `require` or a bundler for the SDK, because a plain ESM import fails under Node.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2. In particular: T-I-12 passes with offline real-SDK verification on every pull request; the nightly run verifies every recorded proof against Sepolia; the trade-off above is written in the test README.

**As built (2.9).** The adapter in `services/zk-verifier` accepts only the domain `legx.app` and has a one-day `validity`. So the recorded `alice-other-domain` set cannot be replayed through it live (the refusal is `WRONG_DOMAIN`), and the nightly P2.9-01 fixes the clock at each set's `recordedAt`. The nightly job (`zk` in `.github/workflows/nightly.yml`, `LEGX_LIVE_SEPOLIA=1`, optional `SEPOLIA_RPC_URL`) must re-record with `tools/record-zk/` when the registry changes. The recorded sets are `devMode` on Sepolia with mock identifiers, so the production profile refuses them (`DEVMODE_REFUSED`) and this flow runs only in the demo profile.

### Phase 2 end-to-end suite (E2E-P2)

| ID | Scenario | Expected |
|---|---|---|
| E2E-P2-01 | T-I-01 on standalone, then the watcher replays the whole deal from ledger history | the watcher's event list equals the transactions T-I-01 sent |
| E2E-P2-02 | T-I-01 on Testnet (nightly, T-N-01 part 1) | every step validated; explorer links printed |
| E2E-P2-03 | All of 2.6 in one run on a fresh ledger | all pass in under 10 minutes on CI |
| E2E-P2-04 | T-I-10 on standalone (secp256k1 operations accounts, lawyer replaced before release) | every step `tesSUCCESS`; the checker passes after the replacement |
| E2E-P2-05 | T-I-11 on standalone, then on Testnet (nightly) | every FROST-signed transaction validates; every pair of shares works |
| E2E-P2-06 | T-I-12 on standalone with offline real-SDK verification; nightly against the live Sepolia registry | the full flow passes; every recorded proof verifies |

**Phase 2 exit gate (G2):** E2E-P2-01, 03, 04, 05 (standalone part) and 06 (offline part) green on every pull request; E2E-P2-02, E2E-P2-05 (Testnet part) and E2E-P2-06 (live Sepolia part) green on at least one nightly run; no plain-key signer remains in the role script.

---

## 7. Phase 3: Platform services

**Goal.** The services in DESIGN 4.1 that hold no party keys and no money: the coordinator (with the FROST relay), the verifier service, the evidence service, the ledger watcher, the share-holder services (recovery agent and firm HSM co-signer), the zero-knowledge verifier adapter, post-quantum signing, plus the database, observability, the mock bar registry, the offline verifier CLI, and one server process that runs them all for the demo.

**Owns:** `packages/db/`, `packages/signer/`, `packages/storage/`, `packages/observability/`, `services/*`, `apps/server/`, `apps/mock-bar-registry/`, `tools/verifier-cli/`, `services/frost-relay/`, `services/recovery-agent/`, `services/hsm-cosigner/`, `packages/zk/`.

**Starts:** after G0. Services code against `LedgerPort` with a stub until G2, then switch to `@legx/xrpl`. **Covers DESIGN:** 4.1, 4.2, 5.1 (persisted), 7.5, 6.3, 6.4, 6.10, 6.13, 8.1 to 8.10, 9, 10.2, and milestones M3 and M4.

**Shape.** Each service is a library with a `register(app, deps)` function. `apps/server` composes all of them into one Fastify process for the demo. Production can run each one alone with the same code. Every outside dependency is a port from `packages/contracts`. The demo profile and the production profile only swap the port implementations:

| Port | Production | Demo profile |
|---|---|---|
| `SignerPort`, hybrid (verifier attestation key, verifier issuer key, evidence log key; returns an Ed25519 and an ML-DSA-65 signature) | AWS KMS: `ML_DSA_65` with `EXTERNAL_MU`, plus Ed25519 (or Vault Transit) | `FileSigner` with a local file holding both keys, marked demo only |
| `ObjectStorePort` (WORM evidence) | S3 with Object Lock, compliance mode | a local folder, write-once by convention and checked by hash |
| `TransparencyLogPort` | Trillian Tessera sidecar | the in-process RFC 9162 tree from `@legx/core` |
| `TsaPort` (RFC 3161) | a commercial timestamp authority | a free public authority, optional; the ledger `close_time` is the second clock |
| `ZkVerifierPort` (checks ZKPassport proofs) | the ZKPassport SDK (`@zkpassport/sdk` 0.19.x), `verifierMode: "local"`, the domain `"legx.app"` passed explicitly, our own Ethereum RPC, a pinned version; the gate refuses Sepolia, mock identifier types and `devMode` | the same SDK with `devMode: true` and the Sepolia registry (mock passports); tests use a replay adapter that serves recorded results and injected loaders |
| `FrostRelayPort` (forwards FROST DKG and signing messages between share holders) | the relay in the coordinator (task 3.9) | the same relay, in process; tests use an in-memory relay |
| `BarRegistryAdapter` | per-jurisdiction adapters, plus `manual` | `demo` adapter that reads the mock bar registry |
| `LedgerPort` | Mainnet only after legal review (DESIGN O6) | XRPL Testnet, with standalone as the offline fallback |

### 3.1 Database: schema, migrations and repositories (`packages/db`)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L6 | Sonnet | medium | M (6 h) | G0 |

**Research.** DESIGN 9, all 18 tables, including the new `deal_key` columns (`pq_key_hash`, `pq_binding_sigs`, `pq_cross_sig`) and the `zk_proof` and `enrollment_key` tables. DESIGN 6.3 and 6.10 for what they hold. Postgres 18 notes (section 4.3): `uuidv7()`, and the Docker volume path change to `/var/lib/postgresql`. Kysely with the `pg` dialect and the PGlite dialect. The append-only pattern: `REVOKE` plus a trigger.

**Test first.** Unit tests run on PGlite (fast, in-process). Tests marked `[pg]` run on a real Postgres 18 container (testcontainers), because PGlite allows one connection and has no roles.

| ID | Test | Expected |
|---|---|---|
| P3.1-01 | All migrations apply on an empty database, then roll forward twice | idempotent; the schema equals a committed snapshot (`pg_dump --schema-only`) |
| P3.1-02 `[pg]` | As role `app_rw`: `UPDATE` or `DELETE` on `evidence_event`, `evidence_log_entry`, `bar_verification`, `bar_deal_link`, `attorney_credential`, `passport_attestation`, `release_gate`, `zk_proof`, `enrollment_key` | refused (both the `REVOKE` and the trigger fire) |
| P3.1-03 | `deal.releaser_account` different from `lawyer_ops_b` | refused by the check constraint |
| P3.1-04 | `deal_key` for a lawyer without `contract_sig` or `ops_account` | refused |
| P3.1-05 `[pg]` | Two writers insert `evidence_event` with the same `(deal_id, seq)` at the same time | exactly one wins; the other gets a unique violation, and the repository maps it to `SeqTaken` |
| P3.1-06 | The same `leaf_hash` twice | the second insert is a no-op returning the first row (idempotency) |
| P3.1-07 | No column anywhere has a name or type that could hold passport data (`dg1`, `sod`, `mrz`, `passport` other than `passport_attestation`) | a schema scan finds none |
| P3.1-09 | `deal_key` has the columns `slot_policy`, `pq_key_hash`, `pq_binding_sigs` (jsonb), `pq_cross_sig` and `id_method`. Insert a row with `id_method` other than `zkpassport` or `nfc-chip`, a `pq_key_hash` that is not 32 bytes, or a `pq_binding_sigs` that does not hold exactly two signatures | the row is refused by the check constraints |
| P3.1-10 `[pg]` | The new tables are append-only: as role `app_rw`, `UPDATE` or `DELETE` on `zk_proof` and `enrollment_key` | refused (both the `REVOKE` and the trigger fire) |
| P3.1-11 | `zk_proof` holds no passport data: its columns are only the stage, the proof, the registry roots (which also hold the trust record of task 3.11: chain ID, block, registry address, root, circuit manifest version, verification-key hashes, identifier type, `dev_mode`) and the identifier hash. Insert a row with an extra field through the repository | the schema scan finds no `dg1`, `sod`, `mrz`, name, number or birth-date column; the repository rejects the extra field |
| P3.1-12 | `enrollment_key` rows: one Ed25519 and one ML-DSA-65 public key per share holder, unique per `(deal_id, role, holder)` | a duplicate or a missing half is refused |
| P3.1-13 | The migration covers **every** table of DESIGN 9: `deal`, `deal_key`, `lawyer`, `bar_verification`, `attorney_credential`, `bar_deal_link`, `passport_attestation`, `zk_proof`, `enrollment_key`, `release_gate`, `signature_request`, `signature`, `evidence_event`, `evidence_log_entry`, `ledger_observation`, `watcher_cursor`, `outbox` and `checkpoint_anchor` | a test lists the tables of DESIGN 9 and the tables of the schema snapshot; the two sets are equal (plus `deal_head`, task 3.1 below) |
| P3.1-14 | `enrollment_key` rows are never replaced: a second row for the same `(slot, holder_role)` with a different key is a new row with a new `key_id`, and the evidence log records the key hash before the key is used | the old row is still there; a key with no evidence entry is refused for use (T-U-29 at table level) |
| P3.1-08 `[pg]` | The outbox: `FOR UPDATE SKIP LOCKED` with 4 workers on 1,000 rows | each row is processed exactly once |

**Think.** Repositories return plain objects typed from `packages/contracts`. No Kysely type leaks out of `packages/db`. Add the `deal_key` columns and the `zk_proof` and `enrollment_key` tables exactly as DESIGN 9 lists them. The signed key lists of service holders (task 3.9 and 3.10) are stored as evidence objects, not as a new table. Add one table that DESIGN 9 does not list: `deal_head (deal_id, head_seq, head_hash)`, a small mutable row per deal that hands out the gap-free `seq` under `FOR UPDATE` (task 3.4). It is working state, not evidence. Also add `deal_id` and `seq` columns to DESIGN's `outbox` table, with an index on `(deal_id, seq)`, because the live-update replay reads by them (task 3.7). Record both changes in DESIGN 9 when this task merges.

**Test in all directions.** Run the whole repository suite on PGlite and on Postgres 18; the results must match. Property: random sequences of inserts never break the append-only rule.

**Think hard.** The per-deal `seq` must be gap-free and assigned inside one transaction (DESIGN 8.1). Do not use a global `bigserial` as the push cursor: a value is assigned at insert, not at commit, so a reader can skip a row forever. Use the per-deal `seq` as the cursor.

**Implement.** SQL migrations for all of DESIGN 9, including the tables `lawyer`, `bar_verification`, `attorney_credential`, `bar_deal_link`, `passport_attestation` and `release_gate`, the new `deal_key` columns, `zk_proof` and `enrollment_key`. Every append-only table (`evidence_event`, `evidence_log_entry`, `bar_verification`, `attorney_credential`, `bar_deal_link`, `passport_attestation`, `release_gate`, `zk_proof`, `enrollment_key`) gets the same `REVOKE` and trigger pattern. Kysely types generated from the schema. One repository per table.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 3.2 Coordinator: persisted deal state machine and API

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L6 | Sonnet (Opus for the review) | high | L (2 days) | 3.1, 1.14, and 2.2 to 2.4 for the real ledger |

**Research.** DESIGN 5.1 to 5.4 and 7.5. oRPC contract-first routing with Fastify (section 4.3). The rule that signed-request routes must read the raw body: the oRPC Fastify adapter bypasses Fastify's body parsing, so those routes stay plain Fastify routes.

**Test first.** Fastify `inject()` for all API tests: no network, full app.

| ID | Test | Expected |
|---|---|---|
| P3.2-01 | Create a deal; each role joins with its public data; the coordinator computes the deal seal (29 fields) and serves the same public data to all four | every role's recomputed seal equals the coordinator's |
| P3.2-02 | Every route checks its request against the contract schema | a bad request gets 400 with the field path |
| P3.2-03 | Every state change goes through `machine.step` and is stored in the same transaction as its evidence event and outbox row | an injected failure after the state write rolls everything back |
| P3.2-04 | Signature request for an exit: `autofill(tx, 4)`, `LastLedgerSequence` + 1800, stored with expiry | the request is listed with its expiry ledger |
| P3.2-05 | Four signer blobs arrive in any order, some twice | combined once; `verifyMultisigned` passes; submitted once |
| P3.2-06 | A blob that signs a different transaction (changed amount) | rejected; the other blobs stay valid |
| P3.2-07 | The request expires (`LastLedgerSequence` passed) | marked expired; a new request is built; old blobs are refused |
| P3.2-08 | Slot S: record it at funding; both exit candidates use it; a `tec` result moves the slot to S+1 and voids both | as DESIGN 7.5 |
| P3.2-09 | The coordinator never accepts or stores a private key, a release code or a raw passport | a schema test: no route accepts such a field; a fuzz test posts such fields and checks they are rejected and never stored |
| T-P-06 | Model-based test: fast-check `commands` drive the API (join, sign, lock, verify, release, exit, attacks) against a standalone ledger; after each command the model state equals the stored state | holds for 200 runs |
| P3.2-10 | Restart in the middle of every step (kill the process between any two awaited calls) | the deal resumes; nothing is signed or submitted twice (DESIGN M3) |
| P3.2-11 | The coordinator runs the lock checker and the release gate itself before it relays release records (DESIGN 10.2) | a gate failure stops the relay |
| P3.2-12 | The gate at the coordinator, with `identityPolicy: "chip"` and a ZK attestation; and with an attestation whose method differs from the sealed `idMethod_side` or from the onboarding method | `IDENTITY_POLICY_OK` fails in each case and the relay stops |
| P3.2-13 | One test for each new gate code through the coordinator: `ONBOARDING_OK`, `IDS_DISTINCT`, `IDENTITY_POLICY_OK`, `PQ_BINDINGS_OK`, `SLOT_SETUP_OK` | each code fails on its own bad input and the relay stops; the stored gate record lists all 15 codes |
| P3.2-14 | A release attestation whose `face_match_passed` is false (the face match is on by default) | `PASSPORT_*_OK` fails; no relay |

**Think.** Keep the pure transition table from task 1.14. Persist one `state` column. Rebuild nothing from snapshots: the evidence log is the history, and the `deal` row is the current state.

**Test in all directions.** T-P-06 (model-based). P3.2-10 (kills at random points). Fuzz every route with schema-shaped random input.

**Think hard.** Duplicate delivery is normal (phones retry). Every write is keyed: signature blobs by `(request_id, role)`, events by `leaf_hash`, ledger observations by `tx_hash`. A retry returns the first result.

**Implement.** `services/coordinator/` with `routes.ts` (oRPC), `deal.ts` (state changes in one transaction), `signatures.ts` and `slot.ts`.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 3.3 Verifier service and the mock bar registry

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L7 | Sonnet | medium | M (6 h) | 3.1, 1.10, 2.3, 3.6 (SignerPort) |

**Research.** DESIGN 6.16, D19 and D23. XRPL credential rules (`tecNO_TARGET` for a missing subject, 64-byte type, 256-byte URI, expiry behavior).

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P3.3-01 | The `BarRegistryAdapter` contract tests run against the `manual` adapter and the `demo` adapter | both pass the same suite |
| P3.3-02 | `demo` adapter against the mock registry: an active lawyer, a struck-off lawyer, an unknown bar number | `active`, `not_active`, `not_found` |
| P3.3-03 | `manual` adapter: an operator uploads a saved registry page | its SHA-256 goes into `evidence_sha256` |
| P3.3-04 | Onboarding order: issue the credential before the operations account exists | refused by the service before any ledger call (it checks `account_info` first) |
| P3.3-05 | Full onboarding on the standalone ledger: verify, sign `BarVerification`, step 0a, step 0b | `LEGX_ATTORNEY` is on the ledger with `lsfAccepted`, the right URI and expiry |
| P3.3-06 | Re-verify after 30 days: `CredentialDelete`, new create, new accept, new `BarDealLink` | the gate passes again (T-U-17h at service level) |
| P3.3-07 | Per-deal link: the lawyer sends the per-deal bar salt; the service opens `LC` and signs `BarDealLink` | verifies in the gate |
| P3.3-08 | The salt is not stored after the link is signed | a database and log scan finds no salt |
| P3.3-09 | The mock registry shows "DEMO REGISTRY" on every page and in every JSON response | true |

**Think.** The service is a thin pipeline: adapter, then sign, then ledger steps 0a and 0b, then events. Each step is idempotent, and pg-boss resumes it after a crash.

**Test in all directions.** Run the adapter contract suite against a deliberately broken adapter (time-outs, garbage HTML), to see clean errors.

**Think hard.** The verifier key is the root of lawyer trust. It signs only through `SignerPort`, and every signature it makes is logged as an evidence event.

**Implement the mock registry** (`apps/mock-bar-registry`, Haiku, low effort, 2 h): a tiny static site plus a JSON endpoint, with 4 fake lawyers (2 active, 1 struck off, 1 with a lapsed license). It never claims to be a real registry.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 3.4 Evidence service

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L7 | Sonnet (Opus review) | high | L (2 days) | 3.1, 1.13, 3.6 (test P3.4-15 is written now and runs once 3.11 and 3.12 have merged; 3.12 itself depends on 3.4) |

**Research.** DESIGN 8.1 to 8.10. Section 4.6. Facts checked on 24 Oct 2026:
- DSSE v1.0.2 has not changed its PAE. Keep our own 10-line `pae()`; use `@sigstore/core`'s `preAuthEncoding` only as a test cross-check.
- Trillian Tessera v1.0.4 is a Go library, not a server. Its `cmd/conformance/posix` binary runs as a sidecar: `POST /add` with the raw entry returns the index as text, and the entry appears in the checkpoint about 1 second later, so the adapter polls. Reads are tlog-tiles static files (`/checkpoint`, `/tile/...`). Keep our in-process tree's checkpoint in the exact C2SP signed-note format, so Tessera can replace it without changing verifiers. `@cloudflare/signed-note-wasm` and `@cloudflare/tlog-tiles-wasm` verify only; use them as test cross-checks.
- RFC 3161: write our own client on PKI.js `TimeStampReq` and `TimeStampResp` (other npm clients are stale). Free authorities that answered on 24 Oct 2026: DigiCert, Apple, SSL.com, Sectigo (wants 15 s or more between requests), Certum, sigstore, freetsa (1 request per second, no service level) and GlobalSign. Use two independent ones; Entrust is now signed by Sectigo, so it is not independent.
- AWS KMS Ed25519 (since 7 Nov 2025, key spec `ECC_NIST_EDWARDS25519`, `ED25519_SHA_512`, `MessageType: RAW`) signs raw messages of up to 4,096 bytes. AWS KMS `ML_DSA_65` signs RAW messages of up to 4 KB too; longer messages need `EXTERNAL_MU`. Every envelope is hybrid-signed (Ed25519 + ML-DSA-65, both required, `sig_algs` in the payload; DESIGN 6.13 and 8.1), so each PAE either stays under 4 KB or goes through `EXTERNAL_MU` (task 3.12). Checkpoints are hybrid: C2SP lines 0x01 (Ed25519) and 0x06 (timestamped ML-DSA-44). See research note r8-pq.md.
- RFC 8785: `canonicalize` 5.1.0, pinned exactly (its output changed across three majors in 2026).

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P3.4-01 | `nextSeq(dealId)` then append: the signer puts `seq` and `prev_hash` inside the payload and signs | stored; the chain verifies (T-U-10 at service level) |
| P3.4-02 `[pg]` | Two signers race for the same `seq` | one wins; the other gets `SeqTaken`, refetches the head, signs again, and is stored next |
| P3.4-03 | An envelope is stored and returned byte for byte | its SHA-256 equals `leaf_hash` (never re-serialized) |
| P3.4-04 | Every PAE we sign goes through `EXTERNAL_MU`, or the PAE is under 4,096 bytes | a property test over every event kind: no RAW sign call ever gets more than 4,096 bytes |
| P3.4-05 | The Merkle log integrates each leaf; `evidence_log_entry` gets the index in a separate insert | inclusion proofs verify |
| P3.4-06 | A hybrid checkpoint every 10 minutes and at once on legal milestones (contract signed, lawyer approval, dispute opened) | the checkpoint carries the 0x01 and 0x06 lines; an anchor `AccountSet` with the `legx/ckpt/v1` memo validates (T-I-07 path) |
| P3.4-07 | RFC 3161: the TSA answers | the token verifies against the checkpoint hash and the TSA chain |
| P3.4-07b | Two authorities are asked; one is slow | the first good token is stored; the second is stored when it arrives; the rate limits per authority are respected |
| P3.4-07c | Our checkpoint parses and verifies with `@cloudflare/signed-note-wasm` (the 0x01 line; the 0x06 line is checked by our own verifier) | passes (format cross-check) |
| P3.4-08 | RFC 3161: the TSA is down | the anchor still happens; the missing token is retried later by pg-boss; the dashboard shows "time stamp pending" |
| P3.4-09 | WORM store: the same object written twice with different bytes | refused; with the same bytes, a no-op |
| P3.4-10 | Bundle for a deal (DESIGN 8.8, every item) | a deterministic ZIP: two builds give the same bytes |
| P3.4-14 | Every envelope the service stores is hybrid-signed: take a stored envelope and strip the ML-DSA-65 signature (then the Ed25519 one) | the verifier rejects both (T-U-24 at service level); the append is refused if either signature is missing |
| P3.4-15 (needs 3.11 and 3.12) | The bundle includes the zero-knowledge proofs, the trust records, the registry roots and circuit IDs, the FROST records (`frost.dkg.completed`, `frost.signed`, `frost.refreshed`) and the post-quantum bindings (`pq.bound`) | all four are present, each with its checks; the CLI verifies them offline |
| P3.4-16 | A hybrid checkpoint with the 0x06 line removed or altered, checked by our verifier and by a standard signed-note verifier | our verifier fails and names the missing line; the standard verifier alone passes it (it ignores unknown keys), which is why our verifier requires both lines (DESIGN 6.13) |
| P3.4-11 | Client records view: a request signed by Alice's x-key | returns Alice's records only, each with its three checks |
| T-A-31 | Bob, Lawyer B, or an unsigned request asks for Alice's records | refused (401 or 403) |
| P3.4-12 | A replayed signed request (same nonce) or one older than 5 minutes by ledger time | refused |
| P3.4-13 | Tessera adapter, production profile: add a leaf, read the checkpoint and the inclusion proof from the tiles API | verifies with the same core functions as the in-process tree |

**Think.** Signing goes through the hybrid `SignerPort` (tasks 3.6 and 3.12). Four modules: `events` (append and chain), `log` (Merkle tree and checkpoints), `anchor` (ledger and RFC 3161), `bundle` (ZIP and the records view).

**Test in all directions.** P3.4-02 under `fc.scheduledModelRun`. Bundle determinism across machines: build in Docker and locally, then compare the bytes.

**Think hard.** A database administrator can rewrite Postgres (DESIGN 8.9). The WORM copy, the log and the ledger anchors must each catch a rewrite. A test edits a row directly as the superuser and expects the next verification to fail.

**Implement.** `services/evidence/` with the four modules. The gap-free `seq` comes from a per-deal row lock, not a sequence object:
```sql
-- inside the same transaction as the state change
SELECT head_seq, head_hash FROM deal_head WHERE deal_id = $1 FOR UPDATE;
INSERT INTO evidence_event (event_id, deal_id, seq, prev_hash, envelope, leaf_hash)
VALUES (uuidv7(), $1, $2, $3, $4, $5);               -- $2 = head_seq + 1, signed inside the envelope
UPDATE deal_head SET head_seq = $2, head_hash = $5 WHERE deal_id = $1;
INSERT INTO outbox (id, deal_id, seq, topic, payload) VALUES (uuidv7(), $1, $2, 'deal.event', $4);
SELECT pg_notify('deal_events', $1::text);
```
`deal_head` is a small mutable table (not evidence). The evidence rows stay append-only. When a client signs ahead with a `seq` it fetched earlier and loses the race, the unique key `(deal_id, seq)` rejects it, and the client signs again with the new head.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 3.5 Ledger watcher service

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L8 | Sonnet | high | M (6 h) | 3.1, 2.7 |

**Research.** DESIGN 8.5 and the client from task 2.7.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P3.5-01 `[pg]` | For each validated transaction: insert the observation (on conflict do nothing), insert an outbox row, move the cursor, in one database transaction | a crash between any two of them leaves all three or none |
| T-I-08 | Disconnect for 50 ledgers | the backfill finds every transaction once |
| P3.5-02 | After funding, the watcher runs the lock checker on every new validated ledger for the deal wallet, with the exit ticket allowed | a planted change raises an alert and an evidence event (DESIGN 10.2) |
| P3.5-03 | Two servers (a rippled node and Clio) disagree | an alert, and decisions pause until they agree |

**Think.** The service connects the client to Postgres: a cursor table, an observations table and the outbox.

**Test in all directions.** Kill the process between each pair of the three writes in P3.5-01.

**Think hard.** Running the checker after funding fails on the missing quarantine escrow (DQ-1 in IMPLEMENTATION Appendix B). Until the design answers, the watcher runs it with a `phase: 'funded'` option that skips only the escrow rules. Record this as a temporary rule in the code, linked to DQ-1.

**Implement.** `services/watcher/`, about 150 lines on top of the client.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 3.6 Signer, storage and observability packages

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L8 | Sonnet | medium | M (6 h) | G0 |

**Research.** AWS KMS Ed25519 and ML-DSA API and limits (task 3.12); MinIO with Object Lock; the OTel 2.x Node SDK and `@fastify/otel`.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P3.6-01 | `SignerPort` contract tests run against `FileSigner` and `KmsSigner` (KMS against a local KMS emulator, or a recorded response) | the same suite passes; both the Ed25519 and the ML-DSA-65 signatures verify (the Ed25519 one with `verifyXrplKeySig`) |
| P3.6-02 | `FileSigner` refuses to start unless the profile is `demo` | true |
| P3.6-03 | `ObjectStorePort` contract tests on the local folder and on S3 (MinIO with Object Lock in a container) | the same suite passes; a delete before retention is refused on S3 |
| P3.6-04 | One span per new step (DESIGN 8.6 table), with `deal.id` and the trace ID | an in-memory exporter sees each span |
| T-A-32 | A full API flow with a fixture passport; then search every exported span and every log line for MRZ text, DG1 bytes, salts and keys | none found |
| P3.6-05 | The Collector redaction config: an attribute not on the allow-list | dropped |

**Think.** Each port has one contract test suite. Every implementation must pass it.

**Test in all directions.** The contract suites run against every implementation, including the demo ones.

**Think hard.** A demo implementation running in production is a silent security hole. P3.6-02 and P3.7-05 prevent it.

**Implement.** `packages/signer`, `packages/storage` and `packages/observability`.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 3.7 Server composition and live updates (`apps/server`)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L6 | Sonnet | medium | M (6 h) | 3.2 to 3.6, 3.9 to 3.12 |

**Research.** `@fastify/websocket`; Postgres LISTEN and NOTIFY on a dedicated connection.

**Live updates over WebSocket.** The client sends `{ subscribe: dealId, after: seq }`. The server replays every outbox row for that deal after `seq` from Postgres, then pushes new rows as `pg_notify` wakes it. WebSocket is used, not server-sent events, because one of the two tunnels in section 4.4 does not carry server-sent events.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P3.7-01 | `pnpm dev` starts the server, Postgres and the mock registry; `GET /health` lists each port and its profile | all `ok` |
| P3.7-02 | A client subscribes after `seq` 5 | it gets 6, 7, ... with no gap and no repeat |
| P3.7-03 | The client drops and reconnects with its last `seq` | no gap; no repeat |
| P3.7-04 | 3 clients and 100 events per second for 1 minute | every client sees every event in order |
| P3.7-05 | The profile is `production` and any demo port is configured | the server refuses to start |
| P3.7-06 | Wiring: `apps/server` composes the FROST relay (3.9), the recovery agent (3.9), the firm HSM co-signer (3.10), the ZK verifier adapter (3.11) and the post-quantum signer and jobs (3.12); `GET /health` lists each one | all five report `ok`; a full DKG, a FROST signature, a ZK verify and a hybrid checkpoint each go through the composed server, not through a unit-test harness |
| P3.7-07 | The profile is `production` and the ZK adapter has `devMode`, a Sepolia RPC or a mock identifier type configured | the server refuses to start |

**Think.** The wiring test matters because every Phase 3 service passes alone and can still fail when composed (a missing port, a wrong profile). One in-memory map from deal ID to sockets. NOTIFY only wakes the server; the data always comes from the outbox query.

**Test in all directions.** P3.7-04 (load). Random reconnects driven by fast-check.

**Think hard.** A slow client must not block the others. Each socket has a bounded send queue. When it overflows, the server closes the socket, and the client subscribes again from its last `seq`.

**Implement.** `apps/server/src/main.ts` composes the services; `ws.ts` is about 80 lines:
```ts
socket.on('message', async raw => {
  const { subscribe: dealId, after } = SubscribeMsg.parse(JSON.parse(String(raw)));
  if (!canRead(socket.user, dealId)) return socket.close(4403);
  let last = after;
  const pump = serial(async () => {                  // replay, then live: one code path; serial() runs one call at a time
    for (const row of await outbox.after(dealId, last, 500)) { send(socket, row); last = row.seq; }
  });
  await pump();
  listeners.add(dealId, pump);                       // NOTIFY only wakes pump(); data always comes from the table
  socket.on('close', () => listeners.remove(dealId, pump));
});
```

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 3.8 Offline verifier CLI for arbitrators (`tools/verifier-cli`)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L7 | Sonnet | medium | M (4 h) | 3.4, 1.12, 3.11, 3.12 |

**Research.** DESIGN 8.8 and the bundle layout from task 3.4.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P3.8-01 | `legx-verify bundle.zip` on a good bundle | exit code 0 and a plain report: signatures, chain, Merkle proofs, anchors, time stamps, the signed contract, bindings, bar records, attestations, and a rerun of the release gate |
| P3.8-02 | One byte changed anywhere in the bundle | exit code 1, naming the file and the check |
| P3.8-03 | Run with networking blocked (a test that makes `fetch` and sockets throw) | still passes (DESIGN 8.8) |
| P3.8-04 | Clause proof: the arbitrator checks one clause against the contract root | passes; a changed clause fails |
| P3.8-05 | Offline ZK re-verification: the CLI re-verifies each ZKPassport proof in the bundle through `verify({config})` with loaders injected from the bundle (`rpcUrl`, `circuitManifestUrlGenerator`, `packagedCircuitUrlGenerator`), with `fetch` and sockets throwing | each proof gives `verified = true` from the recorded registry answer and circuit files alone (T-U-32 at CLI level) |
| P3.8-06 | The CLI on a bundle whose trust record shows chain 11155111 (Sepolia), a mock identifier type or `dev_mode: true`, in production mode | refused with the reason; the demo mode warns instead |
| P3.8-07 | A bundle whose checkpoint has the 0x06 line stripped, or whose envelope has no ML-DSA-65 signature | exit code 1, naming the checkpoint or envelope |

**Think.** The CLI imports only `@legx/core`, the bundle reader and the injected-loader wrapper of `packages/zk/`. It has no network modules.

**Test in all directions.** Run every bundle produced in Phase 6 through it (SYS-I3). Fuzz the ZIP reader with corrupted archives.

**Think hard.** An arbitrator may run it years later. So the CLI and its dependencies are bundled into one file and shipped inside the evidence bundle (DESIGN 8.8, item 11).

**Implement.** `tools/verifier-cli/`: one command, with a text report and a JSON report.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 3.9 FROST relay in the coordinator, and the recovery agent service

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L16 | Sonnet | high | L (2 days) | 3.2, 1.15, 1.16 (recovery uses the `ZkVerifierPort` contract from 1.2 with a replay stub; task 3.11 supplies the real adapter) |

**Research.** DESIGN 6.3 (the key directory) and 6.4 (key generation rules, signing rules, recovery, refresh, repair and rotation). Research note r7-frost.md: noble `ed25519_FROST` (DKG with proofs of knowledge, `commit`, `signShare`, `aggregate`), DKG round 2 needs confidential and authenticated channels, noble throws "signing nonces already used", and refresh is written by us (task 1.15). X-Wing HPKE (`@hpke/hybridkem-x-wing` 0.7.0) from task 1.16. The `FrostRelayPort` contract from task 1.2.

**Test first.** Fastify `inject()` plus scripted participants driven from the core FROST functions.

| ID | Test | Expected |
|---|---|---|
| P3.9-01 | A full DKG for one slot through the relay with three scripted participants | all three get the same group key; `frost.dkg.completed` is logged; the relay saw no share in the clear |
| P3.9-02 | The relay is only a forwarder: replace the coordinator code with a spy that records every message | the relay never calls a signing or share function; it stores and forwards bytes |
| P3.9-03 | Every message carries an enrollment signature (Ed25519 and ML-DSA-65, DESIGN 6.3). A message with a bad, missing or unpinned enrollment key | refused; the other participants never see it |
| P3.9-14 | Key directory: a client's own phone and second authenticator pin each other by a QR scan; the coordinator then offers a different key for the recovery agent | the client's app refuses; the key it pinned is the only one it accepts (T-U-29 at service level) |
| P3.9-15 | Key directory for service holders: the recovery agent publishes a signed list of its enrollment keys at a well-known HTTPS address and anchors the list hash on the ledger from its own XRPL account (a memo) | a client's app accepts a key only when it is in the list and the list hash equals the ledger anchor; a swapped list, a list with no anchor and an anchor from another account are each refused |
| P3.9-16 | Echo broadcast: after round 1, every holder signs the hash of the full round-1 transcript; the relay shows one holder a different round-1 message | that holder's signature differs, the DKG aborts and names no share; nothing enters the seal |
| P3.9-17 | A holder sends a round-2 share that fails its check | the receiver publishes a signed complaint with the ciphertext, and everyone can see which sender cheated; the DKG aborts |
| P3.9-18 | Before the slot key enters the seal, the slot test-signs one fixed message with each of its three pairs | all three signatures verify; `frost.dkg.completed` holds them, and the gate code `SLOT_SETUP_OK` passes; with one pair missing or failing, `SLOT_SETUP_OK` fails |
| P3.9-19 | Allow-list: a holder is asked to sign an off-list message (a tagged `tupleHash` with an unknown tag, or an XRPL transaction that is not a multisign for this wallet matching the seal) | the holder refuses; allowed messages (bindings, contract signatures, presence statements, post-quantum cross-signatures, operations bindings, gate records, and the sealed exit) are signed |
| P3.9-20 | Atomic nonce marking: the recovery agent gets two concurrent requests that use the same commitment ID | exactly one gets a signature share; the other is refused; a crash between the mark and the release leaves the commitment marked used (T-U-22 at service level) |
| P3.9-04 | A hostile relay: it alters, drops, replays or reorders messages | participants detect it (bad signature or round mismatch); the relay cannot forge a signature from any share holder |
| P3.9-05 | DKG round-2 shares are sent encrypted with X-Wing HPKE to the receiver's key | the relay's stored bytes cannot be opened by the relay; the receiver decrypts them |
| P3.9-06 | A signing round: the first pair of the 2-of-3 group commits, and one of them stalls | after the timeout the relay asks another pair; the signature verifies against the group key |
| P3.9-07 | Every 2-of-3 pair signs through the relay (T-P-01 at service level); one share alone | each pair gives a valid signature; one share alone cannot finish |
| P3.9-08 | A retry of a signing round after a timeout | fresh nonces are used; a reused commitment is refused (T-U-22 at service level); nonces are never stored by the relay |
| P3.9-09 | Recovery agent: a signing request with the client's valid enrollment signature and a deal that is in a state that allows it | the agent signs its share and logs `frost.signed` |
| P3.9-10 | Recovery agent: a request from a lawyer (any lawyer share or role), an unauthenticated request, a replayed request, or a request for another client's slot | refused; nothing is signed; the refusal is logged |
| P3.9-11 | The recovery agent holds exactly one share of each client slot, and never two shares of one slot | a state test: its store holds one share per slot, encrypted at rest |
| P3.9-12 | Lost phone: a new phone enrolls, and the agent and the second-authenticator share run a repair and then a refresh | `frost.refreshed` is logged; the group key is unchanged; an old share plus a new share does not combine; the deal continues (T-U-23 at service level) |
| P3.9-21 | `frost.refreshed` completeness: the event is written, but one remaining holder has not signed its deletion statement | the refresh is not complete: the status stays `pending_deletions` and the old epoch is not retired until every remaining holder's deletion statement is in the log |
| P3.9-22 | Refresh sub-share checks: one holder sends a sub-share that does not match its Feldman commitments | the receiver rejects it and names the sender; the refresh aborts and the old shares stay valid (T-U-23 at service level) |
| P3.9-23 | Repair: a new device gets a fresh share with the help of two holders, without the old share | the new share signs with one other holder; the group key is unchanged; the old holder's share is never sent (T-U-30 at service level) |
| P3.9-24 | Client recovery start: a request with a fresh ZK proof with the same deal-scoped identifier as onboarding, plus a face match; then the same request with a different identifier, with no face match, and with a proof made from copied chip data and no face match | only the first starts; the others are refused with a reason (T-U-31 at service level) |
| P3.9-25 | Lawyer recovery start: a request signed by the firm's operations account; then one signed by any other key | only the first starts |
| P3.9-26 | The 72-hour delay (a controllable clock): after the start, the old device and both lawyers get a notice; try to sign with the recovery shares at hour 71 | no share is released before hour 72; every step is a logged event |
| P3.9-27 | The old device cancels during the delay | the recovery is cancelled; the recovery shares never sign; the cancel is logged and both lawyers are told |
| P3.9-28 | Rotation on the ledger after a stolen share: a new DKG for the slot, a 4-of-4 `SignerListSet` signed by all four slots, a new seal; for a lawyer slot a new contract signature and a new NFT | on the standalone ledger the new key is the only valid signer; the old slot key can no longer sign an exit; the new seal passes the lock checker |
| P3.9-13 | The relay and the recovery agent run in the demo profile and in the production profile | both pass the same suite |

**Think.** The relay is a message box with timeouts. It routes by `(slotId, round, participantId)` and checks signatures, but it never reads a share. The recovery agent is a separate service with its own key store and its own database role. It trusts only a request signed by the client's enrollment keys.

**Test in all directions.** P3.9-04 with random message mutations (fast-check). Random stalls and crashes at every round. Kill the relay in the middle of a DKG and check that the round restarts cleanly.

**Think hard.** Collusion is the risk (DESIGN 10.1): the recovery agent plus one client share is enough to sign. So the agent signs only when the client's own authenticated request asks it to, it never signs for a lawyer, and every use is a `frost.signed` event in the evidence log. The relay must never hold two shares of one slot, and must never hold a nonce. Refresh is hygiene, not revocation: old shares still combine with each other until they are deleted, and nobody can prove a deletion. Only a rotation on the ledger removes a stolen share (P3.9-28). The coordinator must not choose anyone's enrollment key: that is why P3.9-14 and P3.9-15 exist.

**Implement.** `services/frost-relay/` (routes, a message queue in Postgres, the timeout and retry logic, the transcript echo and complaint messages) and `services/recovery-agent/` (one share per slot, the request checker with the allow-list, atomic nonce marking, the 72-hour delay and notices, the refresh and repair helpers, the signed key list and its ledger anchor). The rotation flow uses the ledger client (tasks 2.2 to 2.4), with a stub until G2. Both are libraries with `register(app, deps)`; `apps/server` composes them.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 3.10 Firm HSM co-signer service

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L16 | Sonnet | high | M (6 h) | 3.6, 3.9, 1.15 |

**Research.** DESIGN 6.3 (the key directory), 6.4 (the lawyer's firm HSM share, the approval rule and the message allow-list), 6.6 (the deal seal) and 7.2 for the transactions the deal wallet may sign. The hybrid `SignerPort` from task 3.12.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P3.10-01 | A request to sign a share for a good exit transaction (right destination, right deal) | the service decodes the transaction, matches the destination and the deal to the seal, signs its share and logs an audit entry |
| P3.10-02 | The destination is not one the seal allows (changed account, changed tag) | refused; nothing is signed |
| P3.10-03 | The transaction is for another deal, or the seal does not match the stored deal seal | refused |
| P3.10-04 | Any other transaction type or flag (`SetRegularKey`, `SignerListSet`, `AccountDelete`, an extra memo that changes meaning, a different amount than the plan) | refused: the service signs only the transactions it knows |
| P3.10-05 | A transaction blob that does not decode, or decodes to a different hash than the one sent | refused |
| P3.10-06 | The share is used through `SignerPort` (or an HSM): the service never holds the share bytes in a log or a response | a scan of logs and responses finds no share material |
| P3.10-07 | Every decision (signed or refused) writes an append-only audit log entry with the transaction hash, deal ID, seal and reason | present and chained into the evidence log |
| P3.10-08 | A request that is not signed by the firm's own authorized operator | refused |
| P3.10-09 | A request with no WebAuthn approval by the lawyer | refused: the HSM signs only with a user-verified WebAuthn approval by the lawyer over the same message hash (T-U-31 at service level) |
| P3.10-10 | Approvals that fail: the approval covers a different message hash, the user-verified flag is not set, the credential is not the lawyer's registered credential, or the challenge is reused | each is refused; nothing is signed |
| P3.10-11 | Allow-list: the HSM is asked for an off-list message (an unknown `tupleHash` tag, or any message that is neither a sealed multisign nor a tagged message of the list) even with a valid approval | refused; the allowed tagged messages (bindings, contract signatures, presence statements, post-quantum cross-signatures, operations bindings, gate records) are signed with an approval |
| P3.10-12 | Atomic nonce marking: two concurrent requests use one commitment ID | exactly one share is released; a crash after the mark and before the release leaves the commitment used; nonces never leave the HSM |
| P3.10-13 | Key list: the firm publishes its enrollment keys (HSM service, console and partner) in a list signed by its operations account, which holds the `LEGX_ATTORNEY` credential, and anchors the list hash on the ledger | the lawyer's console accepts a key only if it is in the list and the hash equals the anchor; a list signed by another account is refused (T-U-29 at service level) |
| P3.10-14 | Lawyer recovery at the HSM: a request signed by the operations account starts the 72-hour delay | no share is released during the delay; the notices go out; the console of either lawyer can see it |

**Think.** The service is a checker first and a signer second. It rebuilds the allowed transaction from the stored deal and the seal, then compares it byte for byte with the request. It never trusts the coordinator's description of the transaction.

**Test in all directions.** Fuzz the transaction decoder with random and malformed blobs. Property: for random transactions, the service signs only those equal to a plan it can rebuild.

**Think hard.** The firm HSM share is one of two lawyer-side shares that can finish a signature with a partner or console share. A service that signs anything would turn the firm into a single point of failure. The approval rule is what stops a hacked coordinator and a stolen console together from moving the money: the HSM signs only what the lawyer approved, on a device with user verification, over the same bytes. So the allow-list must be narrow, and the refusal tests must be as strong as the success tests.

**Implement.** `services/hsm-cosigner/`: the decoder and checker (about 150 lines), the WebAuthn approval check, the allow-list, atomic nonce marking, the signed key list with its ledger anchor, the recovery delay, the share signing call, and the audit log.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 3.11 ZK verifier adapter (`packages/zk`)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L15 | Sonnet | high | M (6 h) | 1.17, 3.1, 3.6 |

**Research.** DESIGN 6.10 (who verifies, the trust anchors, offline re-verification, changes in mid-deal and disputes) and 6.15. Research note r6-zkpassport.md. Facts from the prototype of 24 Oct 2026: the identifier depends on the domain string passed to `new ZKPassport(domain)`; the result holds `proof`, `vkeyHash`, `version` and `committedInputs`, but not the scope, so we store the scope ourselves; offline `verify()` with injected loaders returned `verified = true` with the network blocked; the SDK does not check the `bind` length at request time. Then: `@zkpassport/sdk` 0.19.2, `verify()` is not network-free (it needs an Ethereum RPC for the registry roots and the ZKPassport CDNs), `verifierMode: "local"`, `devMode` and the Sepolia registry, a plain ESM import fails under Node, and ZKPassport proves passive authentication only.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P3.11-01 | The adapter passes the `ZkVerifierPort` contract tests from task 1.17 using the replay adapter and the real SDK adapter (mock passports, `devMode`) | the same suite passes |
| P3.11-02 | Local mode only: run a verification with a network spy that fails any call to the hosted verification service | the call is never made; the check passes or fails on local data |
| P3.11-03 | The adapter makes registry calls only to the pinned RPC URL from the config | a spy on `fetch` and the RPC client sees one host |
| P3.11-04 | The pinned SDK version: the adapter checks the loaded package version against the config | a different version stops start-up |
| P3.11-05 | `devMode` in the production profile | the server refuses to start; a proof made in `devMode` is refused in production |
| P3.11-06 | Each verified proof records the registry roots, the circuit IDs and the verification key hashes in `zk_proof` | all three are stored with the proof; none is empty |
| P3.11-07 | The scope is `legx/v1/<dealId>`; a proof for another scope, or one not bound to the contract root and the slot key (onboarding) or to `presenceMsg` (release) | refused with a clear reason |
| P3.11-08 | The same passport in the same deal gives the same identifier at onboarding and at release; a different passport gives a different one | equal, then different |
| P3.11-09 | CommonJS loading: the adapter loads the SDK with `require` (or a bundler build) under Node | loads and verifies; a test that uses a plain ESM `import` is documented as failing |
| P3.11-10 | The CDN for the circuits is down (a stubbed failure) | the adapter retries with backoff; after the last try it fails with a clear `ZkCdnUnavailable` error; the deal does not advance and no proof is stored as valid |
| P3.11-11 | The registry RPC is down | same: a clear `ZkRegistryUnavailable` error; the gate stays closed |
| P3.11-12 | A forged or corrupted proof (one flipped byte) | rejected (T-U-28 at adapter level) |
| P3.11-13 | No passport data in logs, spans or `zk_proof` after a full verify (the disclosed name, date of birth and nationality are only in the X-Wing box for the client's lawyer, P3.11-19) | a scan finds none (extends T-A-32) |
| P3.11-14 | The trust record: every verified proof stores the chain ID, block number and hash, registry address, root, circuit manifest version, verification-key hashes, identifier type and `dev_mode`, plus the scope we passed in | all fields are non-empty in the record; a missing field fails the store (T-U-32 at adapter level) |
| P3.11-15 | Offline re-verification: the adapter re-verifies a recorded proof through `verify({config})` with injected loaders (`rpcUrl`, `circuitManifestUrlGenerator`, `packagedCircuitUrlGenerator`) served from the recorded files, with the network blocked | `verified = true`; with one recorded file altered, it fails |
| P3.11-16 | Production rules: a trust record with chain 11155111 (Sepolia), a mock identifier type or `dev_mode: true` | refused in the production profile with a clear reason; accepted only in the demo profile |
| P3.11-17 | The domain is always `"legx.app"`, passed explicitly: construct the adapter with the page origin, with no domain, and with another domain | the first two fail at start-up; a proof made under another domain is refused (a different domain gives a different identifier) |
| P3.11-18 | The bind length is checked by our code: a bound value of 506 bytes, then of 507 bytes | 506 passes; 507 is refused before any request is built or any QR code is shown |
| P3.11-19 | Onboarding: the client's own lawyer verifies the onboarding proof; the disclosed name, date of birth and nationality are encrypted with X-Wing to that lawyer's enrollment key; the proof shows the passport does not expire before `CancelAfter` plus 30 days ([CHECK] the exact API) | the coordinator and the other lawyer cannot decrypt the facts; an expiry one day too early is refused; the lawyer signs `identity.onboarded` only after the checks pass |
| P3.11-20 | Release: the proof repeats the disclosed facts, uses the strict face match (on by default, [CHECK] the exact API) and binds `presenceMsg`, which holds `lawyerNonce` | a proof with `face_match_passed` false is refused; a proof with a different fact is refused |
| P3.11-21 | `lawyerNonce` is 32 random bytes and single use: the same nonce is used for a second proof, or the nonce was never issued | the second use is refused; so is an unknown nonce (replay protection) |
| P3.11-22 | Freshness: the ledger anchor in `presenceMsg` is 30 minutes old, then 2 hours old, then 25 hours old, with the default window of 1 hour and a configured maximum of 24 hours | the first passes; the second fails by default; the third fails for any configuration |
| P3.11-23 | The salt: `C_side = tupleHash("legx/zk-identity/v1", [zkSalt32, utf8(N_side)])`; the adapter gets the salt only from the client's lawyer's encrypted copy | the identifier hash matches the sealed `C_side`; a wrong salt fails; the salt is in no log, span or table (a scan) |
| P3.11-24 | Identity method change in mid-deal (a passport renewed, a ZKPassport formula change shown by a new circuit manifest version, or a switch to the chip path) | the adapter reports `METHOD_CHANGE`; the deal needs a 4-of-4 seal update; a refusal to sign it is recorded as O9 (the release stall) |
| P3.11-25 | A dispute: the arbitrator asks who the client is | the answer comes from the client's lawyer's onboarding disclosure and the `identity.onboarded` record; a new proof is optional and its failure (an expired passport) does not block the answer |

**Think.** The adapter is a thin shell around the SDK. It turns every SDK result into the plain `ZkVerifierPort` result, and it records what the offline verifier will need later: roots, circuit IDs and key hashes.

**Test in all directions.** Run the contract suite against a deliberately broken SDK stub (time-outs, bad shapes). Repeat P3.11-02 and P3.11-03 in the production profile.

**Think hard.** A silent fallback to the hosted verifier would break the promise that we trust no outside service (DESIGN 6.10). Block it in code (a config check at start-up) and in a test. The SDK is pre-1.0 and has no external audit, so pin it and keep the replay adapter so the rest of the suite does not depend on it.

**Implement.** `packages/zk/`: the adapter, the config check (domain, mode, version, RPC), the CommonJS loader, the retry wrapper, the injected-loader wrapper for offline verify, the bind-length check, the trust-record recorder for `zk_proof`, and the X-Wing box for the disclosed facts. The profile switch sets `devMode` and the registry.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 3.12 Post-quantum signing in services

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L14 | Sonnet | high | M (6 h) | 3.4, 3.6, 1.16 |

**Research.** DESIGN 6.13 and 8.1. Research note r8-pq.md: AWS KMS `ML_DSA_65` (and `ML_DSA_SHAKE_256`), RAW messages up to 4 KB else `EXTERNAL_MU`; `@noble/post-quantum` 0.7.1 (`ml_dsa65`, not audited, not constant-time); Node 24.7+ has ML-DSA in `node:crypto`; C2SP signed-note type 0x06 (timestamped ML-DSA-44); RFC 4998 evidence record renewal. pg-boss for jobs.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P3.12-01 | `KmsSigner` signs with `ML_DSA_65` and `EXTERNAL_MU`, against a KMS emulator or recorded responses | the signature verifies with noble `ml_dsa65.verify`; a PAE over 4 KB works |
| P3.12-02 | `EXTERNAL_MU`: we compute mu ourselves from the public key, the context and the message (FIPS 204), and the KMS call gets only mu | the recorded request has `MessageType: EXTERNAL_MU` and a 64-byte mu; it matches an independent computation (noble `ml_dsa65.internal.sign(mu, sk, {externalMu: true})`); the signature is an ordinary one that includes the context |
| P3.12-03 | The same keys and messages on Node 24.7+ built-in ML-DSA and on noble | each verifies the other's signatures; sizes are 1,952 B (public key) and 3,309 B (signature) |
| P3.12-04 | The hybrid `SignerPort` returns both signatures for the same PAE; one half fails (KMS error) | no half-signed envelope is stored; the error is clear; the append is retried |
| P3.12-05 | The hybrid checkpoint job: every checkpoint gets the 0x01 line and the 0x06 ML-DSA-44 line | both verify; the job is idempotent after a crash |
| P3.12-10 | Checkpoint policy: our verifier needs BOTH lines. Strip the 0x06 line, strip the 0x01 line, and alter the 0x06 signature; a standard signed-note verifier checks the same notes | our verifier rejects all three and names the missing or bad line; the standard verifier passes the first (it ignores unknown keys) |
| P3.12-11 | The ML-DSA context is explicit on every side: sign with `legx/dsse/v1` through KMS, noble and Node `crypto.sign`; verify with the empty context and with no context argument | the right context verifies; the empty or missing context fails (Node defaults to an empty context, so every call site passes it) |
| P3.12-12 | The 0x06 context: build the 0x06 line with the empty context and verify it with a second implementation ([CHECK]; the prototype of 24 Oct 2026 was not tested against another implementation) | passes, or the test is marked as an open DQ and the mismatch is written in the repo |
| P3.12-13 | The required algorithms are fixed per record type and format version in the verifier's code: a record that lists only `ed25519` in `sig_algs`, or lists an extra algorithm | rejected; the record's own list is only a second check |
| P3.12-06 | The RFC 4998-style renewal job (pg-boss): on its schedule it takes the current evidence head, builds a new time-stamped hash over the old record with a new signature set, and stores it in the WORM store | the chain of renewals verifies offline; the old and the new records are both kept |
| P3.12-07 | The renewal job when the time stamp authority is down, or the job crashes in the middle | it retries; no renewal is lost or doubled |
| P3.12-08 | A key rotation of the ML-DSA key | new envelopes use the new key; old envelopes still verify; the rotation is an evidence event |
| P3.12-09 | `FileSigner` (demo) holds both keys and passes the same suite | passes; refuses to start outside the demo profile (P3.6-02) |

**Think.** The services only call the hybrid `SignerPort`. How the post-quantum half is made (KMS, Node built-in, or noble) hides behind it. Node built-in ML-DSA is for speed and as a cross-check; noble is the reference for the tests.

**Test in all directions.** Cross-verify between KMS recordings, Node and noble over random messages (property test). Run the renewal job under random crashes.

**Think hard.** A hybrid signature is useful only if both halves are required. Never accept an envelope with one half, and never let the signer return one half as success. noble is not audited and not constant-time, so keep production signing in KMS; use noble in services only to verify.

**Implement.** `packages/signer` additions (`KmsSigner` ML-DSA path, the `EXTERNAL_MU` helper that computes mu with the explicit context, Node built-in adapter with the context always passed), `services/evidence/checkpoint-job.ts` and `services/evidence/renewal-job.ts` as pg-boss jobs.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### Phase 3 end-to-end suite (E2E-P3)

Scripted clients (no browser) drive the real server over HTTP and WebSocket, against Postgres 18 in a container and the standalone ledger.

| ID | Scenario | Expected |
|---|---|---|
| E2E-P3-01 | The full deal, P0 to P8, through the API only, with every slot signing FROST 2-of-3 through the relay | Bob paid; wallet closed; every event in the chain, each hybrid-signed; the bundle verifies with the CLI |
| E2E-P3-02 | E2E-P3-01 with the server killed at a random point in each phase (10 runs) | each run completes; no double submit; no lost event |
| E2E-P3-03 | E2E-P3-01 with the demo profile and with the production profile (KMS emulator, MinIO, Tessera container) | both pass |
| E2E-P3-04 | Search the database, the evidence folder, logs and spans after E2E-P3-01 | no passport data, no salt, no private key, no key share, no nonce, no release code before the finish |
| E2E-P3-05 | FROST-signed steps through the relay: DKG for all signer slots, then funding, lock and exit steps signed by different pairs | every signature verifies against its group key; `frost.dkg.completed` and `frost.signed` are in the chain; the relay never held a share |
| E2E-P3-06 | A lost phone: the client's phone is dropped after the contract is signed; recovery starts with a fresh ZK proof plus a face match, waits out the 72-hour delay (controlled clock), then a repair and a refresh give the new phone its share; the deal then completes | the notices go out; `frost.refreshed` is logged and complete only with every remaining holder's deletion statement; the group key is unchanged; an old share plus a new share does not combine; Bob is paid |
| E2E-P3-09 | A hostile coordinator at key generation: it swaps the recovery agent's enrollment key, and separately shows one holder a different round-1 transcript | both are detected before the seal (key not in the anchored list; transcript signature mismatch); no slot key is made |
| E2E-P3-10 | The old device cancels a recovery during the delay, and a stolen share is handled by a rotation on the ledger | the cancel stops the recovery; the rotation (new DKG, 4-of-4 `SignerListSet`, new seal) leaves only the new key able to sign |
| E2E-P3-11 | The firm HSM is asked to co-sign with no lawyer approval, and then with an approval over another message hash | refused both times; with the right approval it signs |
| E2E-P3-12 | Production profile: a Sepolia proof, a mock identifier type, a `devMode` proof, and a checkpoint with the ML-DSA line stripped | all four are refused by the gate and by the offline CLI |
| E2E-P3-07 | Hybrid evidence: build the bundle after E2E-P3-01 and run the CLI with networking blocked | every envelope and checkpoint verifies with both signatures; the bundle holds the ZK proofs, registry roots, circuit IDs, FROST records and post-quantum bindings; stripping any ML-DSA signature fails |
| E2E-P3-08 | A zero-knowledge release attestation through the adapter (mock passports, `devMode`, Sepolia registry or the replay adapter) | the release gate passes on a `zkpassport` attestation; the same identifier appears at onboarding and release; the hosted fallback is never called |

**Phase 3 exit gate (G3):** E2E-P3-01 to 12 green, tasks 3.9 to 3.12 done with their tests, no `devMode` ZK path and no `FileSigner` reachable in the production profile, and no stub `LedgerPort` left in any service test marked `e2e`.

---

## 8. Phase 4: Web clients

**Goal.** The three surfaces from the demo plan: the party app on Alice's and Bob's phones, the lawyer console (Lawyer A and Lawyer B on one laptop), and the dashboard with attack mode on the projector. Also the production key vault with FROST shares and recovery, FROST signing in the browser, the ZKPassport request flow, post-quantum keys, the signing-code integrity checks, and the native chip reader helper (the fallback path, DESIGN O13).

**Owns:** `apps/web/`, `packages/ui/`, `packages/vault/`, `apps/vault-host/` (the separate origin of task 4.10), `tools/release-hash/`, `apps/chip-reader-android/`.

**Starts:** after G0. Until G3, every test runs against MSW mocks generated from the frozen contracts. **Covers DESIGN:** 1.1 (the story as screens), 4.1 (party app and lawyer console), 6.3 (enrollment keys and the key directory), 6.4 (FROST slot keys, share storage, recovery, repair, rotation and code integrity), 6.5 (binding), 6.10 (zero-knowledge proofs), 6.13 (post-quantum keys), 6.15 (attestation methods and chip reading), 7.5 (decode and check before signing), 8.10 (client records view), and milestone M5.

**One app, three routes.** `apps/web` is one Vite single-page app with `/party/$role`, `/lawyers` and `/dashboard`. All three share one origin, so one tunnel URL and one QR code base serve them all (section 4.4). In production, the same code can be split into three apps on separate subdomains, so each role's key storage is isolated by the browser.

**Budgets.** Phone route: first load under 250 kB gzipped, without xrpl's optional WASM, which loads only when needed. Every screen works at 360 px wide. Projector text has 7:1 contrast, and no state is shown by color alone: each item also has an icon and a PASS or FAIL label.

### 4.1 Web foundation

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| LW1 | Sonnet | medium | M (6 h) | G0 |

**Research.** Section 4.4: Vite 8 config for xrpl.js (no Node polyfills; tunnel host in `server.allowedHosts`), TanStack Router file routes, TanStack Query with a WebSocket feed, shadcn/ui with Base UI, vite-plugin-pwa settings (never cache `/api` or `/ws`).

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P4.1-01 | Each route renders its empty state under MSW | renders; no console error |
| P4.1-02 | The API client is generated from `packages/contracts` route table | a wrong request shape fails at compile time (type test) |
| P4.1-03 | The live feed: MSW sends `deal.updated` over WebSocket | the query cache updates; the screen shows the new state |
| P4.1-04 | The socket drops and reconnects | the client asks for events after its last `seq` and shows no gap |
| P4.1-05 | The app is opened over plain HTTP on a LAN IP | a full-screen message says "Open the HTTPS link", because `crypto.subtle` is missing |
| P4.1-06 | Phone route bundle size | under budget (a CI check on the build output) |
| P4.1-07 | Axe accessibility scan of each route | no serious or critical issues |

**Think.** Server state lives in TanStack Query only. A tiny Zustand store holds UI-only state, such as attack-mode toggles. No key or secret ever goes into either store.

**Test in all directions.** Run every route test in Chromium and WebKit. Throttle the network to a slow 3G profile for the phone routes.

**Think hard.** The service worker can serve an old build during a rehearsal. Ship a kill switch (`selfDestroying` mode) behind a config flag, and test it.

**Implement.** `apps/web` with Vite 8, TanStack Router file routes, the oRPC client, the WebSocket hook, Tailwind and shadcn/ui.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 4.2 Key vault and recovery (`packages/vault`)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| LW1 | Opus | xhigh | L (8 h) | 1.3, 1.15, 4.1 |

This package is where share secrets live. It is the most sensitive code in the browser. There is no deal secret and no key made from a seed any more. Each signer slot is a FROST 2-of-3 group key (DESIGN 6.4). FROST shares are scalars, not WebCrypto keys, so the vault stores them as encrypted bytes.

The vault stores:
- **Share 1** (the phone share), encrypted under a non-extractable AES-GCM `CryptoKey` kept in IndexedDB.
- **Share 2** (the second-authenticator share). It lives on a **separate authenticator**: a FIDO2 security key with the PRF extension, or the client's second device. The vault stores share 2 encrypted under a key from WebAuthn PRF on that authenticator. When PRF is missing, a recovery file encrypted with a recovery code is the fallback. A passkey that syncs to the same phone is allowed only as a labeled **"single-device mode"**: it loses the protection against theft of the phone (DESIGN 6.4, Risks).
- **The enrollment keys** (Ed25519 and ML-DSA-65, DESIGN 6.3). Task 4.9 owns the ML-DSA-65 part.

The third share belongs to the independent recovery agent (task 3.9). It never enters this vault.

**Research.**
- WebCrypto AES-GCM with non-extractable keys, and storing `CryptoKey` objects in IndexedDB. WebCrypto Ed25519 (Chrome 137+, Firefox 129+, Safari 17+) is used only for the Ed25519 enrollment key.
- WebAuthn PRF support on FIDO2 security keys and on platform passkeys (section 4.4) and `@simplewebauthn/browser`. Derive the AES-GCM key from the PRF output with HKDF, using a salt that names the deal and slot. The two ways to hold share 2 (security key, or second device with an approval on it) and the single-device label come from DESIGN 6.4.
- The FROST wrapper from task 1.15 (noble `ed25519_FROST`): `commit`, `signShare`, `aggregate`, `verifyShare`. noble zeroes nonces and throws "signing nonces already used". Read r7-frost.md.
- How to place a FROST signature in an XRPL multisign entry: sign `encodeForMultisigning(tx, address)` from `ripple-binary-codec` (it is not exported by `xrpl`). The result is a plain 64-byte Ed25519 signature, so the ledger sees an ordinary signer. Task 2.8 proves this on the ledger.
- HPKE (RFC 9180) for share transport (section 4.6). Checked on 24 Oct 2026: `@hpke/core` 1.9.0 is maintained but not audited. The X-Wing form is in task 1.16.

**Test first.** These run in Vitest browser mode on Chromium and WebKit, because jsdom has no real WebCrypto or IndexedDB.

| ID | Test | Expected |
|---|---|---|
| P4.2-01 | `storeShares({ dealId, role, share1, share2 })` encrypts share 1 under a fresh non-extractable AES-GCM key, encrypts share 2 under the PRF key, and zeroes the input buffers | `exportKey` on the AES key is refused; IndexedDB holds only ciphertext (a byte search for the share finds nothing); the input buffers are all zero |
| P4.2-02 | `signFrost(tx, account, ctx)` decrypts both shares, runs `commit` and `signShare` for both, aggregates and verifies | the signature verifies strictly (`zip215: false`) under the slot group key, and it is a valid XRPL multisign signature over `encodeForMultisigning(tx, addr)` |
| P4.2-03 | Reload the page | both encrypted shares are still there (IndexedDB), named `dealId:role:slot` |
| P4.2-04 | Two roles on one device (the lawyer laptop) | each role sees only its own entries |
| P4.2-05 | Share 2 under WebAuthn PRF on a separate authenticator (a virtual FIDO2 security key with PRF, distinct from the phone's own platform authenticator) | restore on a fresh profile with the same security key gives a share that signs correctly with share 1 |
| P4.2-14 | Share 2 on the client's second device: the signing call asks that device for an approval, and share 2 never leaves it | no signature without the approval on the second device; the phone never sees share 2 bytes |
| P4.2-15 | Single-device mode: share 2 is held by a passkey that syncs to the same phone | allowed only after the user accepts a warning; the label "Single-device mode: no protection if this phone is stolen" shows on the share screen, in the DKG summary and in the deal record; the mode is part of the slot's recorded setup |
| P4.2-06 | The fallback: a recovery file encrypted with a recovery code, for authenticators without PRF | restore works; a wrong code fails cleanly and leaks nothing |
| P4.2-07 | Signing without a passkey check (the PRF call is cancelled or fails) | no share is decrypted; the call throws `PASSKEY_REQUIRED` |
| P4.2-08 | No function in the vault returns, logs or posts a share or secret | a test spies on `fetch`, `WebSocket.send`, `console.*` and `postMessage` during a full lifecycle (store, sign, restore), and searches every argument for the share bytes, the AES key bytes and the PRF output |
| P4.2-09 | `navigator.storage.persist()` is requested at share creation | called; the result is shown to the user |
| P4.2-10 | The share flow is asked to send a share to a lawyer role | refused at the type level and at run time; the share screen says "Never give a share to your own lawyer" |
| P4.2-11 | Every buffer that held a decrypted share, nonce or PRF output after a signing call, including the error paths | all zero (the test passes its own buffers through the wrapper hooks) |
| P4.2-12 | Content Security Policy: an inline script and a `javascript:` URL are injected | both are blocked; Trusted Types rejects a string sink |
| P4.2-13 | iOS home-screen mode (WebKit emulation of a separate storage partition) | the app says which context holds the shares; a recovery file moves them |

**Think.** In normal mode share 2 is on a different device or key from share 1, so one stolen phone cannot sign. A share is needed in raw form only inside one signing call, and once at creation or restore. Decrypt both shares inside the call, use them, and drop every reference. Nothing outside the call holds a raw share, and nothing is cached between calls. In the signing call both shares take part, but share 2 is released only by the security key or the second device. The recovery agent holds the third share, so no one device or party can sign alone without the second authenticator.

**Test in all directions.** Run P4.2-01 to 13 on Chromium and WebKit. Property: for random messages, a signature made from shares 1 and 2 verifies under the slot key, and the same shares never verify under another slot's key. Fault tests: a corrupted ciphertext fails with a clear error and zeroes its buffers; a quota error at storage time leaves no half-written state.

**Think hard.**
- Against cross-site scripting, encryption at rest stops theft of the stored bytes, but script on the page can still ask the vault to sign. Real defences: a strict Content Security Policy with Trusted Types, pinned dependencies, the second-authenticator check before every signature, the decode-and-check rule before every signature (task 4.3), and the integrity of the signing code itself (task 4.10: a reproducible bundle with a published hash, served from a separate origin). Write the CSP now and test it (an inline script must be blocked); task 4.10 owns the full header set.
- The xrpl.js 4.2.1 to 4.2.4 supply-chain attack (CVE-2025-32965) is the reason to pin exact versions and commit the lockfile.
- On iOS, the installed home-screen app may not share IndexedDB with the Safari tab. The app must say which one holds the shares, and the recovery file is the way to move them.
- Never give a share to the client's own lawyer (DESIGN 6.4). The share screen says so, and the share flow cannot send a share to a lawyer role. Recovery goes through the recovery agent's share, not through a split of our own.
- The AES key is non-extractable, but an attacker with page script can still call decrypt. That is why share 2 on a separate authenticator is needed for any signature: the stolen phone share alone is useless. In single-device mode this does not hold, and the screens say so.

**Implement.** `packages/vault`: `storeShares`, `signFrost`, `backupShare2ToFile`, `restore`, and the enrollment key store. `refreshShares` is not here: it lives in task 4.7, which depends on this task. All raw share handling stays inside `signFrost`, which decrypts both shares, runs both signers, aggregates, verifies and zeroes:
```ts
// Sketch. The real signatures come from the task 1.15 wrapper over noble ed25519_FROST. [CHECK]
export async function signFrost(ctx: SlotCtx, msg: Uint8Array): Promise<Uint8Array> {
  const prf = await passkeyPrf(ctx.credentialId, ctx.prfSalt);          // throws PASSKEY_REQUIRED
  const bufs: Uint8Array[] = [prf];
  try {
    const s1 = await aesDecrypt(ctx.aesKey, ctx.enc1);  bufs.push(s1);   // phone share
    const s2 = await aesDecrypt(await prfKey(prf), ctx.enc2); bufs.push(s2); // share 2, unlocked by the security key's PRF output for this one signature
    const c1 = frost.commit(s1), c2 = frost.commit(s2);                  // nonces stay in this scope
    const list = [c1.commitments, c2.commitments];
    const z1 = frost.signShare(s1, ctx.pubs, c1.nonces, list, msg);      // each nonce set is used once
    const z2 = frost.signShare(s2, ctx.pubs, c2.nonces, list, msg);
    const sig = frost.aggregate(ctx.pubs, list, msg, [z1, z2]);
    if (!ed25519.verify(sig, msg, ctx.groupPub, { zip215: false })) throw new Error('FROST_VERIFY_FAILED');
    return sig;
  } finally { for (const b of bufs) b.fill(0); }                         // shares, PRF output
}
export const signMultisig = async (ctx: SlotCtx, tx: object, account: string) =>
  bytesToHex(await signFrost(ctx, hexToBytes(encodeForMultisigning(tx, account)))).toUpperCase();
```
Test P4.2-02 checks that the output verifies strictly and that the ledger accepts it (the ledger part runs in task 2.8).

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 4.3 Party app (Alice and Bob)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| LW2 | Sonnet | medium | L (8 h) | 4.1, 4.2, 4.7 |

**Research.** DESIGN 7.5 (the checks before signing an exit) and the demo screens in this plan.

Screens, from the demo plan: **Home** (the deal checklist), **Make my key** (the DKG screens of task 4.7), **Lock money** (Alice only: shell key, funding, escrow), **Accept my badge** (step 5f), **Passport presence** (sign the presence statement during the lawyer's check; with the zero-knowledge method, the ZKPassport request of task 4.8), **Approve payment** (exit and close), **My records** (DESIGN 8.10).

**Test first.**

| ID | Test | Expected |
|---|---|---|
| T-I-04 | The coordinator sends an exit whose destination is not a sealed payout address | the app decodes the real transaction, compares it with the seal, and refuses; the screen says why |
| P4.3-01 | The summary screen shows the destination, amount and deal from the **decoded** transaction, never from the coordinator's description field | a test sends a description that disagrees with the transaction; the screen shows the transaction's values |
| P4.3-02 | The seal recomputed on the phone differs from the coordinator's | the app refuses to sign anything and shows "Seal mismatch" |
| P4.3-03 | The payout account requires a destination tag that the seal lacks (read through the coordinator's validated `account_info` relay, then checked) | the app warns before signing |
| P4.3-04 | Approve a payment: the app signs (FROST, after a passkey check) and posts only the signer blob | the request carries no share, nonce or secret (spy test) |
| P4.3-05 | The presence statement: the app shows "Your lawyer is checking your passport", asks for the passkey, signs `presenceMsg` with the slot key as a FROST signature (two shares, task 4.7), and shows the ledger index it signed | the signature verifies strictly under the slot group key in `verifyAttestation` |
| P4.3-06 | My records: each record shows the signature check, the chain check and the ledger link | matches `verifyClientRecords` |
| P4.3-07 | Phone flow in Playwright with WebKit and Chromium phone devices | all screens pass on both |
| P4.3-08 | Visual snapshot of each screen | matches the baseline |
| P4.3-09 | The Passport presence screen shows the method (zero-knowledge or chip) that the deal's `identityPolicy` allows | the label matches the attestation's `method` |

**Think.** Each screen is a small component that reads one query and has one action.

**Test in all directions.** Run the phone flow with the network dropping between screens, and with a tampered coordinator response on every screen that leads to a signature.

**Think hard.** The coordinator might be hacked (DESIGN 10.1). Every screen that leads to a signature must show values that the phone computed itself, from the transaction bytes and the seal.

**Implement.** `apps/web/src/routes/party/`. The signing calls go through `packages/vault` (task 4.2) and the FROST screens of task 4.7.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 4.4 Lawyer console (Lawyer A and Lawyer B)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| LW3 | Sonnet | high | L (8 h) | 4.1, 4.2, 4.7, 4.8 |

**Research.** DESIGN 5.3 (phases P6 and P7), 6.10, 6.15 and 6.17.

One page, split in two halves. Each half has its own vault keys.

**Buttons:**
- **Lawyer A:** sign contract, bind operations account, mint the contract NFT.
- **Lawyer B:** sign contract, bind operations account, make the release code, run the lock check, check Bob's passport (method-aware), run the release gate, release money.
- **Both:** check my client's passport (method-aware), approve exit. The lawyer slot signs with the console share plus the firm HSM co-signer (task 4.7); the HSM signs only after the lawyer's approval prompt (DESIGN 6.4).

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P4.4-01 | Sign contract: the console shows the contract text, the wallet address and the contract root it computed itself; it signs `contractSigMsg` | the signature verifies in `verifySignedContract` |
| P4.4-02 | The release code is made in the browser and never leaves it, except inside the `EscrowFinish` | spy test: no request carries the preimage before the finish; the coordinator receives only the condition |
| P4.4-03 | The passport check is method-aware. Zero-knowledge (default): the console shows the proof result from the ZK verifier adapter (task 3.11, see task 4.8). Chip (fallback, only when `identityPolicy` allows): load a fixture passport (demo profile) or receive chip data from the reader helper (task 4.6) | zero-knowledge shows the proof checks; chip runs `passiveAuth` in the console and shows each check; every item has PASS or FAIL |
| P4.4-04 | The attestation is signed only after the client's presence signature (a FROST signature by the slot key) arrives and verifies | without it, the sign button stays disabled |
| P4.4-05 | After the attestation is signed, the console drops the DG1 and SOD bytes (chip method) and any proof payload not needed for the record (zero-knowledge method) | a test checks that no reference remains in app state or IndexedDB |
| P4.4-06 | Run release gate: the console reads one validated ledger snapshot through the coordinator's ledger relay, runs `checkRelease` locally, and shows each of the 15 codes | the list matches `checkRelease` output |
| P4.4-07 | The release button is enabled only when the gate has no blocking finding, and the snapshot is from the current validated ledger | otherwise disabled, with the reason |
| P4.4-08 | Release: the console builds `EscrowFinish` with the gate memo, signs with the operations account key and submits | the transaction validates; `release.performed` appears |
| P4.4-09 | Lawyer A's half cannot see or use Lawyer B's keys | vault isolation test |
| P4.4-11 | Lawyer approval prompt: before the firm HSM co-signs, the console shows the decoded message (what is signed, its destination and amount, or the tag and fields) and its hash, and asks the lawyer for a user-verified WebAuthn approval over that same hash; the approval goes with the request to the HSM | the prompt shows values the console decoded itself; the HSM request carries the approval; cancelling the prompt or failing user verification sends nothing (the HSM would refuse anyway, P3.10-09) |
| P4.4-12 | The approval prompt for a message the coordinator describes differently from the bytes | the prompt shows the decoded bytes' meaning; the lawyer sees the mismatch and the approval is not offered for the false summary |
| P4.4-13 | `identityPolicy` is `"chip"` and the attestation is a ZK attestation; or the method differs from the sealed `idMethod_side` | `IDENTITY_POLICY_OK` shows FAIL with its reason; release stays off |
| P4.4-14 | The face match: a release attestation with `face_match_passed` false; and a proof made from copied chip data that has no face match | the screen shows FAIL with the reason "face match"; the attestation cannot be signed |
| P4.4-15 | The gate screen shows each of the new codes (`ONBOARDING_OK`, `IDS_DISTINCT`, `IDENTITY_POLICY_OK`, `PQ_BINDINGS_OK`, `SLOT_SETUP_OK`) failing in turn | each shows its own FAIL line and reason; the button stays off |
| P4.4-10 | Run release gate: the gate list and the release screen show the identity method (zero-knowledge or chip) of each party's attestation | the label matches each attestation's `method`; a method the `identityPolicy` forbids blocks release with its code |

**Think.** Both halves share components, with a `role` prop and separate vault namespaces.

**Test in all directions.** Run the release flow with each of the 16 gate codes failing in turn. The button stays disabled, and the reason shows.

**Think hard.** The gate runs in the browser, on data relayed by the coordinator. A hacked coordinator could feed a false snapshot. So the console checks the snapshot's ledger hash against a second public server directly (a read-only WebSocket to a public XRPL node). If they disagree, it refuses.

**Implement.** `apps/web/src/routes/lawyers/`.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 4.5 Dashboard and attack mode

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| LW3 | Sonnet | medium | M (6 h) | 4.1 |

**Research.** The Testnet explorer URL patterns (section 4.5).

**Panels:** the deal state (DESIGN 5.1 states), the lock checker items, the release gate items, the ledger log with explorer links, the evidence log with chain status and Merkle root, and the attack-mode buttons.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P4.5-01 | Each validated step appears in the ledger log with an explorer link for the active network | the link pattern matches section 4.5 |
| P4.5-02 | Lock checker items turn PASS one at a time as the lock steps validate | order follows the ledger |
| P4.5-03 | Attack buttons: stranger finish, master key left on, double exit, one-byte bundle change, fake passport, stale bar check | each triggers its scene; the result appears with the ledger's engine code |
| P4.5-04 | Attack mode is off unless the server runs the demo profile | the buttons are hidden and the API refuses |
| P4.5-05 | Visual snapshot at 1920 x 1080 in dark mode | matches the baseline |
| P4.5-06 | `prefers-reduced-motion` | no animation |

**Think.** The dashboard only reads. Attack mode posts to `/demo/attack/*` routes that exist only in the demo profile.

**Test in all directions.** Run each attack twice in a row, and again on a fresh deal.

**Think hard.** Attack routes in production would be a back door. P4.5-04 and P3.7-05 both guard against it.

**Implement.** `apps/web/src/routes/dashboard/`, and `services/coordinator/demo-attacks.ts` (demo profile only).

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 4.6 Native chip reader helper (the fallback path, DESIGN O13)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| LW4 | Sonnet | high | L (2 to 3 days) | 1.9 |

A small Android app that reads the passport chip with JMRTD and sends DG1, EF.SOD, DG14 and DG15, plus the Active Authentication answer, to the lawyer's console over a local, end-to-end encrypted channel. This is the **fallback** path. The default identity method is zero-knowledge (task 4.8). The helper is used only when `identityPolicy` is `"zk-or-chip"` and the party chooses it, or when it is `"chip"`. It is the only method that proves the physical chip was present (Active or Chip Authentication), which ZKPassport does not prove (DESIGN 10.1). The demo does not need it (fixture passports and mock passports). It is in this plan because the design requires real chip reading before real users who need it.

**Research.** JMRTD (section 4.6), the Android NFC IsoDep API, PACE or BAC access with the MRZ, and passing our own 8-byte Active Authentication challenge (a **[CHECK]** in DESIGN 6.15).

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P4.6-01 | Unit: the transfer format round-trips DG1, SOD, DG14, DG15 and the AA answer | equal |
| P4.6-02 | The channel: the console shows a QR with a one-time key; the helper encrypts to it | a third party on the network sees only ciphertext |
| P4.6-03 | AA challenge = the first 8 bytes of `presenceMsg` | the console verifies the answer |
| P4.6-04 | On a real test passport (manual test, recorded) | passive authentication and Active or Chip Authentication pass (the DESIGN M5 **[CHECK]**) |

**Think.** The helper only reads and forwards. It never sees the deal or any key, only a one-time encryption key from the QR code.

**Test in all directions.** Fuzz the transfer decoder. Test with a card that holds copied passport data but no Active Authentication key; the console must show `CHIP_AUTH_INVALID`.

**Think hard.** The helper sees raw passport data. It keeps nothing after it sends, and it shows the user what it read.

**Implement.** `apps/chip-reader-android/` in Kotlin, with JMRTD.

**As built (4.6).** The protocol is in `packages/chip-link` (TypeScript, tested): the `LGXC` transfer format, the QR text `legxchip1:<session>:<challenge>:<X-Wing key>`, an encrypted session that opens once, and the console receiver that calls `chipChecks`. `apps/chip-reader-android` is a Kotlin skeleton only. It has no Gradle project, manifest, QR scanner, PACE or Kotlin X-Wing, and it was never compiled. P4.6-04 (the manual test on a real passport) is not done.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 4.7 FROST in the browser: DKG, two-share signing, recovery, repair and refresh (in `packages/vault`)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| LW1 | Opus | xhigh | L (2 days) | 1.15, 3.9, 3.10, 4.2 |

This task puts the FROST group keys of DESIGN 6.4 on screen. Client slots have three shares: the phone, a separate authenticator (a FIDO2 security key with PRF, or a second device; a same-phone passkey is only "single-device mode") and the recovery agent. Lawyer slots have three shares: console, firm HSM co-signer and partner.

**Research.** DESIGN 6.4 and 6.5. r7-frost.md. noble `ed25519_FROST` 2.4.0 has a 3-round DKG with proofs of knowledge. Round 2 needs confidential and authenticated channels, which the coordinator's FROST relay (task 3.9) gives with HPKE to each party's enrollment key. noble has no refresh, so the refresh protocol is ours (task 1.15). Read the relay API and the key-directory rules from task 3.9 and the co-signer and approval API from task 3.10. DESIGN 6.4 sets the recovery delay (72 hours), the notices, the cancel option, repair, refresh and rotation.

**Test first.** Browser-mode tests run on Chromium and WebKit. Network parts run against MSW mocks of the relay until G3.

| ID | Test | Expected |
|---|---|---|
| P4.7-13 | Key pinning: the phone and the second authenticator pin each other's enrollment keys by a QR scan between the two devices; the recovery agent's key is checked against its anchored signed list | a key that was not scanned or is not in the anchored list is refused; the screen names the key it refuses (T-U-29 in the browser) |
| P4.7-01 | The DKG screens for a client slot: phone, second authenticator and recovery agent take part through the relay | all three get the same group public key; the phone holds share 1 and the second authenticator share 2 (stored by task 4.2); the screen shows the group key fingerprint |
| P4.7-02 | A DKG round-2 package from a party with a bad proof of knowledge or a share that fails its check | the screen aborts and names the party; a signed complaint is shown and sent; no share is stored |
| P4.7-14 | The echo step: the phone signs the round-1 transcript hash and the relay shows it a different transcript than the others got | the DKG aborts before any share is stored |
| P4.7-15 | The slot test: all three pairs test-sign the fixed message before the slot key is shown as ready | the screen shows three green pairs (each by name); with one pair failing the slot is not ready |
| P4.7-03 | Two-share signing on the phone: Approve payment asks for the second authenticator (a tap of the security key, or an approval on the second device), then signs | a valid FROST signature under the slot key; without the second-authenticator check, no signature (`PASSKEY_REQUIRED`) |
| P4.7-04 | The recovery flow on a new phone: share 2 (restored from the PRF backup or the recovery file) plus the recovery agent's share, a repair for the new phone's share 1, then a share refresh | the new phone gets a fresh share 1; the old phone's share 1 plus a new share does not combine (a signing attempt with old and new fails verification); old shares still combine with each other until they are deleted, and the screen says so |
| P4.7-16 | The recovery screen on the new phone: it asks for a fresh ZK passport proof with the same identifier plus a face match, then shows the 72-hour delay with a countdown and says who was notified (the old device and both lawyers) | no recovery share is used before the delay ends; a proof with another identifier or without a face match is refused with a reason |
| P4.7-17 | The old device receives the recovery notice and presses Cancel during the delay | the recovery is cancelled, the screen on the new phone says so, and the evidence shows the cancel; a lawyer's console shows the notice and the cancel |
| P4.7-18 | The repair flow: a new device gets a share through two helpers without the old share | the new share signs with one other holder; the group key is unchanged; the screen offers a refresh next |
| P4.7-19 | Single-device mode in the DKG screens: share 2 is a same-phone passkey | the label "Single-device mode" shows on every summary; recovery of the phone loses the theft protection and the screen says so |
| P4.7-20 | The rotation screen after "my share was stolen": a new DKG, a 4-of-4 `SignerListSet` signed by all four slots, a new seal (and for a lawyer slot a new contract signature and NFT) | each step is a screen with its own check; the old slot key is shown as retired only after the ledger validates the new signer list |
| P4.7-21 | A lawyer slot signs: the console share plus the firm HSM co-signer, with the vault's approval call (`requestApproval(hash)`, a WebAuthn user-verified assertion over the message hash); the console screen that shows it is task 4.4 | the HSM share is released only after the approval; without it the console shows "Your firm's HSM needs your approval" |
| P4.7-05 | The lawyer slot: console share plus the firm HSM co-signer | the co-signer checks the transaction against the seal first (task 3.10) and needs the lawyer's approval (P4.7-21); a transaction that does not match gets no share, and the console shows the reason |
| P4.7-06 | Nonces are held in memory only: the page reloads between `commit` and `signShare` | the nonces are gone; the signing session restarts with new nonces; nothing in IndexedDB or storage holds a nonce |
| P4.7-07 | A nonce set is used for a second message | `signShare` throws "signing nonces already used"; the UI shows an error and starts a new session |
| P4.7-08 | The relay or a party sends a different message than the one the phone decoded | the phone's `signShare` runs only over the bytes it checked itself (task 4.3), so a different message gets no share |
| P4.7-09 | Spy test over a full DKG, signing, recovery, repair and refresh | no share, nonce or secret leaves the device in clear; only the DKG round packages (HPKE sealed), commitments and signature shares go out |
| P4.7-10 | Every 2-of-3 pair of a client slot signs; one share alone cannot (T-P-01 in the browser) | all three pairs verify; one share gives no valid signature |
| P4.7-11 | Signing speed on a mid-range phone profile (4x CPU throttle in Chromium, and a real mid-range Android as a manual test) | a two-share signature in under 1 s on the throttled profile; the DKG finishes in under 5 s of device time, not counting the network |
| P4.7-12 | Share refresh with all three parties online | the group key is unchanged; an old share plus a new share does not combine; a signing test passes after |
| P4.7-22 | The refresh screen collects each holder's deletion statement and checks every received sub-share against the sender's Feldman commitments | the screen shows "refresh complete" only when every remaining holder's deletion statement is in; a bad sub-share aborts the refresh and names the sender; the screen says "hygiene, not revocation" |

**Think.** The phone plays two FROST participants in one signing call (task 4.2's `signFrost`). The relay only moves messages. It never holds a share. The UI shows which share holders took part, so the user can see that the recovery agent was not needed for a normal signature.

**Test in all directions.** The relay drops or reorders messages. The user cancels the passkey prompt. The tab is backgrounded during the DKG (mobile browsers pause timers). Run every test on Chromium and WebKit. Replay the RFC 9591 vectors through the browser wrapper (T-U-21 inputs). Run the DKG with a hostile relay mock (T-U-29).

**Think hard.** Nonce reuse leaks the share (DESIGN 10.1), so nonces never touch storage, never survive a reload and are used once. Recovery-agent collusion: the agent plus one stolen share could sign. The recovery screen says who the agent is, and the agent signs nothing on its own (it needs the user's request, a fresh proof with a face match, and the 72-hour delay that the old device can cancel, task 3.9). Refresh is hygiene, not revocation: a share known to be stolen needs the rotation of P4.7-20. Refresh and repair are our own code and not in any audit (r7-frost.md), so the screens label them clearly and the tests above are the evidence.

**Implement.** `packages/vault/src/frost/` (DKG client with the echo and complaint steps, key pinning, signing session, `refreshShares` and the refresh client, repair, recovery with the delay and cancel, rotation) and the screens in `apps/web/src/routes/party/` and `apps/web/src/routes/lawyers/`.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 4.8 ZKPassport request flow (party app and lawyer console)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| LW2 | Sonnet | high | L (8 h) | 1.17, 3.11, 4.3 |

**Research.** DESIGN 6.10 (domain, who verifies, the trust record, mid-deal changes) and 6.15. r6-zkpassport.md. Prototype facts of 24 Oct 2026: the identifier depends on the domain string, so it is always `"legx.app"`; the SDK does not check the `bind` length at request time; `verify()` ran headless in Node (about 0.65 s) but whether it runs in a browser is unknown (`bb.js` has about 4 MB of WASM and needs `SharedArrayBuffer` for threads). `@zkpassport/sdk` 0.19.2: `request({scope, devMode, validity, ...}).gte('age',18).bind('custom_data', str).done()` gives a URL for a QR code or deep link. The phone app proves in 10 to 50 s. `bind` takes at most about 506 bytes. A plain ESM import fails under Node, so use a bundler in the browser. `verify()` needs an Ethereum RPC and ZKPassport CDNs, so the console never verifies through the hosted fallback.

**Test first.** The SDK is mocked in Playwright and Vitest (the mock returns scripted callbacks), against MSW, until G3. At G3 the demo profile uses the real SDK with mock passports.

| ID | Test | Expected |
|---|---|---|
| P4.8-01 | The party app builds the request: the domain `"legx.app"` passed explicitly (never the page origin), scope `legx/v1/<dealId>`, the bound value (the contract root and slot key at P5), and the checks the deal needs | the mocked `request` is called with exactly these values; a different scope or bound value fails the test |
| P4.8-02 | The screen shows a QR code and a deep link for the request URL | the QR decodes to the URL; the link has the same URL; both appear at 360 px |
| P4.8-03 | The callbacks: `onRequestReceived`, `onGeneratingProof`, `onProofGenerated`, `onResult`, `onReject`, `onError` | each state has its own screen text; reject and error offer "Try again" |
| P4.8-04 | The onboarding proof at P5: the client's own lawyer verifies it in the console (not the coordinator); the request discloses name, date of birth and nationality to that lawyer only, and proves the expiry is after `CancelAfter` plus 30 days ([CHECK] the exact API) | the proof reaches the client's lawyer's console; the lawyer signs the onboarding attestation and the event `identity.onboarded` appears; the party app shows "Passport proof done" |
| P4.8-14 | The disclosed facts travel encrypted with X-Wing to the client's own lawyer's enrollment key | the coordinator, the other lawyer and the other party cannot read them (a spy test and a decrypt attempt); the client's own lawyer can |
| P4.8-15 | The salt: the app makes `zkSalt32`, keeps it with share 2 and sends an encrypted copy to the client's own lawyer; `C_side` uses the salt | the console recomputes `C_side` from the salt and the identifier and it equals the sealed value; the coordinator sees only `C_side`; no request carries the plain salt |
| P4.8-16 | The release flow builds the request with the strict face match (on by default, [CHECK] the exact API) and the repeated facts | the mocked `request` is called with the face match on; a result with `face_match_passed` false shows FAIL, and a proof made from copied chip data with no face match is refused |
| P4.8-17 | The lawyer nonce: the lawyer's console makes `lawyerNonce` (32 random bytes, single use) and the phone includes it in `presenceMsg` before it makes the release proof | the bound value equals the `presenceMsg` that holds the nonce; the second use of the same nonce, and an unknown nonce, are refused (replay) |
| P4.8-18 | The bound value is at most 506 bytes, checked by OUR code before the QR code is shown | a 507-byte value shows an error and no QR code; the SDK is never asked |
| P4.8-19 | The trust record in the console: chain, registry root, circuit manifest version, verification-key hashes, identifier type and `dev_mode` | each is shown; in the production profile a Sepolia root, a mock identifier type or `devMode` shows FAIL and blocks the attestation |
| P4.8-20 | Freshness: the ledger anchor in `presenceMsg` is older than 1 hour (the default window) and then older than 24 hours | the first is refused by default; the second is refused for any setting |
| P4.8-21 | Identity method change in mid-deal (a renewed passport, a formula change, or a fall back to the chip) | the console shows that a 4-of-4 seal update is needed; a refusal to sign it shows as a stall (O9) and is recorded |
| P4.8-05 | The release proof at P7 bound to `presenceMsg`, built from a **fresh** ledger hash that the phone read itself | the bound value equals `presenceMsg`; a stale ledger hash (older than the allowed window, 1 hour by default) makes the app refuse to start the request |
| P4.8-06 | The release proof has the same scope as onboarding, so the same unique identifier | a different identifier is rejected by the console with `ZK_IDENTIFIER_MISMATCH` |
| P4.8-07 | The client's own lawyer's console checks the result through the ZK verifier adapter (task 3.11) and shows each check with PASS or FAIL | the list matches the adapter's output; a tampered result shows FAIL |
| P4.8-08 | If the SDK can verify in the browser (`verifierMode: "local"`), the console also re-verifies locally **[CHECK]** | a local failure blocks the attestation even when the adapter says PASS; if the SDK cannot verify in the browser, the test is skipped and the note is written in the repo |
| P4.8-09 | The demo profile: ZKR mock passports and `devMode: true` | the flow completes; with `devMode` set outside the demo profile, the app and the adapter both refuse |
| P4.8-10 | The fallback button "Use my passport chip instead" | shown only when `identityPolicy` is `"zk-or-chip"`; it starts the chip path of task 4.6; hidden for `"zk"`, and for `"chip"` the zero-knowledge screen is hidden |
| P4.8-11 | The proof takes 50 s, or the phone app never answers | the screen shows progress, then a timeout with "Try again"; the app never signs without a result |
| P4.8-12 | Spy test: nothing from the passport (MRZ, name, photo) is posted | the requests carry only the proof, the result and public values |
| P4.8-13 | Playwright flow with the mocked SDK on Chromium and WebKit | onboarding and release both pass on both |

**Think.** The party app is only a request builder and a result forwarder. The proof is made on the party's own phone app (ZKPassport's), not in our code. We check the proof on our side (adapter and console), never by trusting the SDK result alone.

**Test in all directions.** Mock each callback in a wrong order. Send a proof for a different scope, a different bound value or an expired validity. Run with the ZK registry down (the adapter returns an error, and the console shows "Cannot check now" and blocks, never passes).

**Think hard.** ZKPassport proves passive authentication only. It does not prove that the chip was present (DESIGN 10.1). The screens must not say "chip verified". The release proof is bound to a fresh ledger hash so a recorded proof cannot be replayed at another time. `devMode` accepts mock certificates, so it must never run outside the demo profile. The SDK is pre-1.0 and not externally audited, so pin the exact version.

**Implement.** `apps/web/src/routes/party/passport/` (request builder, the bind-length check, QR, callbacks, salt handling) and `apps/web/src/routes/lawyers/passport/` (onboarding verify and the encrypted facts, lawyer nonce, result list, trust record view, adapter call, optional local re-verify).

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 4.9 Post-quantum keys in the browser: the 2-of-3 binding screen (noble post-quantum ML-DSA-65)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| LW1 | Sonnet | medium | M (4 h) | 1.16, 4.2, 4.7 |

**Research.** DESIGN 6.3 and 6.13. r8-pq.md. `@noble/post-quantum` 0.7.1 has `ml_dsa65`. It is not audited and not constant-time. Sizes: public key 1,952 B, signature 3,309 B, signing about 9 ms on a laptop. Each of a slot's three holders has its own ML-DSA-65 enrollment key (DESIGN 6.3). `pqKeyHash_slot` is the SHA-256 of the slot's three holder ML-DSA-65 public keys in role order, and it is in the seal. The binding message is `pqBindMsg = tupleHash("legx/pq-binding/v1", [dealSeal, slotPub, pqKeyHash_slot])`. **Any two holders** sign it with ML-DSA-65, and the slot key cross-signs it (a FROST signature, task 4.7). There is no separate single post-quantum key per slot, so a lost phone does not lose the slot's post-quantum binding.

**Test first.** Browser mode, Chromium and WebKit.

| ID | Test | Expected |
|---|---|---|
| P4.9-01 | Generate an ML-DSA-65 key; store the 32-byte seed only, encrypted under the same scheme as shares (task 4.2) | the public key is 1,952 B; IndexedDB holds the seed ciphertext only, not the expanded secret key |
| P4.9-02 | Reload and sign | the seed is decrypted inside the signing call, the key is expanded, the signature verifies, and the buffers are zeroed |
| P4.9-03 | The binding screen: the phone signs `pqBindMsg` with its ML-DSA-65 enrollment key, a second holder (the second authenticator for a client; the HSM or partner for a lawyer) signs it too, and the slot key cross-signs | the two holder signatures and the cross-signature verify in the core `verifyPqBinding` (task 1.16); the event `pq.bound` appears |
| P4.9-09 | Only one holder signs | the binding is not accepted (2 of 3 needed); the screen shows "waiting for a second holder" |
| P4.9-10 | The phone is lost: the other two holders (and the new phone after repair) sign the binding | the binding verifies with any two holders; no new binding scheme is needed |
| P4.9-04 | The screen shows the `pqBindMsg` fields it computed itself (`dealSeal`, slot key, `pqKeyHash_slot` from the three holders' keys in role order) | they match the seal; a seal mismatch refuses to sign |
| P4.9-05 | Spy test over key creation, signing and binding | no seed or secret key leaves the device; the public key and signatures go out |
| P4.9-06 | A coordinator that swaps one holder's ML-DSA-65 key | the phone recomputes `pqKeyHash_slot` from the keys it pinned (task 4.7) and the screen shows "Key mismatch" |
| P4.9-07 | Timing on a mid-range phone profile (4x CPU throttle; a real Android as a manual test) | key generation plus binding under 1.5 s on the throttled profile; the screen shows a progress state |
| P4.9-08 | noble ML-DSA-65 known-answer vector from the core tests (T-U-27 inputs) | the browser output equals the vector |

**Think.** The seed is the only stored secret. The expanded key is rebuilt for each signing call and dropped. The binding screen is the browser half of DESIGN 6.13. The slot key's cross-signature uses the same FROST path as other signatures.

**Test in all directions.** Run on Chromium and WebKit. Corrupt the seed ciphertext. Cancel the passkey prompt in the middle of the binding. Reload between the two signatures: the binding must not be submitted half-signed.

**Think hard.** noble post-quantum is not audited and not constant-time, which matters little for a single-user browser but is stated on the screen's help text and in the repo notes. Enrollment keys must be bound to the deal before any release (a deal without all four bindings fails `PQ_BINDINGS_OK` at the release gate, DESIGN 6.17).

**Implement.** `packages/vault/src/pq/` (key store, signing, `pqKeyHash_slot` check) and `apps/web/src/routes/party/pq-binding/` (screen). The lawyer slots use the same package with the lawyer roles.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 4.10 Signing-code integrity

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| LW1 | Sonnet | high | M (6 h) | 4.1, 4.2 |

In a web app, whoever serves the page code could copy decrypted shares. This task makes the signing code (the vault and FROST) a **reproducible static bundle with a published hash**, served from a **separate origin** that the coordinator cannot change. The vault refuses to run if its own hash does not match the published release (DESIGN 6.4, code integrity). A native app or a browser extension is stronger and comes later (DESIGN O18).

**Research.** DESIGN 6.4 (code integrity, and what this protects honestly) and 10.1 (the coordinator-is-hacked row). Vite 8 reproducible builds: fixed lockfile, no timestamps, sorted and content-hashed output files, `SOURCE_DATE_EPOCH`, the same Node version in Docker and locally. Subresource Integrity and its limit (cross-origin iframes get no SRI). CSP level 3 (`script-src 'self'`, `require-trusted-types-for 'script'`, `frame-ancestors`, `base-uri`, `connect-src`), and `Cross-Origin-Opener-Policy` and `Cross-Origin-Embedder-Policy` headers. How a vault on its own origin talks to the app: the app embeds the vault in an iframe from the vault origin and uses `postMessage`; browser storage is per origin, so the shares sit only in the vault origin. This shape is chosen here, and the repo notes record it as a decision to add to DESIGN 6.4.

**Test first.** Chromium and WebKit through Playwright; the build tests run in CI.

| ID | Test | Expected |
|---|---|---|
| P4.10-01 | Reproducible build: build the vault bundle twice, once in Docker and once on the host | the two outputs are byte for byte equal, and the manifest SHA-256 is the same |
| P4.10-02 | Published hash: the release step writes `release.json` (version, the SHA-256 of every file, the manifest hash), signs it with the release key, and publishes it at a well-known URL on a host that is neither the coordinator nor the app origin, and in the git tag | the hash in `release.json` equals the hash of the built files; the signature verifies; the git tag holds the same hash |
| P4.10-03 | The vault refuses to run on a mismatch: change one byte of one JavaScript file; add an extra file; remove one; swap `index.html` | on any change the vault shows "Code does not match the published release", decrypts no share, and `signFrost` throws `CODE_HASH_MISMATCH` |
| P4.10-04 | The coordinator cannot change the bundle: the coordinator's deploy credentials and config have no write access to the vault origin (a config check of the hosting setup), and the coordinator serves a changed copy of the app shell | the vault origin still serves the published bundle; a changed app shell cannot make the real vault sign a message the user did not approve (the vault shows its own decoded summary and asks for the second authenticator) |
| P4.10-05 | A fake vault origin: the coordinator's app shell points its iframe at another origin | the fake origin has no stored shares, so nothing can be signed; the app shell pins the vault origin and refuses another one; the first-use screen shows the vault origin and short hash for the user to compare with the published release |
| P4.10-06 | CSP on the vault origin: the response headers hold `default-src 'none'`, `script-src 'self'` (no `unsafe-inline`, no `unsafe-eval`), `require-trusted-types-for 'script'`, `base-uri 'none'`, `frame-ancestors` for the app origin only, and a short `connect-src` list (relay and ledger hosts) | a header test reads each one; the policy is the same in the production profile |
| P4.10-07 | A CSP that blocks inline and foreign scripts: inject an inline script, a `javascript:` URL, an `eval` call, and a script from another host into the vault page | all four are blocked and a violation report is sent to the report endpoint; none runs |
| P4.10-08 | The built bundle has no third-party script and no external URL for code (a scan of the output), every script and style tag has an integrity attribute, and the lockfile is committed with exact versions | the scan finds none; the build fails if a dependency range is loose |
| P4.10-09 | Rollback: serve an older bundle with a valid older hash after the signed `release.json` names a higher minimum version | the vault refuses the old version |
| P4.10-10 | The party app and the lawyer console show the vault version and the short hash | they equal `release.json`; a mismatch shows a red banner and blocks signing |
| P4.10-11 | The service worker (task 4.1) never caches the vault bundle under another hash: update the bundle, then reload | the new bundle's hash is checked on every load; an old cached copy is not run if it differs from `release.json` |

**Think.** The vault checks the hash of every file it loads against the signed manifest before it touches a share. The check runs before any key call. The separate origin means a hacked coordinator, which serves the app shell and the API, cannot change the code that holds the shares.

**Test in all directions.** Change each file type in turn (JS, WASM, HTML, CSS). Put a malicious proxy between the phone and the vault origin that stands in for the coordinator. Run the tamper tests on Chromium and WebKit, on a slow network, and with the service worker on and off.

**Think hard.** A self-check can be skipped by a replaced bundle, so it does not protect against whoever controls the vault origin itself. What protects is the combination: a reproducible build lets anyone (the lawyers' IT, an auditor) rebuild and compare with the published hash; the vault origin is controlled apart from the coordinator; and the first-use screen lets the user compare the hash. Say this limit in the repo notes and on the screen. Native or extension builds (DESIGN O18) remove the problem and come later.

**Implement.** `apps/vault-host/` (static host config, security headers, the `release.json` loader), `tools/release-hash/` (manifest, hash, signature, the reproducible build script and the Docker file), and `packages/vault/src/integrity.ts` (the boot-time check and the `CODE_HASH_MISMATCH` error).

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### Phase 4 end-to-end suite (E2E-P4)

| ID | Scenario | Expected |
|---|---|---|
| E2E-P4-01 | Playwright with 4 contexts (Alice phone, Bob phone, lawyers laptop, dashboard) against MSW, with FROST signing (two-share on the phones, console plus co-signer on the laptop), zero-knowledge proofs (mocked SDK) and post-quantum bindings | the full flow from P0 to P8 completes in the UI; every slot signs with FROST; both parties onboard and release with a proof; all four bindings are made |
| E2E-P4-02 | The same flow against the real server (G3) and the standalone ledger, with the real demo-profile ZKPassport SDK and ZKR mock passports (`devMode`) | every step validated; the dashboard shows each one, including `frost.dkg.completed`, `frost.signed`, `identity.onboarded` and `pq.bound` |
| E2E-P4-03 | The full HAR of E2E-P4-02, searched for every secret the run made (FROST shares, nonces, PRF outputs, ML-DSA seeds, release code, DG1, SOD, passport MRZ data) | none found outside the `EscrowFinish` fulfillment, which is public by design |
| E2E-P4-04 | The chip fallback: a deal with `identityPolicy` `"zk-or-chip"` where one party uses the fixture chip path (task 4.6 fixtures) | the release gate shows `nfc-chip` for that party and `zkpassport` for the other; the release passes |
| E2E-P4-05 | Phone recovery in the full flow: Alice loses her phone after P5, starts recovery with a fresh proof and a face match, waits out the 72-hour delay (controlled clock), repairs and refreshes with her security key and the recovery agent, and signs the exit | the exit validates; an old share plus a new share does not combine; both lawyers and the old device got notices |
| E2E-P4-06 | Alice's old phone cancels a recovery that Mallory started during the delay | the recovery is cancelled; no recovery share signs; the cancel is on the dashboard |
| E2E-P4-07 | A lawyer exit with the firm HSM: the console shows the approval prompt; one run is cancelled, one is approved | the cancelled run signs nothing; the approved run validates |
| E2E-P4-08 | The signing code is tampered at the app origin (one byte changed in a copy served by a hostile proxy) and at the vault origin (a test bundle with a changed hash) | the vault refuses to run on the changed bundle; the real vault origin keeps working |
| E2E-P4-09 | Single-device mode: a client uses a same-phone passkey as share 2 | the label shows on every summary and in the deal record; the deal still completes |
| E2E-P4-10 | The 2-of-3 binding: one slot's binding is made by the second authenticator and the recovery agent (the phone is not used) | `pq.bound` appears and `PQ_BINDINGS_OK` passes |

**Phase 4 exit gate (G4):** E2E-P4-01 to 10 green, P4.7 to P4.10 browser-mode and tamper tests green on Chromium and WebKit, the phone speed budgets met (P4.7-11, P4.9-07), visual baselines approved, accessibility checks clean, and the HAR scan (E2E-P4-03) clean for shares and ML-DSA seeds as well as the older secrets.

---

## 9. Phase 5: Hardening, formal model and demo readiness

**Goal.** Prove the rules with tools that do not depend on our own tests: a formal model, fuzzing, a second implementation and mutation testing. Then make the demo safe to run in front of judges.

**Owns:** `spec/`, `tools/fuzz/`, `tools/py-ref/`, `stryker.config.*`, `.github/workflows/nightly.yml`, `demo/`, `docs/RUNBOOK.md`.

**Starts:** tasks 5.1 to 5.3 after G0 (they need only the contracts and the design). Tasks 5.4 to 5.7 after G1 to G4 as noted. **Covers DESIGN:** 12.1 (formal, fuzz, differential, mutation, end to end), 11.3, 15 (O13 demo profile) and milestone M6.

### 5.1 Quint model (T-F-01)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L9 | Opus | xhigh | M (6 h) | G0 |

**Research.** The Quint docs for `run`, `verify` with Apalache, and the TLC backend flags (section 4.2 lists the version). DESIGN Appendix C is a sketch that was never run.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P5.1-01 | `quint typecheck spec/deal.qnt` | passes |
| T-F-01a | `quint run` with invariants `invLockedBeforeFunds`, `invFourSigs`, `invGateBeforeFunds` (I8), `invOneExit` (I5), `invClosedFinal` (I6), 30 steps, 10,000 runs | no violation |
| T-F-01b | `quint verify` (Apalache) for the same invariants, bounded to 30 steps | no violation |
| T-F-01c | liveness "eventually CLOSED" under fairness (TLC) | holds |
| P5.1-02 | Mutation of the model: remove the gate guard on release | `invGateBeforeFunds` is violated, and the counterexample is printed (proves the invariant has teeth) |
| P5.1-03 | Attacker actions: `plantRegularKey` while the master key is on, `singleSignedExit`, `strangerFinish`, `skipPassport` | invariants still hold |
| P5.1-04 | FROST slot state: each slot has `sharesAvailable` (0 to 3). Actions: `shareJoins`, `shareLost`, `slotSign` | the model type checks and runs |
| P5.1-05 | Invariant `invTwoShares`: a slot with fewer than 2 shares available never produces a signature | no violation in `quint run` and `quint verify` |
| P5.1-06 | Invariant `invTwoPassports`: no release without two valid passport attestations, each of an allowed identity method (`zkpassport` or `nfc-chip`, as the `identityPolicy` allows) | no violation in `quint run` and `quint verify` |
| P5.1-07 | Model mutations: let `slotSign` run with 1 share; let release run with one attestation; let release accept a method the policy forbids | `invTwoShares` or `invTwoPassports` is violated each time, and the counterexample is printed |
| P5.1-08 | Attacker actions: `soloAgentSign` (recovery agent share alone), `outsidePolicyShare` (a share from a participant outside the slot policy) | invariants still hold |
| P5.1-09 | Recovery delay and cancel: each slot has `recoveryState` (`none`, `pending`, `cancelled`, `done`) and a clock in hours. Actions: `recoveryStart` (needs a fresh proof with the same identifier plus a face match for a client, or an operations-account request for a lawyer), `tick`, `recoveryCancel` (by the old device), `recoverySign` (with the recovery shares) | the model type checks and runs |
| P5.1-10 | Invariant `invRecoveryDelay`: `recoverySign` never happens fewer than 72 hours after `recoveryStart`, and never after `recoveryCancel` | no violation in `quint run` and `quint verify` |
| P5.1-11 | Slot rotation: actions `compromiseShare` (a share is known stolen) and `rotateSlot` (a new DKG, then a 4-of-4 `SignerListSet`, then a new seal; a lawyer slot also needs a new contract signature and NFT). Invariants: `invRotateNeedsAll` (rotation happens only when all four slots signed), `invOldKeyDead` (after rotation, the old slot key never signs an exit) | no violation in `quint run` and `quint verify`; a refresh alone (no rotation) after `compromiseShare` leaves the slot marked unsafe, never safe |
| P5.1-12 | Model mutations: let `recoverySign` run at hour 0; ignore `recoveryCancel`; let `rotateSlot` run with three slots signed; let the old key sign after rotation | `invRecoveryDelay`, `invRotateNeedsAll` or `invOldKeyDead` is violated each time, with the counterexample printed |
| P5.1-13 | Attacker actions: `earlyRecoverySign`, `signAfterCancel`, `staleEpochSign` (a share of the old epoch after a rotation), `rotateWithoutOneSlot` | invariants still hold |

**Think.** Model the version 1.0 states, including the identity method (A zero-knowledge, B chip), the FROST slot state, the 72-hour recovery delay with cancel, and slot rotation on the ledger. Represent each release-gate check as one boolean. Attacker moves are separate actions.

**Test in all directions.** P5.1-02 (mutate the model). The conformance replay of 1,000 traces through `machine.ts`.

**Think hard.** A model that matches the code is worth more than a model that matches the doc. Add a conformance test: export 1,000 random traces from `quint run`, replay each through `machine.ts` (task 1.14), and require the same final state.

**Implement.** `spec/deal.qnt`, extended from DESIGN Appendix C, with the FROST slot state, the identity method, the recovery delay and cancel, and slot rotation added.

**Done when.** T-F-01a to c and P5.1-01 to P5.1-13 pass, and the conformance replay matches.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 5.2 Fuzzing (T-Z-01)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L9 | Sonnet | medium | M (4 h) | G1 |

**Research.** Section 4.2: fast-check properties are the main fuzzer, and Jazzer.js covers byte parsers.

Targets: the condition and fulfillment parser, `decodeMintMemo`, the gate memo parser, the SOD and DG1 parsers, `verifyAttestation` input parsing, DSSE envelope parsing, and every API request schema. New targets for version 1.0: FROST round messages (DKG rounds 1 and 2, commitments, signature shares), **complaint messages** (the signed complaint with its ciphertext, DESIGN 6.4), ZK proof result parsing (the `ZkVerifierPort` input and the `zk_proof` record), **trust records** (the chain ID, registry root, circuit manifest version, key hashes, identifier type and `dev_mode` record, DESIGN 6.10), hybrid envelopes (`sig_algs` and both signatures), C2SP signed-note lines of type 0x06 (ML-DSA-44), and X-Wing ciphertexts. The tool is the one picked in section 4.2.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| T-Z-01 | 10 minutes per target nightly; 30 seconds per target on pull requests | no crash, no hang over 1 s, no uncaught exception |
| P5.2-02 | The seven new targets (FROST round messages, complaint messages, ZK proof result, trust record, hybrid envelope, C2SP 0x06 line, X-Wing ciphertext) run in the same nightly and pull request jobs | no crash, no hang over 1 s; a bad X-Wing ciphertext is rejected, never accepted |
| P5.2-03 | Complaint message fuzz: random bytes, and valid complaints with one field changed (the accused, the round, the ciphertext, the signature) | no crash; a complaint is accepted only when its signature verifies and the ciphertext really fails its check; an accepted complaint round-trips |
| P5.2-04 | Trust record fuzz: random bytes, and valid records with one field changed or missing (chain ID, root, manifest version, key hash, identifier type, `dev_mode`) | no crash; a record with a missing field is rejected; a record with chain 11155111, a mock identifier type or `dev_mode: true` parses but is flagged, so the production gate refuses it; an accepted record round-trips |
| P5.2-01 | Every crash input found is saved to `tools/fuzz/corpus/<target>/` and becomes a unit test | committed |

**Think.** One fuzz target per parser. Each is a property from `fc.uint8Array()` to the parser, which must return a result and never throw.

**Test in all directions.** Seed the corpora from the test vectors and the fixtures, including the FROST vectors (T-U-21), the DKG transcripts and complaints (T-U-29), the post-quantum vectors (T-U-27), the mock-passport proofs (T-U-28) and the recorded trust records (T-U-32).

**Think hard.** A parser that throws is a denial of service. A parser that accepts garbage is worse. So each target also checks that accepted input round-trips.

**Implement.** `tools/fuzz/targets/*.ts`.

**Done when.** Every target runs in CI, and the corpora are committed.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 5.3 Second implementation and differential tests (T-Z-02)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L9 | Sonnet | medium | L (12 h) | G0; tasks 1.15, 1.16 and 1.17 for the cross-tests |

**Research.** xrpl-py's latest version and its binary codec API. ZF `frost-ed25519` 3.0.0 (its CLI-friendly API and the vector files). The second ML-DSA implementation (for example Python `dilithium-py` or the `liboqs` bindings; pick one and record the version).

**Test first.**

| ID | Test | Expected |
|---|---|---|
| T-Z-02 | 10,000 random transactions of every type we use: xrpl.js and xrpl-py encode byte for byte the same | equal |
| P5.3-01 | A Python reference (`tools/py-ref/legx_ref.py`, under 300 lines) of `tupleHash`, the deal seal (29 fields), the signed-contract seal, `opsBindMsg`, `presenceMsg`, the condition, `slotPolicy(slot, roles)`, `pqKeyHash_slot`, `pqBindMsg` (it holds `pqKeyHash_slot`, not a single `pqPub`) and the salted ZK identity commitment `C_side = tupleHash("legx/zk-identity/v1", [zkSalt32, utf8(N_side)])` | equals the TypeScript golden vectors from 1.5, 1.6, 1.12, 1.15, 1.16 and 1.17 |
| P5.3-02 | Random inputs: TypeScript and Python give the same bytes | equal for 10,000 cases |
| P5.3-03 | The 29-field deal seal: Python and TypeScript hash the same field list; change each field in turn | the seal changes for every one of the 29 fields, and both languages agree |
| P5.3-04 | FROST cross-test: a small Rust CLI in `tools/frost-ref/` built on ZF `frost-ed25519` 3.0.0 reads the RFC 9591 E.1 and ZF vectors, and signs and verifies with fixed shares | a signature made by noble `ed25519_FROST` verifies in the Rust CLI, and a signature made by the Rust CLI verifies in noble, for 100 random messages |
| P5.3-05 | FROST refresh cross-test: refresh shares with our code and check the group key stays the same; verify with the Rust CLI | the group public key is unchanged, and signatures verify in both |
| P5.3-06 | ML-DSA cross-tests: noble `ml_dsa65` against Node built-in ML-DSA (Node 24.7 or later) against the second implementation, using the same keys and messages | every signature verifies in all three, for 200 random messages |
| P5.3-07 | `pqBindMsg` (with `pqKeyHash_slot`) signed by two holders in noble, verified in Node and in the second implementation | verifies in all three |
| P5.3-08 | `pqKeyHash_slot` = SHA-256 of the three holder ML-DSA-65 public keys in role order: Python and TypeScript for random keys; then the same keys in another order | equal bytes; a different order gives a different hash in both languages |
| P5.3-09 | The salted `C_side`: random salts and identifiers in both languages; change the salt, then the identifier, one byte at a time | equal bytes; `C_side` changes for every change; two equal identifiers with different salts give different `C_side` |
| P5.3-10 | `EXTERNAL_MU`: Python computes mu from the public key, the context `legx/dsse/v1` and the message (FIPS 204) | equals the mu of the TypeScript helper and the noble `internal.sign` input; a signature made over the Python mu verifies in Node with the context |

**Think.** The arbitrator's verifier might be rewritten in another language one day. The Python reference proves the recipes in DESIGN 6 are complete enough to implement from the text alone.

**Test in all directions.** Run with fixed seeds and with random seeds.

**Think hard.** The Rust CLI and the ZF vectors are the check on noble's FROST, which has no external audit. If Python and TypeScript agree but both are wrong, only the golden vectors catch it. Keep the DESIGN vectors as a third check.

**Implement.** `tools/py-ref/`, using uv and pytest, and `tools/frost-ref/` (a Rust CLI, built with cargo, pinned to `frost-ed25519` 3.0.0).

**Done when.** P5.3-01 to P5.3-10 and T-Z-02 pass.

**As built (5.3).** The tests are in `tools/differential` (`@legx/differential`, run with `pnpm vitest run --project unit tools/differential`, seeds 20261024 and 7 plus one random seed, `LEGX_DIFF_N` for the case count). P5.3-04 and P5.3-05 (the live ZF Rust CLI in both directions, and the refresh cross-test) are not done, because there is no Rust toolchain. The FROST comparison runs against a hand port, with byte-exact vectors.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 5.4 Mutation testing

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L9 | Sonnet | medium | S (4 h) | G1 |

**Research.** The StrykerJS 10.1.1 Vitest runner and its incremental mode. Killing mutants means writing new tests, so this task uses Sonnet, and the estimate is 4 hours, double the first guess.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P5.4-01 | StrykerJS on `packages/core` (incremental) | score at least 80 overall, at least 85 on `releaseGate.ts`, `lockcheck.ts`, `attest.ts`, `signedContract.ts`, `frost.ts`, `pq.ts`, `zkIdentity.ts` |
| P5.4-02 | Every surviving mutant in those seven files | either a new test kills it, or a comment in the test file explains why it is equivalent |

**Think.** Run it on `packages/core` only. Other packages use coverage gates.

**Test in all directions.** Run once with all mutators on the seven critical files, and once with the default set on the rest of the package.

**Think hard.** An equivalent mutant marked as killed hides a gap. Review each "equivalent" comment in the pull request.

**Implement.** `stryker.config.mjs` and a nightly job.

**Done when.** The thresholds are met and every survivor is killed or explained.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 5.5 Testnet and Devnet nightly (T-N-01)

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L9 | Sonnet | medium | M (4 h) | G2, G3; tasks 2.8 and 2.9 |

**Research.** Section 4.5: faucet limits and explorer patterns.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| T-N-01 | T-I-01 (the full flow) on Testnet and on Devnet, fresh keys each run | every step validated |
| P5.5-03 | T-I-11 (FROST-signed multisig) on Testnet | the FROST-signed transaction validates on the public ledger |
| P5.5-04 | T-I-12 (full flow with ZKPassport mock passports) on Testnet, with `devMode` and the Sepolia RPC | every step validated; the nightly skips with a clear message if the Sepolia RPC is down |
| P5.5-01 | A Credentials and NFT probe (create, accept, mint with memo) before the full run | fails fast with a clear message if the network changed |
| P5.5-02 | The nightly never blocks a pull request; a failure opens an issue with the run log | as stated |

**Think.** Fresh keys each run. Fund through the faucet with backoff.

**Test in all directions.** Run on Testnet and on Devnet.

**Think hard.** A Testnet seed must never reach logs or artifacts. The run writes no seed to disk.

**Implement.** `.github/workflows/nightly.yml` and `packages/xrpl/test-int/network.int.ts`.

**Done when.** The nightly runs T-I-01, T-I-11 and T-I-12 on Testnet, and T-I-01 on Devnet.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 5.6 Demo profile, seeding and runbook

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L10 | Sonnet | medium | M (6 h) | G3, G4 |

**Research.** Section 4.4 (tunnel choice). The DESIGN demo profile table (section 3 of this doc).

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P5.6-01 | `pnpm demo:seed --network testnet` funds the 6 accounts (one faucet call each, up to 1,000 XRP, about 6 s each), onboards both lawyers (0a, 0b) and writes `demo/state.json` | idempotent: a second run changes nothing and makes no faucet call |
| P5.6-02 | `pnpm demo:prestart` starts deal #2 and stops before release, so the expiry and close scenes are ready 30 minutes later | the deal is in `VERIFIED` with a short `CancelAfter` |
| P5.6-03 | `pnpm demo:check` (the morning of the demo): ledger reachable, accounts funded, tunnel up, phones can open the URL, Postgres up, fixture passports load, the Sepolia RPC reachable, the recovery-agent laptop up, the firm HSM co-signer process up, a FIDO2 security key registered for each demo phone (or the single-device label confirmed), the ZKPassport app installed on both phones with developer mode on and a ZKR mock passport loaded | prints a green or red line per item |
| P5.6-07 | `pnpm demo:seed` also runs the FROST DKG for the demo slots, binds the post-quantum keys, and records the ZKPassport app state (app installed, developer mode on, ZKR mock passport loaded) as a checklist in `demo/state.json` | idempotent; the checklist items that need a human are listed as manual |
| P5.6-09 | `pnpm demo:rehearse` runs the full flow with ZKPassport's headless prover (the vendored `packages/e2e/src/prove.ts`, about 10 s to prove and 0.65 s to verify) in place of the phones, for rehearsals and for CI | the flow completes with mock proofs and no phone; the same recorded trust records pass the demo profile; it is refused in the production profile |
| P5.6-10 | Share 2 in the demo: each demo phone has its own FIDO2 security key with PRF; if a key is missing, the phone uses single-device mode | the demo screens show the label "Single-device mode" whenever a phone has no separate key; the runbook script tells the presenter to say so aloud; `demo:check` lists each phone as `security key` or `single-device` |
| P5.6-08 | The recovery-agent laptop and the firm HSM co-signer process start from `pnpm demo:prestart` | both answer a health check; `demo:check` shows them green |
| P5.6-04 | `pnpm demo:fallback` switches every service to the local standalone ledger | the same flow works offline |
| P5.6-05 | The DESIGN demo profile section is added and every shortcut is listed (mock registry, fixture passports, local key file, local folder for WORM, in-process log) | reviewed |
| P5.6-06 | A recorded backup video of the full run exists | file present in `demo/` (not in git if large) |

**Think.** Every script is idempotent and can resume. Its state lives in `demo/state.json`.

**Test in all directions.** Run `demo:check` with each dependency down in turn.

**Think hard.** The demo must survive a dead Wi-Fi. Rehearse the P5.6-04 fallback twice.

**Implement.** Scripts in `demo/`, plus `docs/RUNBOOK.md` (with a phone setup page for the ZKPassport app and the mock passport, how to register the FIDO2 key on each phone, the single-device wording, and the headless rehearsal command).

**Done when.** `demo:check` is green on the demo laptop and both fallbacks have been rehearsed.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 5.7 Security review pass

| Lane | Model | Effort | Size | Depends on |
|---|---|---|---|---|
| L10 | Opus | max | L (8 h) | G4 |

**Research.** DESIGN 10.1, the adversarial review of 24 Oct 2026, and IMPLEMENTATION Appendix B.

Walk DESIGN 10.1 row by row, including the new threats of version 1.0: FROST nonce reuse, recovery-agent collusion, a forged ZK proof, ZK does not prove chip presence, the ZK registry down, quantum attack, and a stripped hybrid signature. Also the rows added by the security audit: a coordinator that swaps an enrollment key (the key directory), a key-generation transcript shown differently to different holders, a stolen lawyer share, the firm HSM asked to sign without the lawyer's approval, a recovery started by an attacker, a copied-chip-data proof with no face match, a Sepolia or mock proof in production, hostile signing code served to the browser, and a checkpoint with a stripped ML-DSA line. For each threat, name the test that proves the control, and run it. Then repeat the adversarial review from 24 Oct 2026 against the code, not the doc. An external audit of noble's FROST and post-quantum code and of ZKPassport is recommended before real users.

**Test first.**

| ID | Test | Expected |
|---|---|---|
| P5.7-01 | Every row in DESIGN 10.1 has a test ID that exists and passes | a script checks the table against the test names |
| P5.7-02 | No private key, release code or raw passport crosses the network (HAR capture of a full Playwright run, searched for every secret the run made) | none found |
| P5.7-03 | `pnpm audit --prod` and a licence check | no high or critical issues; no copyleft in shipped code |
| P5.7-04 | Each new threat row has a test ID that exists and passes (T-U-22 nonce reuse, T-P-01 one share alone, T-U-28 forged proof, T-U-24 stripped signature) | a script checks the rows |
| P5.7-07 | Each audit threat row has a test ID that exists and passes: key-directory swap (T-U-29), transcript shown differently (T-U-29), stolen lawyer share and the HSM without approval (T-U-31, T-I-05), recovery by an attacker (T-U-31), a copied-chip-data proof without a face match and a Sepolia or mock proof in production (T-U-28, T-U-32), hostile signing code (P4.10-03 to P4.10-07), a stripped ML-DSA checkpoint line (T-U-26) | a script checks the rows |
| P5.7-08 | The control is on in the production profile: the HSM approval rule, the 72-hour delay, the both-lines checkpoint policy, the Sepolia, mock and `devMode` refusal, and the vault hash check | a config test runs each control against the production profile, not only the demo profile |
| P5.7-09 | The honest limits are written in the report: a quantum break of Ed25519 lets an attacker move the money until the ledger migrates; refresh is hygiene, not revocation; single-device mode loses theft protection; a self-check cannot protect against whoever controls the vault origin | all four are in `docs/` and in the runbook's security section |
| P5.7-05 | The review report states that noble's FROST code, noble's post-quantum code (`@noble/post-quantum`) and ZKPassport (`@zkpassport/sdk`) have no external audit, and recommends an external audit before real users | the statement is in `docs/` and in the security section of the runbook |
| P5.7-06 | Versions are pinned for `@noble/curves`, `@noble/post-quantum`, `@zkpassport/sdk`, `@zkpassport/utils` and `@zkpassport/registry`; the ZK verifier runs in `local` mode with the domain `"legx.app"`, and `devMode` is off outside the demo profile | a test and a config check pass |

**Think.** Rank each threat by damage and by how easy the attack is. The new ones touch the signing keys, so check them first.

**Test in all directions.** Attack the running demo by hand: reuse a FROST nonce, strip a post-quantum signature or a checkpoint line, replay a ZK release proof, swap an enrollment key at the relay, ask the HSM to sign without approval, start a recovery and race the delay, and use a recovery-agent share alone.

**Think hard.** A control that has a test but is off in the demo profile is not a control. Check the production profile next to the demo profile. The review is done by a model that did not write the code.

**Implement.** The review notes in `docs/`, plus `tools/threat-check.ts` rows for the new and audit threats.

**Done when.** P5.7-01 to P5.7-09 pass, and the findings are fixed or logged as DQs.

**As built (5.7).** The review ran in break-it mode. Its attack tests are in `tests/break-it` (run with `pnpm vitest run --config tests/break-it/vitest.config.ts`). Each failing test is intended and names the I-S finding it proves; the passing ones are controls. Findings are logged in `build/ISSUES.md`, not fixed there.

**Phase 5 exit gate (G5):** T-F-01 (with the recovery delay and rotation invariants), T-Z-01, T-Z-02 and T-N-01 green; the FROST and ML-DSA cross-tests green; T-I-11 and T-I-12 green on Testnet; mutation thresholds met; `demo:check` green on the demo laptop.

---

## 10. Phase 6: System test and regression

**As built (phase 6).** The tests are in `tests/system` (`@legx/system-tests`, project `system`). They start the real `apps/server` process in the demo profile and check every route, topic, event kind and port. Known broken links are `it.fails` with their issue ID, and `tests/system/REGRESSION.md` maps every issue to its test.

**Goal.** Test the whole system as one product, the way the judges and a real arbitrator will use it. Then freeze a regression suite that runs on every change from here on.

**How the six steps apply here.** This phase builds no features, so the loop runs once for the whole phase:
1. **Research.** Read the failure reports from Phases 1 to 5, the DESIGN threat table, and the demo runbook. List what can break in front of judges and in real use.
2. **Test.** Write the SYS tests below before fixing anything they find.
3. **Think.** For each SYS test, name the DESIGN invariant (I1 to I8) or threat row it guards.
4. **Test in all directions.** Real devices (one iPhone, one Android phone), slow networks, a dead ledger connection, a killed server, two people pressing the same button, and the production profile next to the demo profile.
5. **Think hard.** Look for false passes: a test that passes because a step was skipped, a mock that hides a failure, a flaky test marked green.
6. **Implement.** Fix each bug found, in the lane that owns the code, with a regression test. Then freeze the suite (6.5).

**Owns:** `e2e/`, `.github/workflows/regression.yml`. **Starts:** after G4 (it can be written earlier against the frozen contracts, but runs only on the full system). **Lane:** L11, Sonnet, effort high, about 2 days. Task 6.4 uses Opus, effort xhigh.

**Think.** One row per threat. One test per row.

**Test in all directions.** Also try each attack by hand in the running demo.

**Think hard.** Any new finding becomes a DQ, or a bug with a test, before G5.

**Implement.** `tools/threat-check.ts`, which compares DESIGN 10.1 with the test catalogue.

**Done when** the tests above pass, the added tests from "Test in all directions" pass, and the task meets the definition of done in section 1.2.

### 6.1 Full flows through the real web apps

Playwright drives 4 roles at once: Alice and Bob in phone-sized contexts, both lawyers in one desktop context, plus the dashboard. The ledger is standalone on pull requests and Testnet nightly.

| ID | Flow | Expected |
|---|---|---|
| SYS-01 | Happy path, phases P0 to P8, through the UI only | Bob paid; wallet closed; every DESIGN 7.3 step validated; the dashboard shows each step |
| SYS-02 | Refund path | Alice refunded; closed |
| SYS-03 | Expiry: lawyer B never releases; time passes `CancelAfter` | `EscrowCancel`; Alice refunded; shell closed |
| SYS-04 | Dispute: notice, award to Alice, 4-of-4 exit per the award | refunded; the award is in the evidence chain |
| SYS-05 | Lawyer B is replaced before release | new bar check, new NFT, new seal, new DepositPreauth; the release works with the new lawyer only |
| SYS-06 | A passport check fails, then passes on retry | the gate blocks, then passes; both attempts are in the evidence log |
| SYS-07 | Alice's side refuses the passport check (D21 trade-off); then a second case where Alice refuses to sign the 4-of-4 seal update that an identity-method change needs (DESIGN 6.10) | release never happens; refund at `CancelAfter`; each refusal is recorded in the evidence log (this is how O9, a stall at release, shows in the tests) |
| SYS-08 | Alice's phone is lost. She starts recovery with a fresh ZK proof (same identifier) and a face match, waits out the 72-hour delay (controlled clock), signs with her security key share plus the recovery agent's share (2 of 3), repairs a share onto a new phone, and refreshes | the notices went to the old device and both lawyers; the exit is signed and validates; the refresh keeps the same slot key; the ledger does not change (same account, same signer list, no `SignerListSet`); an old share plus a new share does not combine; `frost.refreshed` is not complete until every remaining holder's deletion statement is in the log |
| SYS-09 | Full flow with zero-knowledge proofs (ZKR mock passports, `devMode` on, Sepolia RPC) | onboarding and release proofs verify in local mode; Bob paid; the evidence has both proofs; same flow as T-I-12 through the UI |
| SYS-10 | Fallback to the chip path when `identityPolicy` is `zk-or-chip` and the ZK proof cannot be made | the gate passes with a chip attestation (`method: "nfc-chip"`); with policy `zk` the same case blocks |
| SYS-11 | Release blocked: the ZK release proof is bound to an old ledger hash (`presenceMsg` differs) | the gate blocks; a new proof for the current ledger hash passes |
| SYS-12 | A lawyer's partner leaves the firm: a share refresh onto a new partner (lawyer recovery needs a request signed by the operations account) | the slot key is unchanged; an old share plus a new share does not combine; `frost.refreshed` is complete only with every remaining holder's deletion statement; no new bar check, NFT or seal is needed; the release works |
| SYS-13 | A hybrid envelope with the ML-DSA-65 signature stripped | the offline verifier rejects it and names the envelope |
| SYS-14 | A FROST nonce-reuse attempt (the same commitment used for a second message) | refused (T-U-22 at system level); no second signature share is produced |
| SYS-15 | The recovery agent alone tries to sign | refused: one share is not enough (T-P-01 at system level) |
| SYS-16 | Recovery waits out the delay and the old device cancels: Mallory (with the recovery agent's share and a stolen second share) starts a recovery; the old device presses Cancel at hour 40; later a real recovery runs its full 72 hours | no recovery share signs before hour 72 or after the cancel; the cancel is in the evidence log and on both lawyers' consoles; the real recovery completes after the delay (T-U-31 at system level) |
| SYS-17 | A stolen share is known: rotation on the ledger (a new DKG, a 4-of-4 `SignerListSet`, a new seal; for a lawyer slot a new contract signature and NFT) | only the new slot key signs the exit; the stolen share and the old slot key cannot; the lock checker passes with the new seal |

### 6.2 Attack scenes (the demo's attack mode, as tests)

| ID | Attack | Expected |
|---|---|---|
| SYS-A1 | A stranger submits `EscrowFinish` with the right code | `tecNO_PERMISSION`, shown on the dashboard |
| SYS-A2 | The master key is left on in a second deal | the lock check shows red; the release button stays off |
| SYS-A3 | Pay Bob and refund Alice, both fully signed on slot S | exactly one validates |
| SYS-A4 | One byte of the evidence bundle is changed | the offline verifier fails and names the file |
| SYS-A5 | A fake passport (wrong CSCA) | the attestation is refused at the lawyer console |
| SYS-A6 | A lawyer whose bar check is 31 days old | the gate blocks with `BAR_*_OK` |
| SYS-A7 | The coordinator shows a false payout address (a tampered response) | the phone app decodes the real transaction, compares it with the seal, and refuses (T-I-04) |
| SYS-A8 | Another client opens Alice's records | refused (T-A-31) |
| SYS-A9 | A stripped post-quantum signature (a hybrid envelope or checkpoint with only the Ed25519 part) | the offline verifier fails; the API refuses the envelope |
| SYS-A10 | A replayed ZK release proof (the same proof sent for a later release or another deal) | refused: the proof is bound to `presenceMsg` and the scope `legx/v1/<dealId>` |
| SYS-A11 | A FROST share from a participant outside the slot policy | refused at the relay; the aggregate never forms |
| SYS-A12 | The coordinator swaps an enrollment key (the recovery agent's, or the firm HSM's) before key generation | detected: the key is not in the anchored signed list; no slot key is made (T-U-29 at system level) |
| SYS-A13 | The firm HSM is asked to co-sign without the lawyer's user-verified approval, or with an approval over another message hash | refused; nothing is signed (T-U-31 at system level) |
| SYS-A14 | A proof made from copied chip data, with no face match | the release attestation is refused (`face_match_passed` false) |
| SYS-A15 | A Sepolia, mock-identifier or `devMode` proof presented in the production profile | refused by the gate and by the offline verifier (T-U-32 at system level) |
| SYS-A16 | A checkpoint with the ML-DSA (0x06) line stripped | our verifier refuses and names the line; a standard signed-note verifier alone would accept it, which is why both lines are required |

### 6.3 Resilience

| ID | Test | Expected |
|---|---|---|
| SYS-R1 | Kill the server at a random point in each phase, restart | the deal resumes in the right state; nothing is signed twice; no event is lost |
| SYS-R2 | Drop the ledger WebSocket for 60 s mid-deal | the watcher backfills; the dashboard catches up |
| SYS-R3 | A phone goes offline during signature collection, then returns | its signature is accepted if `LastLedgerSequence` has not passed; else a new request is made |
| SYS-R4 | Two lawyers press release at the same time | one `EscrowFinish` is built and sent |

### 6.4 Invariant monitor and privacy scan

| ID | Test | Expected |
|---|---|---|
| SYS-I1 | After every SYS test, a checker reads the ledger history and the evidence log and asserts I1 to I8 from DESIGN 5.1 | all hold |
| SYS-I2 | Search Postgres, the evidence folder, all logs, all exported spans and the HAR files for MRZ text, DG1 bytes, salts, private keys, FROST shares, ML-DSA seeds, and any passport data that should never leave the ZKPassport app (name, document number, date of birth, the raw proof inputs), the plain `zkSalt32`, and the decrypted disclosed facts outside the client's own lawyer's console | none found (T-A-32 at system level) |
| SYS-I3 | Every bundle produced by SYS-01 to 17 verifies offline, with the release gate rerun from the bundle | all pass |

### 6.5 The regression suite

1. **The catalogue.** `e2e/regression.md` lists every test ID in this doc and in DESIGN 12.2, with its file and the job that runs it. A script fails CI if an ID has no test, or a test has no ID.
2. **Tiers.**
   - Every pull request: unit, property, Phase 1 to 4 end-to-end suites, SYS-01, SYS-A1 to A16 and SYS-I1 to I3 on standalone. Target: under 15 minutes.
   - Nightly: everything, plus Testnet, fuzzing, mutation, Quint and SYS-R1 to R4, SYS-09 to SYS-17 (SYS-09 on Testnet too).
   - Before the demo: the full nightly set on the demo laptop, twice in a row.
3. **Flakes.** A test that fails once and then passes is a bug. Mark it quarantined within one day, with an issue. A quarantined test still runs and reports, but does not block. Nothing stays quarantined more than 5 days.
4. **Baselines.** Visual snapshots for the dashboard and the 3 phone screens; a performance budget (each validated step shown on the dashboard within 2 s of validation on standalone).

**Phase 6 exit gate (G6):** the regression catalogue is complete, the pull-request tier is green 10 times in a row, and the nightly tier is green twice in a row.

---

## 11. Phase 7: Cleanup

**Goal.** Remove what is stale or dead, and make the code as small as it can be while it stays clear. Smaller is not the goal by itself: 500 clear lines beat 200 clever ones. The goal is no code that nobody needs, and no code written twice.

**Starts:** after G6. **Lane:** L12. Tasks 7.1 to 7.3 use Haiku (effort low); task 7.4 uses Opus (effort high), because judging "simpler but still clear" needs judgment. About 1 day.

**How the six steps apply here.**
1. **Research.** Run the tool reports (knip, jscpd, dependency-cruiser, coverage, bundle sizes) and read them before changing anything.
2. **Test.** Record the full regression result and the mutation score as the baseline.
3. **Think.** For each finding, decide: delete, merge, simplify, or keep with a written reason.
4. **Test in all directions.** After each change, rerun the unit tests of the touched package. After each batch, rerun the full regression and mutation testing.
5. **Think hard.** Is the smaller version really clearer? Does a removed branch handle a real case that no test covers? If so, add the test and keep the branch.
6. **Implement.** Small pull requests, one kind of change each.

**Rule:** cleanup changes no behavior. The full regression suite (Phase 6) runs before and after, and the results must be the same.

### 7.1 Dead code and dependencies

| ID | Check | Expected |
|---|---|---|
| P7.1-01 | knip (section 4.2): unused files, exports, dependencies, types | zero findings, or each one listed in `knip.json` with a reason |
| P7.1-02 | Every `it.todo`, `TODO` and `FIXME` | resolved, or linked to a DQ in IMPLEMENTATION Appendix B |
| P7.1-03 | Feature flags and demo-only branches | each is behind the demo profile config and listed in the DESIGN demo profile |
| P7.1-04 | `pnpm why` on every dependency | each one has a user in shipped code or tests |
| P7.1-05 | The IMPLEMENTATION Appendix A starting code: leftover `dealSecret`, `deriveXKey` or deal-stamp code | `grep -rn "dealSecret\|deriveXKey\|dealStamp" packages services apps` finds nothing |
| P7.1-06 | Stub signers marked `stubbed:frost` | none left; every slot signs through the real FROST module |

### 7.2 Duplication

| ID | Check | Expected |
|---|---|---|
| P7.2-01 | jscpd over `packages/`, `services/`, `apps/` | no block over 15 lines repeated; hex, address and time helpers live in one module |
| P7.2-02 | One `tupleHash`, one `verifyXrplKeySig`, one envelope verifier, one ledger snapshot reader | a test imports each by its single path; a lint rule bans copies |
| P7.2-03 | One FROST module, one hybrid envelope module and one ML-DSA context and mu helper | every package imports `frost.ts`, the hybrid envelope code and the mu helper by their single paths; a lint rule bans copies |

### 7.3 Architecture rules

| ID | Check | Expected |
|---|---|---|
| P7.3-01 | dependency-cruiser: `@legx/core` imports nothing that does I/O; apps never import services' internals; no cycles | zero violations |
| P7.3-02 | Bundle size of the phone app | under the budget set in Phase 4 (section 8) |

### 7.4 Simplification review

For each package, a reviewer answers these questions in the pull request:
1. Is there a function that only forwards to another? Remove it.
2. Is there a type that equals another type? Merge them.
3. Is there a branch no test reaches (coverage report)? Remove it, or add the missing test if the branch is needed.
4. Is a long function long because the spec is long (keep it; the release gate is a list of rules and should read like one), or because it repeats itself (shorten it)?
5. Does a library already do this (section 4)? Use it, unless the library is larger than the problem.

| ID | Check | Expected |
|---|---|---|
| P7.4-01 | Lines of code per package, before and after | recorded in the pull request; no package grows |
| P7.4-02 | Mutation score after cleanup | not lower than before |
| P7.4-03 | Full regression | identical results before and after |

### 7.5 Documents in sync

| ID | Check | Expected |
|---|---|---|
| P7.5-01 | Every test status in DESIGN 12.2 matches the regression catalogue | a script compares them |
| P7.5-02 | Every **[CHECK]** in DESIGN is resolved or has a test that pins it | none left unpinned |
| P7.5-03 | `grep -nP '[\x{2013}\x{2014}]' DESIGN.md IMPLEMENTATION.md` (en and em dashes) | no output |

**Phase 7 exit gate (G7):** all checks above pass, and the regression suite is green.

---

## Appendix A: Traceability from DESIGN to tasks and tests

Every section of `DESIGN.md` that needs code maps to a task and its tests. Task 6.5 turns this table into a script that fails CI when a row has no passing test.

| DESIGN section | Task | Main tests |
|---|---|---|
| 0 hard rules | 1.1, 2.1, 3.6, 3.7 | P1.1-06, P2.1-08, P3.6-02, P3.7-05 |
| 1.3 who knows what | 3.2, 3.3, 4.2, 4.4 | P3.2-09, P3.3-08, P4.2-08, P4.4-05, SYS-I2 |
| 4.1 components | Phases 3 and 4 | E2E-P3, E2E-P4 |
| 5.1 state machine and invariants I1 to I8 | 1.14, 3.2, 5.1 | T-P-04, P1.14-02, T-P-06, T-F-01, SYS-I1 |
| 5.2, 5.3 phases P0 to P8 | 2.5, 3.2, Phase 4 | T-I-01, T-I-10, E2E-P3-01, E2E-P4-02, SYS-01 |
| 5.4 unhappy paths | 2.6, Phase 6 | T-I-02, 03, 05, 06, SYS-02 to 08 |
| 6.1 contract root | 1.3 | T-P-02, T-P-03, T-U-04 |
| 6.2 commitments (salted zero-knowledge default, chip fallback) | 1.3, 1.10, 1.17 | T-U-05, P1.10-02, P1.17-01, P1.17-13, T-U-28 |
| 6.3 participant enrollment keys and the key directory | 1.15, 1.16, 3.9, 4.7, 4.9 | T-U-22, T-U-29 |
| 6.4 FROST slot keys (DKG, signing, refresh, repair, rotation) | 1.15, 2.8, 3.9, 3.10, 4.2, 4.7 | T-U-21 to T-U-23, T-U-29 to T-U-31, T-P-01, T-I-11, P4.2-01 |
| 6.4 share storage and recovery | 3.9, 3.10, 4.2, 4.7 | T-U-31, P4.2-05 to 07 |
| 6.4 code integrity (reproducible bundle, separate origin) | 4.10 | P4.10-* |
| 6.5 binding statement | 1.3 | T-U-05 |
| 6.6 deal seal (one seal, 29 fields) | 1.3, 1.6 | T-U-06, T-U-14 |
| 6.7 release code | 1.3, 4.4 | T-U-01, T-U-02, P4.4-02 |
| 6.8 multisig check | 1.4, 2.4 | T-U-07, 08, 20, P2.4-01, 02 |
| 6.9 lock checker | 1.11, 3.5 | T-U-09, T-A-01 to 06, 08 to 10, 16, 19 to 25 (listed by name in 1.11), T-A-28a, P3.5-02 |
| 6.10 zero-knowledge passport proofs (trust anchors, offline re-verification) | 1.17, 2.9, 3.11, 3.8, 4.8 | T-U-28, T-U-28c, T-U-32, T-I-12 |
| 6.11 randomness and secrets | 4.2, 5.7 | P4.2-08, P5.7-02 |
| 6.12 signed-contract seal | 1.5, 2.3, 4.4 | T-U-13, T-U-15, P2.3-04, P4.4-01 |
| 6.13 post-quantum by default (hybrid envelopes, binding, checkpoints, X-Wing, renewal) | 1.16, 3.12, 4.9 | T-U-24, T-U-25, T-U-26, T-U-27 |
| 6.14 operations binding | 1.7 | T-U-19 |
| 6.15 passport attestation | 1.8, 1.9, 1.17, 4.4, 4.6 | T-U-16, T-U-28, T-A-27, P1.8-*, P1.9-13 to 18, P4.4-03, 04, P4.6-* |
| 6.16 bar records and credential | 1.10, 3.3 | T-U-17, P3.3-* |
| 6.17 release gate (all codes: `LOCK_OK`, `CONTRACT_SEAL_OK`, `PASSPORT_A_OK`, `PASSPORT_B_OK`, `BAR_A_OK`, `BAR_B_OK`, `ATTORNEY_CREDENTIAL_A_OK`, `ATTORNEY_CREDENTIAL_B_OK`, `RELEASER_SEALED`, `OPS_BINDINGS_OK`, `ONBOARDING_OK`, `IDS_DISTINCT`, `IDENTITY_POLICY_OK`, `PQ_BINDINGS_OK`, `SLOT_SETUP_OK`, 15 codes) | 1.12, 4.4 | T-U-18, T-P-07, T-A-27 to 30, P1.12-05 to 12 (one per new code), P4.4-06, 07 |
| 7.3 transaction catalogue | 2.3 | P2.3-* |
| 7.4 reserves | 2.1, 5.6 | P2.1-07, P5.6-01 |
| 7.5 signing and submission | 2.2, 2.4, 3.2 | P2.2-*, T-A-12, 14, 15, P3.2-04 to 08 |
| 8.1, 8.2 events and chain | 1.13, 3.4 | T-U-10, T-U-11, P3.4-01 to 05 |
| 8.3, 8.4 anchors and time | 3.4 | T-I-07, P3.4-06 to 08 |
| 8.5 watcher | 2.7, 3.5 | T-I-08, P2.7-*, P3.5-* |
| 8.6 observability | 3.6 | P3.6-04, 05, T-A-32 |
| 8.7 privacy | 3.1, 3.6, Phase 6 | P3.1-07, T-A-32, SYS-I2 |
| 8.8 bundle | 3.4, 3.8 | P3.4-10, P3.8-* |
| 8.9 storage | 3.1, 3.6 | P3.1-02, P3.6-03 |
| 8.10 client records view | 3.4, 4.3 | P3.4-11, 12, T-A-31, P4.3-06 |
| 9 data model | 3.1 | P3.1-* |
| 10.1 threats | 5.7 | P5.7-01 (every row has a passing test) |
| 11 sandbox tiers | 2.1, 5.5 | P2.1-*, T-N-01 |
| 12 testing approach | Phases 5 and 6 | T-F-01, T-Z-01, T-Z-02, mutation, regression tiers |
| 14 milestone M0b (core with FROST, post-quantum and zero-knowledge; T-P-01 moved here from M0) | 1.1 to 1.17 | T-U-13 to T-U-32, T-P-01, T-P-07, T-A-27 to 30 |
| 15 O13 chip reading | 4.6 | P4.6-* |

---

## Appendix B: Design questions found while planning (DQ)

These come from the adversarial review of 24 Oct 2026 and from planning this build. The code follows `DESIGN.md` exactly until each one is decided. Each DQ has a test marked `it.todo('DQ-n ...')`, so it shows in every test run.

| DQ | Question | Where it shows | Proposed answer |
|---|---|---|---|
| DQ-1 | After funding, the quarantine escrow is gone, so `QUARANTINE_PRESENT` and `ESCROW_AMOUNT_AND_CONDITION` fail on every ledger. The watcher (DESIGN 10.2) would alert on every ledger. | 1.11, 3.5 | Make the checker aware of the phase: skip the escrow rules once the finish has validated. |
| DQ-2 | `CREDENTIAL_ACCEPTED` checks only credentials that exist. If step 5e never ran, the check passes. | 1.11 | Require exactly one accepted credential for each expected subject. |
| DQ-3 | A stranger can open a trust line to the shell after step 2 and before step 5c. The checker then blocks the release, and only the stranger can remove it. | 2.6 (P2.6-01) | Set the DisallowIncoming flags right after step 2, and treat a trust line that holds no reserve for the wallet as a warning. |
| DQ-4 | Once the Sponsor amendment is live, anyone can create a Sponsorship that names the wallet, and the checker counts it as owned. | 1.11 | Decide ownership per type from the right field; objects that only point at the wallet are warnings. |
| DQ-5 | The checker finds the quarantine escrow by amount and condition. The comment says it uses owner plus sequence, but `exp.escrow.sequence` is never used. | 1.11 | Match by owner plus sequence. |
| DQ-6 | Losing one key used to freeze the money for good, because the quorum equals the total weight. FROST 2-of-3 slot keys now answer part of this: one lost share is recoverable. Two lost shares in one slot still freeze the money. | 2.6, 1.15 | Keep FROST recovery for one share. For two lost shares, add a recovery path per party (for example, signing through a funded signer account's regular key), or a mandatory O1 backstop. |
| DQ-7 | After the release, Bob can hold Alice's refund hostage at no cost. | Phase 6 | A bond from Bob, or a mandatory O1 backstop. |
| DQ-8 | A clause proof does not prove the number of clauses. | 1.3 | Put the clause count into the contract root (a new contract root rule). |
| DQ-9 | The deal seal now has 29 fields, but it still does not include the amount, the releaser's network or the network ID. | 1.6 | Add them to the seal in a later design change (version 1.0 is the only version, so this needs a design decision), or accept the risk with a reason. |
| DQ-10 | A signature window of 1,800 ledgers (about 2 hours) is short for four people in different countries. | 3.2 | Allow a longer window for exits, because both exit candidates share slot S. |
| DQ-11 | In the checker, `Oracle` objects use the field `Owner`, not `Account`. They fail closed today only by accident. | 1.11 | Fix the owner field. Add a test. |
| DQ-12 | DESIGN 7.1 calls a DID an optional home for the seal, but the checker blocks DIDs. | 1.11 | Remove the DID option from 7.1, or allow exactly one DID with the seal. |
| DQ-13 | The account-field part of the checker is a block-list, not an allow-list. A new authority field would pass. | 1.11 | Allow-list the AccountRoot fields. |
| DQ-14 | noble's FROST has no share refresh or repair. We write our own, and they are unaudited. ZF `frost-ed25519` refresh and repair are also outside the NCC audit. The 24 Oct prototype refresh did not check sub-shares against the Feldman commitments; task 1.15 adds and tests that check. | 1.15 (T-U-23, T-U-30) | Test our refresh against ZF 3.0.0 with `tools/frost-ref/`, keep refresh off by default in the demo, and get a review before production. |
| DQ-15 | ZKPassport does not prove chip presence (passive authentication only). Is `"zk-or-chip"` enough as the default identity policy (DESIGN O14)? | 1.17, 4.8 | Default to `"zk-or-chip"`, show the method in the attestation, and let a deal require `"chip"` when the parties want a presence proof. |
