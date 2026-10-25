# E2E-P1 paper deal suite and gate G1

**State:** done

I own `packages/core/test/e2e-paper-deal.test.ts` and `packages/core/test/e2e/` (`world.ts`, `slots.ts`, `pyref.ts`, `bundle.ts`, `approval.ts`). I did not edit any other agent's file.

## Tests
Shell: `export PATH=".../Pool/.tools/node/bin:$PATH"` (Node 24.22.1).

| Command | Result |
|---|---|
| `pnpm vitest run --project unit packages/core/test/e2e-paper-deal.test.ts` | **165 passed**, 1 todo (clauseBytes, see I-E1), 0 failed, about 40 s |
| `pnpm exec tsc -p packages/core/tsconfig.json` | no errors in my files |
| `pnpm exec biome check packages/core/test/e2e-paper-deal.test.ts packages/core/test/e2e` | 0 errors, 44 style warnings (`!` and `any` in break-case helpers) |

| ID | What runs |
|---|---|
| E2E-P1-01 | `buildPaperDeal()` (`e2e/world.ts`): four real FROST DKGs (X-Wing transport, echo, three-pair test-signing, `dkgCompletedRecord`); contract that names the wallet; both lawyer slots sign through FROST with the holders' allow-list (`messageAllowed`) as `checkMessage`; NFT URI and memo; client A on the recorded zero-knowledge results, client B on the chip path (fixture passport, `chipChecks`, active authentication over `presenceMsg`); 29-field seal and Domain; four slot bindings, ops bindings, bar records, 2-of-3 post-quantum bindings; hybrid envelopes; synthetic ledger snapshots; lock checker; gate (all 15 codes pass); gate record and memo; hybrid checkpoint over all records plus the gate record. 7 tests. |
| Python | all 12 vector files (every vector but `clauseBytes`) equal our bytes; the Python reference (`legx_ref.py`, run with `python3 -I`) is also run on this deal's own inputs and gives the same root, seal, Domain, contract message and seal, URI, memo, slot policies, bindings, pq hashes and messages, ops messages, presence messages, commitments and gate memo. |
| E2E-P1-02 | 135 break cases (ids C, S, D, Q, O, B, L, P, Z, H, R, K, I, F), each with the exact first failing check and, for gate cases, the exact set of failing codes. Includes every case the plan names: swapped enrollment key (D-02, D-13), one holder seeing another transcript (D-01), a failing test-sign pair (D-05, D-11), reused nonce (S-02, P-11), presence older than 1 hour (P-03; exactly 1 hour passes, P-04), third share alone (S-01), bad share (S-03, D-03), wrong slotPolicy (D-08, D-09), wrong pqKeyHash (Q-02), stripped ML-DSA signature (Q-01), sig_algs mismatch (Q-11, Q-12), wrong ZK scope and bound value (Z-01, Z-02), devMode in production (Z-03, Z-11), method not allowed (Z-16, Z-19, I-02). |
| E2E-P1-03 | the deal is serialized to a JSON bundle (bytes as hex), parsed back, and recomputed with no private state: seal, Domain, slot policies, pq key hashes and bindings, every hybrid signature from registry rows, the checkpoint, the zk proof hash and trust record, the gate (same findings) and the gate record. |
| E2E-P1-04 | `Date.now`, `fetch` and `WebSocket` throw; the deal is built again from nothing (new DKGs) and passes. A second test guards `new Date()` with no argument: no call comes from `packages/core/src`. `@zkpassport/sdk` is not imported by core or the helpers and is not in the require cache. |
| E2E-P1-05 | refresh of slot A: group key, `xPubA`, `slotPolicyA` and the seal unchanged; the refreshed slot signs a new presence statement the gate accepts; old plus new share = `SHARE_INVALID`; old shares still sign together; `frost.refreshed` COMPLETE with 3 deletion statements and INCOMPLETE (missing holder 3) with 2. |
| E2E-P1-06 | recovery (not in the prompt, in the plan table): notices; 72 h minus 1 s refused (`RECOVERY_DELAY`); second authenticator (with a WebAuthn approval through `cosign`) plus recovery agent sign; verifies under `xPubA`; participants named; without the approval the second authenticator is refused; the gate accepts the recovered presence signature. |
| E2E-P1-07 | repair: holders 2 and 3 rebuild holder 1's share (old share never an input); every pair with the new share signs under `xPubA`. |
| Probes | 3 `KNOWN GAP` tests pin behavior that I think is wrong or weak (I-E2, I-E3, I-E4), so a fix is noticed. |

## G1 coverage (branches), v8
Command (19 test files, ran in the foreground; a background run was killed with exit 144 on this loaded machine):
`pnpm vitest run --project unit packages/core/test/{lockcheck,appendix,releaseGate,attest,signedContract,pq,pqContexts,pqHpke,zkIdentity,zkIdentity.attest,zkIdentity.result,e2e-paper-deal}.test.ts packages/core/test/frost.*.test.ts --testTimeout=120000 --coverage.enabled --coverage.reportOnFailure --coverage.provider=v8 '--coverage.include=packages/core/src/{lockcheck,releaseGate,attest,signedContract,frost,pq,zkIdentity}.ts'`

| File | Branches |
|---|---|
| lockcheck.ts | 73 / 73 = **100 %** |
| signedContract.ts | 31 / 31 = **100 %** (93.5 % before my break cases C-09 to C-17) |
| zkIdentity.ts | 114 / 115 = **99.13 %** |
| frost.ts | 97 / 98 = **98.97 %** |
| attest.ts | 184 / 188 = **97.87 %** |
| pq.ts | 46 / 47 = **97.87 %** |
| releaseGate.ts | 170 / 176 = **96.59 %** |
| total | 715 / 728 = 98.21 % |

All seven are at least 95 %. The one failure in that run is `frost.signing.test.ts` P1.15-22 (a wall-clock budget, known as I-9). In an earlier whole-package run `merkle.test.ts` P1.13-03 timed out at 5 s under load (also I-9). Neither is mine.

## Research notes
No new library or recipe. Sources: IMPLEMENTATION.md "Phase 1 end-to-end suite", DESIGN 6.4, 6.6, 6.9, 6.10, 6.12 to 6.17, DECISIONS OD-2, OD-21; `tools/py-ref/legx_ref.py` for the Python reference.

## Evidence
No deviation from the plan, except:
- The zero-knowledge recordings are bound to the fixture seal and slot key, so they are checked with `checkZkResult` in their own fixture world; the live deal reuses only their verification records (identifier, proof hash, trust record), and the run profile is `demo` (all recordings are Sepolia, devMode, mock). See I-E5.
- Gate cases that rebuild a whole deal (I-01 to I-03) reuse the DKG slots and rebuild everything bound to the new seal (about 1 s each).

## Files created
- `packages/core/test/e2e-paper-deal.test.ts`
- `packages/core/test/e2e/{world,slots,pyref,bundle,approval}.ts`
- `build/tmp/E2E-P1/` (coverage logs)
- Rows I-E1 to I-E6 appended to `build/ISSUES.md`

## Design questions
- DQ-E2E-1: should `SLOT_SETUP_OK` bind Ed25519 enrollment keys to the seal (I-E2)?
- DQ-E2E-2: should the chip path get a deal-scoped person identifier for `IDS_DISTINCT` (I-E4)?

## Requests to other tasks
- 1.17 / 2.5: let `record.ts` take the deal inputs from `e2e/world.ts`, and record a face match (I-E5). Task 2.5 can reuse `buildPaperDeal` with its recorded ledger snapshots.
- 1.15: a recovery record that names the signing holders (I-E6).
- 1.3 / web: implement DESIGN 6.1 clause normalization (I-E1).

## Known gaps
- T-U-28c (real passport) stays a todo in 1.17; no real-passport or non-mock zero-knowledge run exists, so the production profile is tested only by refusal (Z-03 to Z-05, Z-11), and by a chip-only deal (I-03).
- The Rust cross-test (P1.15-13) is still a hand port (I-10); G1 lists it as committed files, which exist.
- I did not run T-P-01 or the other G1 vector tests separately: they ran in the coverage run above (frost.vectors, pq ACVP, zkIdentity) and passed.
- The gate does not verify the outer envelope signature of `ops.bound`, `pq.bound` and `frost.dkg.completed` (1.12 known gap); the suite does not break it.
