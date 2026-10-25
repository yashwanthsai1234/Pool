# Regression catalogue (Phase 6)

Every issue of `build/ISSUES.md` and the test that pins it. Regenerate with `node tests/system/support/regression.ts`;
`tests/system/test/catalogue.test.ts` fails when an issue is missing here or a test names an issue that does not exist.

- **system**: a `tests/system` test names the issue. An `it.fails(...)` there is a known gap that flips to a failure the day the issue is fixed (change it to `it`).
- **package**: a unit or integration test of the owning package names the issue (an `it.todo`, `KNOWN GAP` or a regression test).
- **none**: no test names the issue yet. Most are design, documentation or process items; the code ones are listed under "Pin needed" below.

| Issue | Where | System test | Package tests | Tier |
|---|---|---|---|---|
| I-1 | packages/xrpl builders | - | - | none |
| I-2 | apps/mock-bar-registry | - | `apps/mock-bar-registry/test/registry.test.ts` | package |
| I-3 | packages/xrpl/test-int/happy.int.test.ts | - | - | none |
| I-4 | agents | - | - | none |
| I-5 | apps/web | - | - | none |
| I-6 | packages/storage | - | - | none |
| I-7 | packages/storage + 3.12 | - | `packages/storage/test/logs.test.ts`, `services/evidence/test/pq/checkpoint.test.ts` | package |
| I-8 | tests | - | - | none |
| I-9 | packages/core tests | - | `packages/core/test/frost.signing.test.ts` | package |
| I-10 | packages/core/frost cross-test | - | - | none |
| I-11 | packages/core/hybridEnvelope | - | - | none |
| I-12 | evidence `pq.bound` | - | - | none |
| I-13 | services/evidence | - | - | none |
| I-14 | services/coordinator | `wiring.test.ts`, `sys.test.ts` | - | system |
| I-15 | services/zk-verifier | - | - | none |
| I-16 | packages/core/releaseGate | - | `packages/core/test/mutation-releaseGate.test.ts` | package |
| I-17 | packages/core frost allow-list | - | `packages/core/test/browser/core.browser.test.ts` | package |
| I-18 | packages/contracts LedgerPort | - | `packages/xrpl/test/read.test.ts` | package |
| I-19 | packages/xrpl multisig | - | `packages/xrpl/test/multisig.test.ts` | package |
| I-20 | contracts, vault, vault-host | - | `apps/vault-host/test/build.test.ts` | package |
| I-2.5-a | packages/xrpl/scripts/extract-harness.ts | - | `packages/xrpl/test/extractHarness.test.ts` | package |
| I-2.5-b | packages/xrpl builders | - | `packages/xrpl/test/builders/builders.test.ts` | package |
| I-2.5-c | packages/core/test/helpers/gate.ts | - | - | none |
| I-2.5-d | packages/xrpl/test-int/frostSlots.ts | - | `packages/xrpl/test-int/frostSlots.ts` | package |
| I-2.5-e | design | - | - | none |
| I-2.5-f | build/tmp, docs | - | - | none |
| I-21 | contracts, db, recovery-agent | - | - | none |
| I-22 | packages/core/src/passport/sod.ts `parseLds` | - | - | none |
| I-23 | packages/core/src/frostDkg.ts `judgeComplaint` | - | - | none |
| I-24 | packages/core/src/attest.ts `checkTrustRecord` | - | - | none |
| I-25 | packages/fixtures/src/parse.ts `parseDg1`; core... | - | `packages/core/test/dealcore.test.ts` | package |
| I-E1 | packages/core (no clause normalizer); `tools/py... | - | `packages/core/test/appendix.test.ts`, `packages/core/test/e2e-paper-deal.test.ts` | package |
| I-E2 | packages/core/src/releaseGate.ts `SLOT_SETUP_OK... | - | `packages/core/test/e2e-paper-deal.test.ts` | package |
| I-E3 | packages/core/src/attest.ts `verifyOnboarding` ... | - | - | none |
| I-E4 | packages/core/src/releaseGate.ts `IDS_DISTINCT`... | - | `packages/core/test/e2e-paper-deal.test.ts` | package |
| I-E5 | packages/zk/fixtures, `tools/record.ts` | - | `packages/core/test/e2e/world.ts` | package |
| I-E6 | packages/core/src/frostRules.ts recovery | - | `packages/core/test/frost.rules.test.ts`, `services/recovery-agent/test/agent.test.ts` | package |
| I-2.8-a | IMPLEMENTATION 2.8, DESIGN 5 | - | - | none |
| I-2.8-b | packages/core/src/frost.ts | - | `packages/core/test/frost.signing.test.ts` | package |
| I-2.8-c | IMPLEMENTATION 2.8 | - | - | none |
| I-2.8-d | packages/xrpl/test-int/frost/support.ts | - | `packages/core/test/helpers/frost.ts` | package |
| I-26 | services/firm-cosigner | - | `services/firm-cosigner/test/routes.test.ts` | package |
| I-3.5-a | packages/core/src/lockcheck.ts | - | - | none |
| I-3.5-b | packages/contracts | - | - | none |
| I-3.5-c | packages/db LedgerObservationsRepo | - | `packages/db/test/support/suite.ts` | package |
| I-2.9-a | packages/xrpl/test-int/zk | - | `packages/xrpl/test-int/zk/README.md` | package |
| I-2.9-b | packages/xrpl/test-int/roles.ts | - | - | none |
| I-2.9-c | packages/zk/src/port.ts | - | - | none |
| I-2.9-d | services/zk-verifier adapter | - | - | none |
| I-2.9-e | packages/core attest, releaseGate | - | - | none |
| I-2.9-f | design | - | - | none |
| I-2.6-a | packages/core/src/pq.ts, packages/contracts/src... | - | `packages/xrpl/test-int/unhappy/od-28-release-code-handover.int.test.ts` | package |
| I-2.6-b | packages/xrpl/test-int/full-flow.int.test.ts | - | - | none |
| I-2.6-c | DESIGN 5.2, IMPLEMENTATION Appendix B DQ-3 | - | - | none |
| I-2.6-d | build/AGENT_RULES.md, ci/xrpld.cfg | - | `packages/xrpl/test-int/ledger.int.test.ts` | package |
| I-2.6-e | packages/xrpl/src/submit.ts | - | - | none |
| I-27 | packages/xrpl/test-int | - | - | none |
| I-3.7-a | packages/db migrations, coordinator `events.ts`... | `wiring.test.ts` | `apps/server/test-int/support/pg.ts` | system |
| I-3.7-b | packages/contracts `ws.ts`, apps/web `live.ts` | `wiring.test.ts` | `apps/web/test/live.browser.test.tsx` | system |
| I-3.7-c | apps/web `live.ts`, contracts `ws.ts` | - | `apps/web/test/live.browser.test.tsx` | package |
| I-3.7-d | contracts `api.ts` | `wiring.test.ts` | - | system |
| I-3.7-e | coordinator `keys.ts`, evidence `keys.ts`, `rec... | - | `services/evidence/test/helpers/world.ts` | package |
| I-3.7-f | recovery-agent `routes.ts` | - | `services/recovery-agent/test/http.test.ts` | package |
| I-3.7-g | gate, zk, agents | `wiring.test.ts` | `apps/server/test/gate.test.ts`, `apps/server/test/production.test.ts`, `apps/server/test-int/stack.int.test.ts` | system |
| I-3.7-h | evidence | - | - | none |
| I-28 | contracts, coordinator/frost, recovery-agent | - | `packages/vault/test/frost/ceremony-frame.browser.test.ts`, `services/firm-cosigner/test/routes.test.ts`, `services/recovery-agent/test/http.test.ts` | package |
| I-29 | contracts, apps/web | - | `apps/web/test/party/pq-binding.browser.test.tsx` | package |
| I-30 | packages/core/passport, apps/web | - | - | none |
| I-31 | apps/web, contracts, apps/server | `sys.test.ts`, `ui.test.ts` | `services/coordinator/test/f1routes.test.ts`, `apps/web/test/party/services.browser.test.tsx` | system |
| I-D-1 | apps/server `compose.ts`, contracts `keys.regis... | - | - | none |
| I-D-2 | apps/server `/deals` | - | - | none |
| I-D-3 | apps/server `/ws` | - | - | none |
| I-D-4 | apps/server `zk.verify` | - | - | none |
| I-D-5 | scripts/demo | - | - | none |
| I-D-6 | tools/zk-prove, demo/recorded-proofs | - | - | none |
| I-D-7 | scripts/demo | - | - | none |
| I-D-8 | demo/ | - | - | none |
| I-D-9 | scripts/demo/check.ts | - | - | none |
| I-S-G1 | core `releaseGate.ts` `idsDistinct`, `attest.ts... | - | `packages/core/test/attest.test.ts` | package |
| I-S-G2 | core `releaseGate.ts` `boundKeyIds` (OD-21) | - | `packages/core/test/releaseGate.test.ts` | package |
| I-S-G3 | core `attest.ts` `zkReleaseRules` | - | `packages/core/test/zkIdentity.attest.test.ts`, `packages/core/test/e2e-paper-deal.test.ts`, `packages/core/test/attest.test.ts` (+2) | package |
| I-S-G4 | core `attest.ts` `verifyOnboarding` | - | `packages/core/test/attest.test.ts` | package |
| I-S-G5 | core `attest.ts` `CHIP_SHAPE` | - | `packages/core/test/attest.test.ts` | package |
| I-S-A1 | coordinator `auth.ts` `resolveKey`/`authorize`;... | - | - | none |
| I-S-A2 | apps/web `csp.ts` | - | `apps/web/test/csp.browser.test.ts` | package |
| I-S-A3 | apps/server `config.ts` `assertProfile` | - | `apps/server/test/profile.test.ts` | package |
| I-S-F1 | core `frostRules.ts` `recoveryStart` (lawyer pa... | - | `packages/core/test/frost.rules.test.ts`, `services/recovery-agent/test/http.test.ts`, `services/recovery-agent/test/lawyer.test.ts` | package |
| I-S-F2 | core `frostRules.ts` `recoveryCancelMessage` | - | `packages/core/test/frost.rules.test.ts` | package |
| I-S-F3 | core `frostRules.ts` `approvalCheck` (second au... | - | `packages/core/test/frost.rules.test.ts` | package |
| I-S-P1 | core `hybridEnvelope.ts` `verifyHybrid`; eviden... | - | `packages/core/test/hybridEnvelope.test.ts`, `packages/core/test/attest.test.ts`, `packages/xrpl/test-int/roles.ts` | package |
| I-S-E1 | evidence `tsa.ts` `verifyTimestampToken` | - | - | none |
| I-S-E2 | verifier-cli `checkManifestSignature` | - | `tools/verifier-cli/test/cli.test.ts` | package |
| I-S-E3 | verifier-cli `checkTimestamps` | - | `tools/verifier-cli/test/cli.test.ts` | package |
| I-S-E4 | evidence `events.ts` `append` | - | - | none |
| I-S-E5 | verifier-cli `checkInclusion` | - | - | none |
| I-S-M1 | coordinator `events.ts` `release.performed` | - | - | none |
| I-S-M2 | coordinator `escrow.created` | - | - | none |
| I-S-M3 | coordinator `escrow.cancelled` | - | - | none |
| I-S-M4 | coordinator `key.bound`, `identity.onboarded`, ... | - | - | none |
| I-S-X1 | apps/server, OD-31 | - | `apps/server/test/observer.test.ts` | package |
| I-W-1 | apps/server `routes.ts` (`keys.register` answer... | `wiring.test.ts`, `sys.test.ts` | `services/coordinator/test/f1routes.test.ts` | system |
| I-W-2 | apps/web `vite.config.ts` proxy, `lib/paths.ts`... | `ui.test.ts` | - | system |
| I-W-4 | apps/server `demo.ts` (watcher) | `wiring.test.ts` | - | system |
| I-W-5 | contracts `ws.ts` `OutboxTopic`, apps/web `lib/... | `wiring.test.ts` | `packages/db/test/support/suite.ts`, `services/coordinator/test/restart.test.ts`, `services/coordinator/test/exits.test.ts` | system |
| I-W-6 | services/evidence, apps/server `evidence.ts` | `wiring.test.ts` | `services/coordinator/test/events.test.ts` | system |
| I-W-7 | apps/server `demo.ts`, evidence `tsa.ts` | `wiring.test.ts` | - | system |
| I-W-8 | apps/server `demo.ts` `evidence: { records }` | `sys.test.ts` | - | system |
| I-W-9 | apps/server `demo.ts` `operatorKeys: () => unde... | `wiring.test.ts` | - | system |
| I-W-10 | apps/web `routes/lawyers/-console/ui.tsx` | `console.test.ts`, `ui.test.ts` | `packages/vault/test/frost/slot-frame.browser.test.ts`, `packages/vault/test/signer.browser.test.ts`, `services/coordinator/test/f1routes.test.ts` (+2) | system |
| I-W-11 | apps/server, apps/web `lib/live.ts` | `ui.test.ts` | - | system |
| I-W-12 | apps/server `demo.ts` | `sys.test.ts` | - | system |
| I-W-13 | apps/server `agents.ts` | - | `apps/server/test/agents.test.ts` | package |
| I-W-14 | services/recovery-agent `cipher.ts` | - | `services/renewal/test/noNoble.test.ts` | package |
| I-W-15 | packages/signer `node.ts`, `kms.ts`, core `hybr... | - | - | none |
| I-W-16 | services/coordinator/test-int/flow.int.test.ts ... | - | `services/coordinator/test-int/support/real.ts` | package |
| I-W-17 | packages/core `mutation-releaseGate.test.ts` (I... | - | `apps/web/test/frost/dkg.browser.test.tsx`, `apps/web/test/zk.browser.test.tsx` | package |
| I-W-18 | .github/workflows/ci.yml | - | - | none |
| I-DOC-1 | DESIGN 6.15 `face_match_passed` vs `apps/web/sr... | - | `packages/xrpl/test-int/zk/README.md` | package |

## Pin needed

Issues with no test that names them. Whoever fixes the issue adds the test and names the ID in it.

- I-1: No `CredentialDelete` builder; 3.3 wrote a local one in `services/verifier/src/chain.ts`. Move it to `@legx/xrpl` and delete the local copy. (fixed (C1b: build0c in @legx/xrpl, test in builders.test.ts))
- I-3: The earlier flow's test no longer typechecks against the new seal and lock checker. 2.5 rewrites it as T-I-01 (the full flow). (done (file removed, replaced by `full-flow.int.test.ts`))
- I-4: The web tools need ToolSearch first; rules updated. Earlier agents that reported "no web fetch" must have their research re-checked by th... (open)
- I-5: Slow-3G throttling test missing; P4.1-05 tested only by injection; `frame-ancestors` needs a real CSP header from the server (3.7). (fixed (F4))
- I-6: A local copy of the RFC 9162 Merkle tree duplicates `@legx/core` (1.13 is done). Use the core tree and delete the copy. (wontfix: core tree is array-based, Tessera needs the tile-hash-based tree)
- I-8: MinIO's official images no longer pull, so tests use `pgsty/minio`. Record the image and pin its digest. (fixed (verified C2c): digest pinned in `packages/storage/test-int/s3.int.test.ts` and SOURCES.md)
- I-10: P1.15-13 (FROST against ZF Rust) is compared against a hand port, because there is no Rust toolchain. The vectors are byte-exact; a real ... (fixed (doc): IMPLEMENTATION 1.15 "As built")
- I-11: `DSSE_CONTEXT` is not exported, so evidence duplicated the constant. Export it and delete the copy. (fixed (F2, core part): `DSSE_CONTEXT` exported; deleting the evidence copy is F3's)
- I-12: A `pq.bound` payload (two ML-DSA-65 signatures plus a cross-signature) exceeds 4 KB and is refused under OD-14. Store the binding signatu... (open: needs a contracts change (`PqBinding` carries the two ML-DSA-65 signatures), core `releaseGate`, and apps/server; none is in the services lane. Services side unchanged (OD-14 refusal stays).)
- I-13: Gaps: P3.4-13 (Tessera), P3.4-15 (needs 3.11), the real-TSA tagged test, the [pg] run, cross-machine determinism, index.ts and biome, and... (open: Tessera, P3.4-15, real-TSA test, `[pg]` run, cross-machine determinism, `index.ts`, cross-process log lock not done (feature work, out of the time box). Unit timeouts under load re-run alone.)
- I-15: P3.11-19 to 25 are not built. `reverifyStored` needs the full proof set; implement OD-25. The nightly job must set `LEGX_LIVE_SEPOLIA=1`. (partial: nightly sets `LEGX_LIVE_SEPOLIA=1` (`.github/workflows/nightly.yml:132`, `ci/nightly-zk.yml:24`, verified). Open: P3.11-19 to 25 and OD-25 `reverifyStored`.)
- I-2.5-c: `makeSlot` (one FROST slot with enrollment keys, ML-DSA keys, the DKG record) is not exported, so `roles.ts` has its own copy. Export it ... (open)
- I-2.5-e: After a lawyer B replacement the old signed-contract NFT stays on `lawyerOpsA`: it is minted with `Flags` 0 (not burnable), so nobody can... (fixed (doc): DESIGN 5.4 (supersession and release-code handover, OD-28))
- I-2.5-f: The production profile refuses the recorded mock ZK proofs (`DEVMODE_REFUSED`), so T-I-01 uses chip identity as IMPLEMENTATION 2.5 says. ... (fixed (doc): DESIGN 12.2 T-I-12)
- I-21: The contracts lack fields the FROST protocol needs: 3.9 uses local supersets, listed under "Requests" in `build/status/3.9.md`. Merge the... (fixed (F1): contracts carry the 3.9 supersets (local schema deleted), MlDsaContext frost context, db role check (OD-17), relay/agent/firm tables in migration 0003. Still open: agent HTTP join/sign endpoints and 3.11 store wiring (F3 composition))
- I-22: `parseLds` throws untyped errors on malformed BER (asn1js/pvtsutils: "Offset is outside the bounds of the DataView", "Wrong input string ... (fixed (F2): `parseLds` returns undefined on thrown BER errors)
- I-23: A complaint with a wrong-length revealed KEM key (`cipher.publicKeyOf` throws RangeError) or too few fields (TypeError on the destructuri... (fixed (F2): length checks first, revealed-key errors name the complainer)
- I-24: Accepts what the `ZkTrustRecord` schema refuses: unsafe integers (`block_number: 1e308`) and non-string values through `String()` coercio... (fixed (F2): `Number.isSafeInteger` and string-only regex checks)
- I-E3: The gate does not look at `scope`, `domain`, `unique_identifier` or the bound value inside a zero-knowledge attestation: a wrong scope an... (open (info))
- I-2.8-a: `AccountSet` with `asfDisableMaster` cannot be multisigned: rippled returns `tecNEED_MASTER_KEY` (validated, fee spent). Step 5g must be ... (fixed (doc): DESIGN 5.2 and 7.3)
- I-2.8-c: It asks for a `FrostSlotSigner` implementing `SignerPort` in `roles.ts`. OD-4 says slot signers are FROST sessions, never `SignerPort` (h... (fixed (doc): IMPLEMENTATION 2.8 "As built")
- I-3.5-a: `checkLock` has no `phase: 'funded'` option (DQ-1). The watcher drops exactly four escrow findings (`QUARANTINE_PRESENT`, `ESCROW_AMOUNT_... (fixed (F2, core part): `checkLock` takes `phase: 'funded'`; the watcher filter removal is F3's)
- I-3.5-b: No evidence kind for a ledger disagreement and `OutboxTopic` lacks `ledger.validated` (OD-9). The watcher passes kind `ledger.disagreemen... (fixed (F1))
- I-2.9-b: `openChain` closes a ledger every 100 ms, and a standalone server keeps only 256 ledgers, so anything slow (a 20 s proof) makes the mint ... (fixed (F5))
- I-2.9-c: `replayZkVerifier` throws `ZK_RESULT_MISSING`; P2.9-02 names `NO_RECORDED_RESULT`. Same behaviour, two names. Pick one in the spec or the... (fixed (doc): IMPLEMENTATION P2.9-02 now says `ZK_RESULT_MISSING`)
- I-2.9-d: The adapter refuses every domain but `legx.app` (`WRONG_DOMAIN`), so the recorded `alice-other-domain` set cannot be replayed live throug... (fixed (doc): IMPLEMENTATION 2.9 "As built"; nightly job re-records)
- I-2.9-e: The gate cannot tell whether a release proof was really bound to the current presenceMsg: it trusts the lawyer's `bound_value_is_presence... (fixed (F2): see I-S-G3)
- I-2.9-f: Release proofs have no face match (a headless prover cannot make one), so `face_match_passed` is recorded true by the console code when t... (fixed (F1/F3 R2) by OD-34 and I-DOC-1)
- I-2.6-b: `attacks/deal.ts` is `runFlow` cut into named stages (plus replace/rotate helpers). The two now duplicate each other. Make `full-flow.int... (fixed (F5))
- I-2.6-c: Observed on xrpld 3.4.1: a stranger's trust line to the shell (before 5c) costs the shell no reserve and cannot be removed by the shell. ... (fixed (doc): DESIGN 5.2 (DQ-3 stays open in Appendix B))
- I-2.6-e: `submitReliable` answers a resubmitted old blob with the ORIGINAL validated result (`tesSUCCESS`, same hash), not `tefPAST_SEQ`, because ... (fixed (F5))
- I-27: `network.int.ts` (T-N-01: T-I-01 on Testnet and Devnet) does not exist yet; the nightly Testnet job needs it. The workflows have not run ... (fixed (F5))
- I-3.7-h: Both the coordinator and `createEvents` append events (two implementations of `append`); `createLogService.integrate` is called by nobody... (fixed (F3))
- I-30: tsc: 3 `BufferSource` cast errors in `packages/core/src/passport/`, exposed when web imports the passport checks. The phone route is 341 ... (fixed (F2 core BufferSource errors, checked with the DOM lib; F4 the rest))
- I-D-1: `node scripts/demo/dry-run.ts` step 'observer key registers (POST /enrollment-keys)': `HTTP 401 {"error":"auth_malformed","message":"miss... (contracts part fixed (F1): `keys.register` exists, observer keys are pinned by config (`observerKeys`); the script-side signer is F3)
- I-D-2: Dry-run step 'lawyers A and B onboard clients (POST /deals)': `HTTP 401 ... missing x-legx-auth header` (same cause as I-D-1). Deal creat... (fixed (F3))
- I-D-3: Dry-run step 'dashboard subscribes to /ws as observer': `GET /ws -> HTTP 401 {"error":"auth_malformed","message":"missing or malformed x-... (fixed (F3))
- I-D-4: Dry-run step 'ZK identity proof verified (POST /deals/d1/zk/verify)': `HTTP 401 ... missing x-legx-auth header`; once signed it would ans... (fixed (F3))
- I-D-5: Not built because the flow cannot run yet (I-D-1 to I-D-4): `demo:prestart` (deal #2 to `VERIFIED`, P5.6-02), the FROST DKG and PQ bindin... (closed: prestart and rehearse built (`pnpm demo:rehearse`, screenshots in demo/rehearsal); `demo:*` aliases added. FROST DKG seed and HSM start tracked in other issues)
- I-D-6: Dry-run steps 'headless prover': `tools/zk-prove does not exist (vendored ZKPassport prove.ts not added)` and 'recorded ZK proofs': `demo... (closed: `tools/zk-prove/cli.ts` (fresh proof bound to presenceMsg, recorded fallback), `demo/recorded-proofs/`, production-refusal test; dry-run 13/13)
- I-D-7: `demo:fallback` (P5.6-04) is not a live switch: the local standalone stack is the same one `scripts/dev.ts` starts, so the fallback is re... (wontfix: container names now come from `LEGX_DEV_PREFIX` (lib.ts); a live Testnet-to-standalone switch is out of scope for the demo, the fallback is reset + dev + seed (documented))
- I-D-8: Dry-run step 'backup video': `demo/backup.mp4 does not exist` (P5.6-06). Must be recorded by a person after the flow works. (open)
- I-D-9: `demo:check` cannot test: the tunnel (needs `LEGX_TUNNEL_URL`), the Sepolia RPC (needs `LEGX_ZK_RPC`; the server also reads it), phone re... (wontfix: external dependencies (tunnel, Sepolia RPC, phones, security keys, ZKPassport) cannot be tested from a script; `demo:check` reports them RED by design and the manual items stay in demo/state.json)
- I-S-A1: The party role comes from `slot` alone, and `holder_role` is ignored. The recovery agent's slot-A key reads Alice's records and posts ali... (`api/holder-role.break.test.ts` (3))
- I-S-E1: In `extendedMode` the `signatureVerified` result is ignored. A real token re-pointed at any hash is accepted, and the TSA URLs are plain ... (`evidence/tsa.break.test.ts` (2))
- I-S-E4: Any deal key can sign any kind as any actor. Over the network the coordinator's ACTORS check guards this. (`evidence/actor.break.test.ts`)
- I-S-E5: An event with no inclusion proof is only a warning. (bundle)
- I-S-M1: The EscrowFinish's `Owner`/`OfferSequence` is not checked against this deal's escrow. (`machine/coordinator.break.test.ts`)
- I-S-M2: The amount, condition and `CancelAfter` come from the event's claim, not the transaction. (machine)
- I-S-M3: Any EscrowCancel (any Owner) moves the deal to EXPIRED. With M2, Alice can block the release in the coordinator. (machine)
- I-S-M4: No state guard: these are accepted after VERIFIED or FUNDED, and `publicData` uses `lastOf`, so the recomputed seal drifts. (machine)
- I-W-15: `packages/signer/test/signers.test.ts` fails (3 tests, "signs DSSE PAE bytes so that the core hybrid verifier accepts the envelope"): the... (fixed (F3))
- I-W-18: The integration job sets `XRPLD_WS`, `LEGX_PG_URL` and the 3.2, 3.9 and 3.10 overrides only. The tests also read `LEGX_37_PG`, `LEGX_37_L... (fixed (C1b: ci.yml env, named legx-pg, system job))

## SYS-* index

Test IDs of IMPLEMENTATION 6.1 to 6.4 and the file that holds them (`tests/system/test/`):

SYS-01, SYS-02, SYS-03, SYS-04, SYS-05, SYS-06, SYS-07, SYS-08, SYS-09, SYS-10, SYS-11, SYS-12, SYS-13, SYS-14, SYS-15, SYS-16, SYS-17, SYS-A1, SYS-A2, SYS-A3, SYS-A4, SYS-A5, SYS-A6, SYS-A7, SYS-A8, SYS-A9, SYS-A10, SYS-A11, SYS-A12, SYS-A13, SYS-A14, SYS-A15, SYS-A16, SYS-I1, SYS-I2, SYS-I3, SYS-I3a, SYS-R1, SYS-R1b, SYS-R2, SYS-R3, SYS-R4
