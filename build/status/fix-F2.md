# fix-F2 (core, chip-link, zk)

State: done (two core differential tests wait on the F1 contracts field below)

## Fixed (rows marked `fixed (F2)` in build/ISSUES.md)
- **I-S-G1 / I-E4 (OD-29):** `attest.ts` `distinctTag`; `identity.onboarded` requires `distinct_tag` (zkpassport: recomputed
  from `unique_identifier`, DISTINCT_TAG_MISMATCH); IDS_DISTINCT compares the tags (code IDENTIFIERS_EQUAL kept).
  Python vector `identity.json` fn `distinctTag` (`legx_ref.distinct_tag`), checked by the e2e py-ref handler and attest.test.
- **I-S-G2 / I-E2 (OD-21):** `frostDkg.testSignMessage` now also hashes the three holders' Ed25519 enrollment keys
  (role order), so the sealed group key's test signatures bind them. The gate (`gateKeyIds`) accepts a lawyer signer
  only when that slot's test signatures verify over the registered Ed25519 keys. No seal change. DESIGN 6.4 rule 4.
- **I-S-G3 / I-2.9-e:** `attest.ts` `checkProofBinding`: every disclosure proof's public inputs 2 and 3 equal the
  scope hashes of `legx.app` and `legx/v1/<dealId>`; exactly one `bind` proof commits `custom_data = hex(presenceMsg)`.
  Checked on the real recorded sets (alice-release, alice-deal2, alice-other-domain). DESIGN 6.15.
- **I-S-G4:** SLOT_PUB_MISMATCH. **I-S-G5 (OD-22):** `chip_auth_available` required; "none" refused when true
  (CHIP_AUTH_REQUIRED); `chipChecks` sets it from the SOD's DG14/DG15.
- **I-S-P1:** `RegisteredKey.pair` (required: the `enrollment_key` row id); PAIR_MISMATCH. DESIGN 6.13.
- **I-22, I-23, I-24, I-25 (core part):** typed results; fixed entries removed from `tools/fuzz/corpus/known.json` and the
  targets' `known` lists. DKG replays give FrostError. New `parseCondition`/`parseFulfillment` (strict, 32-byte preimage).
- **I-E1:** `contract.ts` `clauseBytes` (BOM, NFC, CRLF, lone CR / lone surrogate refused), matches the py-ref vector.
- **I-E6:** `frostRules.recoverySigned` record names the two holder roles.
- **I-S-F1/F2/F3 (core parts):** `lawyerRecoveryMessage` in core, signature checked over it; `RecoveryState.recoveryId`
  (UUIDv7) in the cancel statement; WebAuthn origin and crossOrigin checks.
- **I-30 (core part), DQ-1 (`checkLock` `phase: 'funded'`), I-2.6-a (`PackageKind` `release-code-handover`, `chip-link`;
  chip-link now seals through core), I-11 (`DSSE_CONTEXT` exported), I-2.8-b.**

## OD-33 follow-up (orchestrator request)
- `SignRequest` gains `{kind: 'xrpl-single', tx}`: a single-signed `CredentialAccept` by a client slot's own account
  (address of its group key, `SigningPubKey` = the slot key), `Issuer` = sealed wallet, `CredentialType` =
  hex(`LEGX_PARTY_<side>`), capped fee, only `TransactionType, Account, Issuer, CredentialType, Fee, Sequence,
  LastLedgerSequence, SigningPubKey, NetworkID`. Every variant refused (12 cases, test first: `frost.rules.test` OD-33).
- I-2.8-d: `refreshSlot`, `refreshCtx`, `repairShare` exported from `packages/core/test/helpers/frost.ts`.
- `NONCE_USED` messages read "signing nonces already used" (also `releaseShare`), pinned in tests.
- Request F4/F1: vault and co-signers must route `xrpl-single` requests (today they branch only on `xrpl-multisign`).
- Note: `packages/core/test/mutation-frost.test.ts` (5.4, in progress) has 2 biome errors (import order, format); not
  edited by F2; it passes (68/68 with the DKG and lockcheck mutation files).

## Tests (final)
- `pnpm vitest run --project unit packages/core packages/chip-link packages/zk tools/fuzz`: 1069 passed, 6 failed,
  11 todo. The 6: three `attest.test` contract-schema differentials and the fuzz `attestation` target (all wait on the
  F1 `chip_auth_available` field), and two load timeouts (`mutation-releaseGate` "two zkpassport sides", corpus
  `frost-complaint/11faa1bc` over the 1 s hang limit while the fixture builds); those two pass with
  `--testTimeout=30000` alone (29/29).
- `LEGX_BROWSER=1 pnpm vitest run --project core-browser`: 7/7.
- `pnpm vitest run --config tests/break-it/vitest.config.ts gate pq frost`: all pass (G1-G5, P1, F1-F3).
- `uv run pytest` in tools/py-ref: 22 passed. tsc: core, chip-link, zk, and core+chip-link under the DOM lib: clean.
  biome: no errors (warnings only, pre-existing).

## Research and evidence
- ZKPassport scope hash = SHA-256(string)[0..31]; public input 2 = service scope, 3 = subscope. Read from the pinned
  `@zkpassport/utils` 0.40.0-beta.2 bundle (`ki`, `uc`, `lc`) and checked by `build/tmp/F2/scope.mjs` on
  `packages/zk/fixtures/sets/alice-deal2.json` (computed hashes equal the public inputs). A web search found no
  primary doc for this layout, so the library source is the reference.
- WebAuthn L3 7.2 steps 13-14 https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion ; RP ID https://www.w3.org/TR/webauthn-3/#rp-id ;
  localhost https://www.w3.org/TR/secure-contexts/#localhost ; UUIDv7 https://www.rfc-editor.org/rfc/rfc9562#section-5.7 ;
  composite keys https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/ ; RFC 9794; ICAO 9303-11; UAX 15.
  All in packages/core/SOURCES.md.

## New tags (OD-19)
`legx/id-distinct/v1` (DESIGN 6.17), `legx/hpke/release-code-handover/v1`, `legx/lawyer-recovery/v1` (contracts).
`legx/frost-test-sign/v1` and `legx/recovery-cancel/v1` keep their names with more fields.

## Requests to other lanes
- **F1 (contracts):** add `chip_auth_available: z.boolean()` (required) to `ChipChecks`; make `distinct_tag` required;
  add event `frost.recovery.signed` `{recovery_id, slot, holder_roles}` (I-E6). Until the first lands,
  `attest.test` "payloads satisfy the contracts schema" (3 tests) fail, and the fuzz `attestation` target reports
  "accepted a payload the contracts schema refuses".
- **F1 (recovery-agent, firm-cosigner):** `recoveryStart({kind:'lawyer', dealId, newKeyId, ledgerIndex, ...})` replaces
  `request`; use core `lawyerRecoveryMessage` and delete the local copy; use `state.recoveryId` as the row id; tests
  that build `RecoveryState` by hand need `recoveryId`.
- **All registry adapters (F1 coordinator/db, F3 evidence, verifier, verifier-cli, apps/server):** set
  `RegisteredKey.pair` to the `enrollment_key` row id (tsc names each place).
- **F3 (watcher):** pass `phase: 'funded'` to `checkLock` and delete the TEMPORARY filter in `services/watcher/src/locks.ts`.
  Evidence: import `DSSE_CONTEXT` from core and delete the copy (I-11).
- **F4 (web console, vault):** the lawyer console must sign `distinct_tag` (onboarding) and `chip_auth_available`
  (chip checks: `chipChecks` returns it), and store a release proof set bound to the attestation's presenceMsg.
  WebAuthn approvals must come from an https origin on the RP ID (or `ApproverKey.origins`).
- **F5:** move `od-28-release-code-handover.int.test.ts` onto `sealPackage('release-code-handover', ...)`.
- **@legx/fixtures owner:** `parseDg1` accepts a non-minimal BER length (I-25 remainder).

## Known gaps
- I-E5 stays open: the e2e deal stores a synthetic proof set bound to its own presenceMsg (the recorded proofs are bound
  to their fixture seal); a recording against a live deal is still needed.
- I-E3 (onboarding scope/domain trusted from the lawyer, OD-2) is unchanged by design.
- Under the machine's load (load average 16 to 25) some heavy tests time out at 5 s (I-9 / I-W-17), including
  `mutation-releaseGate` "two zkpassport sides" (two `makeWorld` calls). Not edited (5.4's file); they pass alone.
- Two corpus files the fuzz run wrote under load/the pending contract (`attestation/afbb...`, `hybrid-envelope/5a1c...`)
  were removed: the hybrid one passes alone (a timing hang), the attestation one is the F1 field above.

## Files changed
core src: attest.ts, releaseGate.ts, hybridEnvelope.ts, frostDkg.ts, frostRules.ts, frost.ts, contract.ts, dealcore.ts,
zkIdentity.ts, lockcheck.ts, pq.ts, passport/{sod,passiveAuth,activeAuth}.ts; chip-link src/channel.ts; core tests and
helpers (gate.ts `proofSet`, `tagOf`; e2e/world.ts `releaseProof`); tests/break-it/pq/hybrid.break.test.ts (rows carry
`pair`); tools/fuzz (fixtures, targets, known.json); tools/py-ref (legx_ref, make_vectors, vectors/identity.json, test);
DESIGN.md (6.4 rule 4, 6.13 registry, 6.15 rules); packages/core/SOURCES.md.
