# cleanup-C3 (web; the vault lane moved to C3b)

State: done for apps/web. Edits to packages/vault and apps/vault-host were made BEFORE the lane split; handover below.

## Tests (before from build/status/fix-R2-web.md, after = this run)
- `LEGX_BROWSER=1 vitest run --project browser --project vault-browser`: before 910 passed, 6 skipped (89 files); after 926 passed, 6 skipped (91 files; +2 party seal tests, plus other agents' tests).
- `pnpm --filter @legx/web test`: before 19, after 19 (phone route under 250 kB, xrpl and wasm not in the entry).
- `vitest --project unit packages/vault`: 12 -> 12. `apps/vault-host` build.test: 6 tests, FAILS ONLY BY the 5 s timeout under load (the two bundle builds take ~6-11 s on the loaded machine; passes with a quiet machine at 6 s). C3b: give that test a timeout.
- tsc and biome clean for apps/web, packages/vault, apps/vault-host.

## Lines (apps/web / vault-host / vault / ui), `*.ts*`
before 12952 / 1046 / 8932 / 128; after 12937 / 1055 / 8927 / 128 (web also gained `lib/seal.ts`, two tests).

## Done
- Party host pins and loads the seal like the console (OD-36a): `lib/seal.ts` (`loadSealedDeal`, `fetchSealedDeal`, `checkSeal`); party `-services.ts` wraps signFrost, signMultisig, signSingle, signShell so the first call pins and loads. Tests: party services (pin once before first signature; mismatch signs nothing).
- Duplication: three copies of "deal + public data + checkSeal" -> `fetchSealedDeal`; three observable stores -> `-console/listeners.ts`; two attestation sign/self-check blocks -> `-console/attestation.ts`.
- Dead code: removed `public-ledger.ts`, the `zk/index.ts` barrel (test imports modules), `realSdk`, two unused providers, unused exports and types un-exported.
- I-20 verified/fixed (row updated). Vault edits already made: `CODE_HASH_MISMATCH` in VaultCode, alias `apps/vault-host/src/no-mpt-crypto.ts` keeps the 2.1 MB WASM out of the vault bundle (test in build.test.ts), `derive()` helper in `packages/vault/src/vault.ts`, `test/frost/world.ts` unused exports removed.

## Requests
- C2 (`tests/system`): the I-W-10 `it.fails` can flip once the system web env sets `VITE_VAULT_ORIGIN` and `VITE_LEGX_XRPL_RPC` and serves a release-signed vault host: build it with `buildBundle` + the release CLI of `apps/vault-host/scripts/build.ts` and serve the output on its own origin; seed the lawyer's enrollment key in that frame.
- C3b: build.test timeout; `@legx/contracts` is only used in vault-host tests (move to devDependencies); knip flags packages/ui deps as unused (false positive, they are imported).

## Not done
- Tool pass on frost screens beyond what jscpd flagged (small clones left in ui.tsx cards, `-badge`/`-lock` headers, `deal.ts`).
- `PartyHost` / console host composition left as two short files (about 10 shared lines).
- `@zkpassport/sdk` dependency is now unused after removing `realSdk` (no lockfile change made).
- Fail-first not shown for the party seal tests (written after the code).
