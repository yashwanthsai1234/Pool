# fix-F1 (contracts and auth)

State: done (with the cross-lane requests below)

## Contracts (landed first; `build/tmp/contracts-ready` written)
See `packages/contracts/CHANGELOG.md` 1.1.0. Summary:
- `MlDsaContext` + `legx/api-request/v1`, `legx/release/v1`, `legx/frost-msg/v1`, `legx/enrollment-pop/v1`.
- `OutboxTopic` + `ledger.validated` (with `LedgerValidated`), `frost.session` (no producer yet, see gaps).
- `EventKind` + `deal.created`, `enrollment.pinned`, `ledger.disagreement`, `frost.share.released`, `frost.refused`,
  `frost.recovery.requested|cancelled|authorized|signed`, `release_code.handed_over` (OD-28). `ActorRole` + `recovery-agent`, `firm-hsm`.
- `FrostMessage`: 3.9 supersets merged (`refresh.commit.kem_pub`, `refresh.deleted` hashes, `sign.begin`, `repair.hello`,
  `sign.request.tagged`). The local superset in `coordinator/src/frost/schema.ts` is deleted.
- `IdentityOnboarded.distinct_tag` (OD-29, required), `ChipChecks.chip_auth_available` (OD-22, required; F2 request).
- Routes: `frost.openSession.pair`; `firmHsm.sign` (`/deals/{dealId}/firm-hsm/sign`, with the 3.10 operator authorization);
  `ledger.accountInfo|submit|snapshot`; `presence.open|get|submit`; `deals.mine` (I-W-10); `keys.register` moved to
  `/deals/{dealId}/enrollment-keys` with `dealId`; `bar.dealLink`/`bar.manualEvidence` take `barNumber` (+`status`);
  `zk.verify` takes `side`, `zkSalt32`; lawyer `recovery.start` takes `ledgerIndex`; `recovery.cancel` takes `cancelSig`,
  `oldDevicePub`. `Caller` gains `observer` (OD-31) on read routes; `new-key` removed. `PRIMARY_HOLDER_ROLES`,
  `ENROLLMENT_POP_TAG`, `LAWYER_RECOVERY_TAG` exported.

## Fixes (rows marked in ISSUES.md)
- I-S-A1: `authorize` maps a key to the party role only for primary holders (phone, second-authenticator,
  passkey-same-device, console); others get `holder` on `share-holder` routes (FROST relay) only. Events must be signed by a
  primary holder. Observer keys (`deps.observerKeys`) read only. `canReadDeal` exported for the live feed.
- I-S-M1..M4: escrow Owner/OfferSequence checked; escrow fields read from the validated tx; setup events only in
  DRAFT..QUARANTINED and never after a `pq.bound`.
- I-S-F1: route signs/verifies the bound message from core (F2), fresh `ledgerIndex` checked; recovery ids are core's UUIDv7.
- I-21, I-26, I-28, I-29, I-3.5-b, I-3.5-c, I-3.7-a, I-3.7-d, I-31 (contracts), I-W-1, I-W-10 (contracts), I-W-16, I-D-1 (contracts).
- New coordinator procedures: `keys.register` (vouching + proof of possession, refuses a taken key id), `presence.*`
  (table `presence_request`), `ledger.accountInfo|submit`, `deals.mine`; generic `ownSideOnly` enforcement in `app.ts`.
- New firm-cosigner route `firmHsm.sign` (`src/routes.ts`), mounted by `register` when `cosigner` is passed.
- db migration `0003_holders_and_services.sql`: OD-17 role check, outbox NOTIFY trigger, presence table, all
  `frost_relay_*`, `recovery_agent_*`, `firm_cosigner_*` tables (every `ensureSchema` deleted).
- Simplicity: one `ShareVault` (I-26); dead `LAWYERS`, unused imports, the role-constraint workaround in tests removed.

## Tests (final)
- `pnpm vitest run --project unit packages/contracts packages/db services/coordinator services/recovery-agent services/firm-cosigner`: 863 passed, 2 skipped (pre-existing skips).
- Integration (own pg `legx-f1-pg` :5510, xrpld `legx-f1-xrpld` :6110; env LEGX_PG_URL, LEGX_32_*, LEGX_39_*, LEGX_310_PG, LEGX_PG_CONTAINER): `pnpm vitest run --project integration packages/db services/coordinator services/recovery-agent services/firm-cosigner`: 39/39 (8 files), schema dump refreshed.
- `pnpm vitest run --config tests/break-it/vitest.config.ts frost machine api/holder-role`: 11/12; the failing one is the
  records route of I-S-A1 (F3 file).
- tsc clean for all five packages; biome: no errors (3 pre-existing `noExplicitAny` warnings in coordinator test support).
- Flaky under machine load (pass alone): recovery-agent `P3.9-17` (38 s), db PGlite `beforeAll` 10 s hook.

## Research notes
- EscrowFinish/EscrowCancel identify the escrow by `Owner` + `OfferSequence`; a ticketed EscrowCreate has `Sequence` 0 and
  the escrow's sequence is its `TicketSequence`: https://xrpl.org/docs/references/protocol/transactions/types/escrowfinish ,
  https://xrpl.org/docs/references/protocol/transactions/types/escrowcreate , https://xrpl.org/docs/concepts/accounts/tickets
- `account_info` fails with `actNotFound` for a missing account: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_info
- NOTIFY is delivered at commit: https://www.postgresql.org/docs/current/sql-notify.html
- Kysely `sql.table` for dynamic table names: https://kysely.dev/docs/recipes/raw-sql
- UUIDv7: https://www.rfc-editor.org/rfc/rfc9562#section-5.7

## New tags (OD-19 review)
`legx/enrollment-pop/v1` (keys.register proof of possession). (`legx/lawyer-recovery/v1` is shared with F2's core.)

## Requests to other lanes
- F3: evidence `records.ts` refuse non-primary holder roles (I-S-A1 pinned test 1); apps/server `canRead` -> `canReadDeal`;
  pass `observerKeys` and lawyer `opsAccount` in compose; mount `keys.register`, `presence.*`, `ledger.*`, `deals.mine`
  (coordinator procedures exist) and `firmHsm.sign` (pass `cosigner` to `@legx/firm-cosigner` `register`); drop the
  outbox trigger in `apps/server/test-int/support/pg.ts` (migration 0003 creates `outbox_notify`, the test's CREATE FUNCTION
  now collides) and the watcher's own `pg_notify`; enqueue observations only when `insert` returns true; serve
  `ledger.snapshot`, `zk.verify`, `bar.*` with the new inputs; produce `frost.session` rows; allow-list or remove
  `recovery-agent/src/cipher.ts` in `noNoble.test.ts` (KEM only, I-W-14).
- F2: move `xwingShareCipher` into core (4.7 asks too), then recovery-agent drops `cipher.ts`.
- F4: vault `FIRM_HSM_SIGN_PATH` is now `/deals/{dealId}/firm-hsm/sign` with `{slot, pair, seal, operator, message?,
  request?, approval?}`; `ledger.submit` answers SubmitResult form; `/ledger/accounts/{address}` replaces `/sequence`;
  FROST relay ML-DSA context can move to `legx/frost-msg/v1` once vault and services switch together (still `legx/dsse/v1`).

## Known gaps
- The firm route answers `started` and runs the session after; a refusal is visible in the audit log and as a stalled
  session, not in the HTTP answer.
- `frost.session` topic has no producer; `ledger.snapshot` has no coordinator procedure.
- Service holders (agent, HSM) cannot post their own evidence events through `events.append` any more (I-S-A1); their
  `EvidencePort` needs a service route or the coordinator's own statements (F3 composition).
