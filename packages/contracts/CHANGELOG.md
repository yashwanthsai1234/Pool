# @legx/contracts changelog

Every change after the G0 freeze is its own pull request, approved by each lane owner that imports the changed file (IMPLEMENTATION 2.4). A changed JSON Schema shows as a diff in `json-schema/`.

## 1.0.0 (task 1.2, freeze candidate)

- Value types, `PublicDealData` (29 seal fields), records, events, FROST relay messages, ports, the oRPC route table and the WebSocket messages.

## 1.1.0 (fix fleet, lane F1; additive unless marked)

- `MlDsaContext`: `legx/api-request/v1` (OD-5, I-29), `legx/release/v1` (4.10), `legx/frost-msg/v1` (3.9).
- `OutboxTopic`: `ledger.validated` (OD-9, I-3.5-b) with `LedgerValidated`, and `frost.session` (4.7).
- `EventKind`: `deal.created`, `enrollment.pinned` (3.2), `ledger.disagreement` (I-3.5-b), `frost.share.released`,
  `frost.refused` (3.9, 3.10), `frost.recovery.requested|cancelled|authorized` (3.9), `release_code.handed_over` (OD-28).
  `ActorRole` gains `recovery-agent` and `firm-hsm`.
- `FrostMessage`: new kinds `sign.begin`, `repair.hello`; `sign.request.tagged`. **Breaking:** `refresh.commit` requires
  `kem_pub`, `refresh.deleted` requires `old_shares_hash` and `new_shares_hash` (the 3.9 relay already required both).
- `IdentityOnboarded.distinct_tag` (OD-29, required) and `ChipChecks.chip_auth_available` (OD-22, required); event `frost.recovery.signed` (I-E6).
- Routes: `frost.openSession.pair` (I-28); `firmHsm.sign` (I-28, carries the operator authorization of 3.10); `ledger.accountInfo|submit|snapshot` (I-31, 4.4);
  `presence.open|get|submit` (4.3); `deals.mine` (I-W-10); `Caller` `observer` (OD-31) on the read routes, `new-key` removed.
  **Breaking:** `keys.register` moves to `/deals/{dealId}/enrollment-keys` and takes `dealId` (I-W-1, I-3.7-d);
  `bar.dealLink` and `bar.manualEvidence` take `barNumber` (manual: also `status`); `zk.verify` takes `side` and
  `zkSalt32`; `recovery.start` (lawyer) takes `ledgerIndex` and signs `LAWYER_RECOVERY_TAG` (I-S-F1);
  `recovery.cancel` takes `cancelSig` and `oldDevicePub` (3.9).
- New exports: `PRIMARY_HOLDER_ROLES`, `ENROLLMENT_POP_TAG`, `LAWYER_RECOVERY_TAG`, `SignRequest`, `PresenceRequest`,
  `TaggedPreimage`.

## 1.2.0 (fix fleet round 2, lane F1; additive)

- `Finding.code` accepts `GateWarnCode` (`DEMO_NO_FACE_MATCH`, OD-34): a warning finding is `level: 'warn'`, `ok: true`, and travels in the `release.gate.passed` record beside the 15 gate codes.
