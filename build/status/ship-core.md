# ship-core (OD-37 shipment and receipt: contracts, core, py-ref)

**State:** done. `build/tmp/ship-core-ready` is touched.

## Exports for the other agents
- `@legx/contracts/events`: `ShipmentSigned`, `ReceiptSigned` (zod data schemas; also in `EventKind` as `shipment.signed`, `receipt.signed`), `ReceiptCondition` (`ok | damaged | missing`).
- `@legx/contracts/records`: `GATE_CODES` (17; `SHIPMENT_SIGNED_OK`, `RECEIPT_SIGNED_OK` last), `ManifestItem`, `Manifest`.
- `@legx/contracts/values`: `DealState` gains `SHIPPED`, `RECEIVED` (between VERIFIED and FUNDED).
- `@legx/core/shipment`: `jcsItem`, `manifestRoot(items)`, `shipParts`, `shipMsg`, `shipmentHash`, `rcptParts`, `rcptMsg`, `verifyShipment(data, {dealId, dealSeal, slotPub, atLedger, maxAge?})`, `verifyReceipt(data, {dealId, dealSeal, slotPub, atLedger, shipment})`, `SHIPMENT_TAG`, `RECEIPT_TAG`, `SHIP_LEDGER_MAX_AGE` (20), `CONDITIONS`. Results are typed: `{ok:true,...}` or `{ok:false, code}`; verifyReceipt returns the condition and does not judge it.
- `@legx/core/frostRules`: `SealedDeal.dealId?` (new, required for the two tags); `tagged` `legx/shipment/v1` slot B only, `legx/receipt/v1` slot A only, parts 0/1 = sealed dealId/dealSeal, sizes checked, condition 0..2, carrier/tracking 1..64 chars without controls.
- `@legx/core/releaseGate`: `ReleaseInput.records.shipments?` / `receipts?` (envelope bytes; exactly one shipment; the last receipt counts). Failure details: `MISSING`, `NOT_EXACTLY_ONE`, `MALFORMED`, `MSG_HASH_MISMATCH`, `BAD_SIGNATURE`, `LEDGER_AFTER_GATE`, `NO_VALID_SHIPMENT`, `SHIPMENT_MISMATCH`, `MANIFEST_MISMATCH`, `LEDGER_BEFORE_SHIPMENT`, `CONDITION_DAMAGED`, `CONDITION_MISSING`. `relied_on` adds `shipment.signed` and `receipt.signed`.
- `@legx/core/machine`: states `SHIPPED`, `RECEIVED`; events `SHIP_SIGNED`, `RECEIPT_SIGNED {condition}`; `RELEASE_ESCROW` only from `RECEIVED`; a non-ok receipt is refused with refusal `receipt`; both new states allow `CANCEL_AFTER_PASSED`.

## Tests
- `pnpm vitest run --project unit packages/core packages/contracts tools/differential`: 51 files passed, 1 skipped (todo-only), 1887 passed, 10 todo.
- `LEGX_BROWSER=1 pnpm vitest run --project core-browser`: 7 passed.
- `cd tools/py-ref && uv run pytest -q`: 24 passed.
- `pnpm exec tsc -p` core, contracts, tools/differential: clean. `biome check packages/core packages/contracts`: 0 errors (pre-existing warnings only; new files clean).
- New: `packages/core/test/shipment.test.ts` (25: JCS, root, Python vectors byte for byte, verifiers, hostile input property tests), allow-list tests in `frost.rules.test.ts`, OD-37 rows plus 11 attack cases in `releaseGate.test.ts`, machine edges (15 x 16 x 2 table), the e2e paper deal now signs the shipment and receipt through the FROST allow-list and passes all 17 codes.

## Research notes
- RFC 8785 https://www.rfc-editor.org/rfc/rfc8785.html: lone surrogates must abort (3.2.2.2); keys sorted by UTF-16 code units (3.2.3). `canonicalize@5.1.0` checks `isWellFormed()`. Python reference uses `json.dumps(sort_keys, separators, ensure_ascii=False)`, equal to JCS for ASCII keys, strings and safe integers.
- RFC 9162 https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1.1: MTH, 0x00 leaf / 0x01 node prefixes; the empty manifest is refused rather than hashed to SHA-256("").

## Files
- created: `packages/core/src/shipment.ts`, `packages/core/test/shipment.test.ts`, `packages/core/test/helpers/ship.ts`, `tools/py-ref/vectors/shipment.json`.
- changed: contracts `events.ts`, `records.ts`, `values.ts`, examples + json-schema snapshots, `test/events.test.ts`; core `releaseGate.ts`, `frostRules.ts`, `machine.ts`, `package.json` (+`canonicalize@5.1.0`), tests (`releaseGate`, `machine`, `frost.rules`, `helpers/gate.ts`, `helpers/pyref.ts`, `e2e/world.ts`, `e2e-paper-deal`); py-ref `legx_ref.py`, `make_vectors.py`, `tests/test_ref.py`; `DESIGN.md` 6.17 (17 rows) and new 6.17a.

## Design questions
- DQ-OD37-1: `packed_at` and `total_weight_g` are outside the signed root (spec 1 signs only the items). Should they be a leaf?
- DQ-OD37-2: a damaged or missing receipt leaves the deal `SHIPPED`; the machine's `OPEN_DISPUTE` exists only from `FUNDED` (money in the wallet). The dispute for an unreleased escrow ends today in the CancelAfter refund. Is a pre-funding dispute state wanted?
- DQ-OD37-3: the receipt rule also refuses a receipt whose ledger is later than the gate's ledger (not in the spec text; a gate cannot rely on the future).

## Requests to other tasks
- coordinator (`services/coordinator/src/events.ts`): `release.gate.passed` and `release.performed` are now legal only in `RECEIVED` (were `VERIFIED`); map `shipment.signed` to `SHIP_SIGNED` (check with `verifyShipment(..., {maxAge: SHIP_LEDGER_MAX_AGE})`) and `receipt.signed` to `RECEIPT_SIGNED`; pass `shipments`/`receipts` to the gate.
- `spec/deal.qnt` and `spec/test/quint.test.ts`: add SHIPPED, RECEIVED, SHIP_SIGNED, RECEIPT_SIGNED (the trace-name sets).
- vault / firm-cosigner / recovery-agent: fill `SealedDeal.dealId`, or the two tags are refused.
- tools/verifier-cli and tools/differential: shipMsg/rcptMsg random A/B cases could be added to `refcases.ts` with `cross.py` (not done: outside my folders).

## Known gaps
- No random A/B differential cases for the new recipes (golden vectors only).
