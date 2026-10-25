# Shipment and delivery receipt (OD-37): the binding spec

Roles: Alice is the buyer, who funds the escrow. Bob is the seller, who is paid on release. This does not change the 4-of-4 wallet, slot S or the release code.

## 1. Manifest Merkle root (Bob's app)
- The manifest is a list of items `{sku, description, qty, weight_g}` plus `{packed_at, total_weight_g}`.
- Each item is serialized with JCS (RFC 8785).
- `manifestRoot` = the RFC 9162 Merkle root over the items' JCS bytes, in list order, using core's existing `merkle.ts`.
- Bob gives the full manifest to Alice, and to both lawyers, as an evidence attachment. Only the root is signed.

## 2. Shipment (signed by Bob's slot B FROST pair: phone plus second-authenticator)
```
shipMsg = tupleHash("legx/shipment/v1", [utf8(dealId), dealSeal(32), manifestRoot(32), utf8(carrier), utf8(trackingId), uint32_be(ledgerIndex)])
```
- `ledgerIndex` is a recent validated index, at most 20 ledgers old when the coordinator accepts it.
- Signature: the FROST Ed25519 signature by slot B's group key (the slot public key in the seal), over `shipMsg`.
- The signer allow-list gets the `tagged` kind `legx/shipment/v1` for slot B only. Its parts are checked against the sealed dealId and dealSeal.
- Event `shipment.signed`, posted by Bob's primary holder key (hybrid envelope):
  `{ manifest_root, carrier, tracking_id, ledger_index, ship_msg_hash: SHA-256(shipMsg), slot_sig(64, hex) }`
- `shipmentHash` = SHA-256(shipMsg).

## 3. Receipt (signed by Alice's slot A FROST pair)
```
rcptMsg = tupleHash("legx/receipt/v1", [utf8(dealId), dealSeal(32), shipmentHash(32), manifestRoot(32), uint8(condition), uint32_be(ledgerIndex)])
```
- `condition`: 0 = `ok`, 1 = `damaged`, 2 = `missing`.
- The signer allow-list gets the `tagged` kind `legx/receipt/v1` for slot A only.
- Event `receipt.signed`, posted by Alice's primary holder key:
  `{ shipment_hash, manifest_root, condition, ledger_index, rcpt_msg_hash, slot_sig }`

## 4. Release gate (DESIGN 6.17): 15 codes become 17
- `SHIPMENT_SIGNED_OK`:
  - exactly one `shipment.signed` for the deal;
  - `slot_sig` verifies under slot B's sealed public key over `shipMsg`, rebuilt from the fields and the deal;
  - its ledgerIndex is not later than the gate's ledger.
- `RECEIPT_SIGNED_OK`:
  - a `receipt.signed` whose `slot_sig` verifies under slot A's sealed key;
  - `shipment_hash` equals the shipment's hash, and `manifest_root` matches;
  - `condition == 0`;
  - its ledgerIndex is not earlier than the shipment's.
- If either check fails, the gate fails with that code and release is refused. With a `damaged` or `missing` receipt, the UI offers the existing dispute path (DESIGN 5.x, T-I-06).
- The new codes go in the gate memo and the evidence like the others. The `legx-verify` CLI checks them offline.

## 5. State machine
Release is allowed only from a state after `receipt.signed`. Add the states `shipped` and `received` between `funded`/`verified` and `release`. Order of events: `shipment.signed`, then `receipt.signed`, then `release.gate.passed`.

## 6. UI
- **Bob's phone:** a "Ship" screen. Enter the manifest items, carrier and tracking ID; it shows the manifest root; the "Sign shipment" button signs with the FROST pair in the vault.
- **Alice's phone:** a "Confirm delivery" screen. It shows Bob's manifest (and checks it against the root), carrier and tracking; she chooses ok, damaged or missing; "Sign receipt" signs.
- **Lawyer console:** both checks appear in the gate list.
- **Dashboard:** a timeline with "Shipped (Bob signed)" and "Received (Alice signed)", plus 3 attacks:
  1. a forged receipt (signed by a key that is not Alice's slot key): RECEIPT_SIGNED_OK FAIL;
  2. a receipt for another shipment (swapped manifest root): FAIL;
  3. release before receipt: refused.

## 7. Liar-catching story (for the pitch)
- ECC: only Alice's key can make her receipt; only Bob's key can make his shipment.
- Merkle: the signed manifest root fixes what was packed; a changed item changes the root.
- Ledger time: the signed ledger indexes order shipment before receipt.
- The weight telemetry and oracle consensus from the user's notes are later work (section 8).

## 8. Out of scope now (stretch)
Carrier oracle 2-of-3 consensus (courier scan, GPS, third source) as signed oracle attestations, giving an auto-refund on contradiction.
