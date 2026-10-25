# Delivery proofs: physical and digital

How LegX decides that Bob delivered and Alice received, before the escrow pays Bob. The binding spec for the physical flow is `build/SHIP_RECEIPT.md` (decision OD-37). The digital flow below is a proposal, not built yet.

Roles: **Alice** is the buyer and funds the escrow. **Bob** is the seller and is paid on release.

## 1. Mapping the four proposed methods

| Proposed method | Status | How LegX uses it |
|---|---|---|
| 1. Elliptic-curve signatures catch a lie about who signed | Being built (physical) | Bob signs the shipment and Alice signs the receipt with **Ed25519 through FROST**, 2-of-3 shares per person. EdDSA is a Schnorr-type signature: verification checks `s·G = R + H(R, A, msg)·A`. It rests on the same discrete-log hardness as ECDSA's `r, s` check. |
| 2. Merkle trees catch bait-and-switch | Being built (physical) | The packing manifest becomes an **RFC 9162 Merkle root** inside Bob's signed shipment. Alice's receipt binds to that root. Weight telemetry at hubs is not included (it needs real carrier data). |
| 3. Oracle consensus (more than 2/3 of courier, GPS and camera) | Not used | It needs real outside data feeds. Stretch goal: signed oracle attestations with a 2-of-3 rule and auto-refund on contradiction. |
| 4a. Byzantine fault tolerance | Already in | The **XRP Ledger consensus** is BFT. Every escrow, payment, anchor and ledger timestamp LegX relies on is validated by it. |
| 4b. Slashing | Not yet | XRPL has no staking. Equivalent: a **seller bond** in a second escrow, forfeited to Alice by a verified fraud proof (section 3). |

## 2. Physical delivery (being built, OD-37)

| Step | Algorithm |
|---|---|
| Manifest | Each item in JCS (RFC 8785), then an RFC 9162 Merkle root, `manifestRoot` |
| Bob ships | `shipMsg = tupleHash("legx/shipment/v1", [dealId, dealSeal, manifestRoot, carrier, trackingId, ledgerIndex])`, signed with FROST Ed25519 by slot B |
| Alice receives | `rcptMsg = tupleHash("legx/receipt/v1", [dealId, dealSeal, shipmentHash, manifestRoot, condition, ledgerIndex])`, signed with FROST Ed25519 by slot A. `condition` is ok, damaged or missing. |
| Ordering in time | Validated XRPL ledger indexes: the shipment comes before the receipt |
| Evidence | Each event is also a hybrid Ed25519 + ML-DSA-65 record in the Merkle evidence log, anchored on XRPL |
| Release | The gate adds `SHIPMENT_SIGNED_OK` and `RECEIPT_SIGNED_OK` (17 codes). Then the 4-of-4 multisig payment runs on slot S. A damaged or missing receipt leads to the dispute path. |

Attack-mode scenes: forged receipt, swapped manifest root, release before receipt. Each is refused with the failing gate code.

## 3. Digital delivery (proposed: "pay ⇄ key" fair exchange)

| Step | Algorithm |
|---|---|
| Commit | Bob chunks the file. He builds a Merkle root of the plaintext and one of the ciphertext. He encrypts with a fresh key K (AES-256-GCM) and commits to `SHA-256(K)`. |
| Bob delivers | He signs `tupleHash("legx/digital-delivery/v1", [dealId, dealSeal, plainRoot, cipherRoot, SHA-256(K), size, ledgerIndex])` with FROST Ed25519. Only the ciphertext is uploaded. |
| Alice checks before paying | A random chunk spot-check: Bob reveals k chosen plaintext chunks, with Merkle proofs against `plainRoot`. If a fraction f of the file is junk, the check catches it with probability `1 − (1 − f)^k` (for example, k = 20 and f = 10% gives about 88%). |
| Alice receives | The same receipt as physical delivery, bound to the delivery hash and roots |
| Key release | K is sealed with X-Wing HPKE to lawyer B's console, then released to Alice at the same moment as the payment. Bob is paid only when Alice gets K, and Alice gets K only when Bob is paid. |
| Cheating | A **fraud proof**: Bob's signature plus K plus the ciphertext plus a chunk that does not match `plainRoot`. `legx-verify` checks it offline. It leads to the dispute path, and can forfeit the seller bond. |

Limits, stated plainly:
- A fully trustless fair exchange is impossible without a third party or zero-knowledge contingent payments (ZKCP).
- LegX uses the lawyer as the key holder, plus spot-checks and fraud proofs. That makes cheating detectable and provable, not impossible.

## 4. Seller bond: the "slashing" analogue (proposed)

1. When delivering, Bob locks a bond in a second XRPL escrow, with condition fulfillment held by the lawyers.
2. A verified fraud proof, or a dispute award against Bob, sends the bond to Alice.
3. Otherwise the bond returns to Bob after release.

Lying becomes provably unprofitable, which is the game-theory point of slashing, without needing a staking chain.
