# Guided deal walkthrough (demo profile): the spec

Goal: from the lawyer console, a judge sees the WHOLE deal by clicking, through funds released to Bob on the ledger and the wallet closed. It reuses the exact role script that passes T-I-01 (`packages/xrpl/test-int/roles.ts`, `deal.ts`, `full-flow.int.test.ts`): real transactions on the local standalone ledger (or Testnet), the real coordinator and evidence log, and the real release gate. Nothing about the ledger is faked.

## Server: `apps/server/src/demo-walkthrough/` (demo profile only, like demo-attacks)
- `POST /demo/walkthrough` creates a walkthrough. Body: `{ amountXrp, identity: 'zk' | 'chip', delivery: 'none' | 'physical' }`. It returns `{ id, dealId, steps[] }`. Production refuses to mount it (test it, like P4.5-04).
- `POST /demo/walkthrough/:id/next` runs exactly ONE next step and returns `{ step, status, txHashes[], ledgerIndex, detail, gate?: findings[] }`.
- `GET /demo/walkthrough/:id` returns the state.
- Every step also goes to the live feed: the deal events through the real coordinator, plus a `walkthrough.step` row for the dashboard.
- The steps, in T-I-01's order:
  1. Lawyers enroll (the bar check against the mock registry, the `LEGX_ATTORNEY` credentials)
  2. Deal created (`deals.create`, signed by lawyer A)
  3. Contract signed by both lawyers (signed-contract seal, NFT minted)
  4. Identity onboarding (ZK recorded proofs, or the fixture chip)
  5. Keys: FROST DKG for all 4 slots, plus the PQ bindings
  6. Funding: Alice's quarantine escrow
  7. Lock: the wallet is locked (SignerList 4-of-4, DepositAuth, DisableMaster), and the lock checker passes
  8. (If delivery is `physical` and `@legx/core/shipment` exists) Bob signs the shipment
  9. (Same condition) Alice signs the receipt
  10. Presence: the release attestations
  11. Release gate: show every code (15, or 17 with delivery)
  12. Release: EscrowFinish by the sealed releaser, then the 4-of-4 FROST payment to Bob on slot S. Show Bob's balance before and after.
  13. Close: AccountDelete after the 256-ledger wait. On standalone, the server advances ledgers with `ledger_accept`.
- Each step result lists its transaction hashes, with explorer links when on Testnet.
- Holders: party and lawyer FROST shares run inside the server for the walkthrough, and each step says so ("simulated phone"). If Alice's or Bob's phone is connected (the party app is open on that deal), the shipment and receipt steps wait for the phone's signature instead.

## Web
- **Lawyer console `/lawyers`:**
  - a **"New deal" button**: a form for amount, identity method and delivery, which calls `POST /demo/walkthrough` (demo profile), or `deals.create` (production, real keys);
  - a **"Deal walkthrough" stepper**: each step has a "Run" button, a status, transaction hashes with links, gate findings, and Bob's balance change at release.
- **Dashboard:** the existing timeline and gate panels update live from the feed (no new controls).
- **Party phones:** if a walkthrough deal is open on the phone, it shows "Waiting for your signature" at the shipment or receipt step (when the ship and receipt screens exist).
