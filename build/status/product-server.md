# product-server (product demo API, server side; build/PRODUCT_DEMO.md 1 to 4)
State: done

## What
- `apps/server/src/demo-product/` (participants.ts, deal.ts, routes.ts). Mounted inside `withWalkthrough` (demo-walkthrough/index.ts),
  so `apps/server/src/demo.ts` is unchanged: the existing demo hook line already registers it; production never mounts it.
- Routes: `POST/GET /demo/participants`, `POST /demo/deals` (multipart; PDF <= 5 MB, `%PDF-` magic, per-route bodyLimit),
  `GET /demo/deals?status=`, `GET /demo/deals/:id`, `GET /demo/deals/:id/contract.pdf`, `POST /demo/deals/:id/approve {rid, stage:number}`.
  403 `wrong_actor` (not the stage's actor, a non-party, or an auto stage), 409 `wrong_order`, 404 unknown deal, 502 `stage_failed`.
- RID = `rid_` + base32lower(tupleHash("legx/rid/v1",[ed25519Pub, mldsa65Pub])[0..10]); keys from node:crypto (Ed25519, ML-DSA-65),
  raw pubs = SPKI tails. Each participant gets an ed25519 XRPL account funded with 1000 XRP from genesis.
- PDFs stored at `$LEGX_DATA_DIR/demo-contracts/<id>.pdf` (default `.legx-data`), SHA-256 in the summary.
- Deal id = the walkthrough id; `dealId` = the coordinator deal. Participants' XRPL accounts take Alice's and Bob's roles in the
  engine (WalkDeal overrides `aliceBase`/`bobBase` wallets), so Bob's own account is paid.
- `walkthrough.step` feed rows: the engine's per-step rows plus one per product stage `{productDealId, dealId, stage, status}`.

## Stage -> ledger work (DQ-P1)
deal.ts makes onboarding, DKG and PQ records in its `keys` stage, which needs the funded escrow (T-I-01 order). So:
1 at creation: enroll, deal (coordinator deals.create), contract (seal NFT) + the PDF NFT mint; 2 to 5: signed approvals only;
6: funding, NFT sell offer to the deal wallet, identity-keys; 7: lock (+ lock checker, wiped key refused); 8 shipment; 9 receipt;
10 approval; 11 presence; 12 gate (17 codes); 13 release (EscrowFinish + 4-of-4 payment) + the wallet accepts the NFT; 14 the wallet
hands the NFT to the sender, then AccountDelete close.

## NFT and the lock order (DQ-P2)
- Minted by lawyer A's ops account at creation: `URI` = hex of the absolute PDF URL, memo `legx/contract-sha256` = the SHA-256, tfTransferable.
- NFTokenCreateOffer needs an existing Destination (tecNO_DST) and is refused once the destination sets DisallowIncomingNFTokenOffer
  (tecNO_PERMISSION) [https://xrpl.org/docs/references/protocol/transactions/types/nftokencreateoffer], so the 0-XRP sell offer to the
  deal wallet is made in stage 6, after the wallet exists and before deal.ts's `disallow` stage.
- The wallet cannot hold the NFT before the gate: `checkLock` (core, not mine) blocks `UNEXPECTED_OWNED_NFTOKENPAGE`. So the wallet
  accepts it (4-of-4 NFTokenAcceptOffer) in stage 13, after the gate; `contract.nftOwner` is set only after `account_nfts` on the
  validated ledger shows the wallet holds it. Before AccountDelete the wallet offers it to the sender (4-of-4) and the sender accepts,
  so the record survives the wallet. Design question: should lockcheck allow an NFTokenPage holding the deal's contract NFT? Then
  the NFT could sit in the wallet from stage 6.

## Changes outside demo-product
- `packages/xrpl/test-int/deal.ts`: `DealOptions.escrowDrops` (default `ESCROW_DROPS`, 50 XRP); instance code uses `this.escrowDrops`.
- `demo-walkthrough/walkthrough.ts`: any amount (drops = round(amountXrp * 1e6)); `create(..., parties?)`; `chain`/`deal` getters;
  public `row(body)`; on completion it closes only the ledger connection (the feed pool stays for the caller's last row).
  `routes.ts`: amount min 1 drop. Unit test: the old 422 `amount_fixed` case now expects 409 `not_seeded`.

## Tests
- `pnpm vitest run --project unit apps/server/test/demo-walkthrough.test.ts`: 5/5 pass (demo mounts; production 401 on all 7 product
  routes and refuses the hook; base32 RFC 4648 vectors; RID depends on both keys).
- `XRPLD_WS=ws://127.0.0.1:6200 LEGX_PG_URL=postgres://postgres:pw@127.0.0.1:5600/postgres pnpm vitest run --project integration apps/server/test-int/demo-product.int.test.ts`:
  2/2 pass. Alice, Bob, Carol register; Alice opens a 25 XRP deal with a small PDF; 403 (Bob on 2, Carol on 2, Alice on auto 7),
  409 (Alice on 4, Bob on 3); every stage approved by its actor -> released, 14/14 stages done, keys/passports/approvals 2/2,
  16-hex signature fingerprints, nftOwner == deal wallet, 17/17 gate, Bob +25 000 000 drops across stage 11's call, every tx
  tesSUCCESS, mint URI == pdfUrl and memo == sha256, NFT ends with Alice, wallet actNotFound, 14 product feed rows with dealId,
  approve after release -> 409; bad form 400, unknown deal 404. Log: build/tmp/product-server/int.log.
- Same env, `apps/server/test-int/demo-walkthrough.int.test.ts`: passes.
- `packages/xrpl/test-int/full-flow.int.test.ts` (T-I-01/T-I-10): 2 FAIL with gate `SHIPMENT_SIGNED_OK` (+1 more) failing. Not from the
  escrowDrops change (default amount unchanged; the code change is mechanical): the shipment/receipt gate codes (OD-38, the other agent's
  core work) now require shipment records that the base `Deal` never writes. Request: the shipment owner adds them to deal.ts/full-flow.
- tsc: no errors in my files. biome: clean on my files (deal.ts has 2 pre-existing unused-import warnings, not mine).

## Known gaps
- In memory (lost on restart). One serial queue for product deals, separate from the walkthrough queue.
- Ledger amount equals the entered amount (no fallback needed).
