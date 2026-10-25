# Product demo UI: the binding spec

Demo profile only (mounted like `demo-attacks`; production refuses to mount it). It builds on the guided walkthrough engine in `apps/server/src/demo-walkthrough/`, which runs a real deal on the real ledger (T-I-01 role script). Keys for Alice, Bob and the lawyers are held by the server in this profile, and every screen shows a small "demo: keys held by the server" label.

## 1. Participants and RIDs
- `POST /demo/participants {name}` registers a participant.
  - The server makes the participant's demo keys: a hybrid Ed25519 + ML-DSA-65 enrollment pair, plus an XRPL account funded on the standalone ledger.
  - `rid = "rid_" + base32lower(first 10 bytes of tupleHash("legx/rid/v1", [ed25519Pub, mldsa65Pub])))`. It is a fingerprint of the keys, so the name links to the RID and the RID links to the keys.
  - Returns `{rid, name, fingerprint: hex(full 32-byte hash), xrplAddress, createdAt}`.
- `GET /demo/participants` returns every participant as `[{rid, name, fingerprint, xrplAddress}]`.
- The UI always shows the name in front and the RID behind it: "Alice · rid_k3x9…".

## 2. Deals
- `POST /demo/deals` takes multipart form data:
  - `senderRid`: the sender funds the escrow (buyer, Alice's role);
  - `recipientRid`: the recipient is paid on release (seller, Bob's role);
  - `amountXrp`: an integer from 1 to 1000;
  - `terms` (short text);
  - `contractPdf`: `application/pdf`, at most 5 MB.

  The server:
  1. stores the PDF (local object store, demo);
  2. computes `contractSha256`;
  3. creates the deal through the walkthrough engine, with sender in Alice's role and recipient in Bob's role;
  4. mints the contract NFT with `URI` = the PDF's URL and a memo holding `contractSha256`, **owned by the deal wallet**.

  It returns the deal summary (section 4). The ledger amount is the entered amount. If the T-I-01 script cannot vary it, the ledger uses its fixed amount, the UI shows the entered amount, and the status file says so.
- `GET /demo/deals?status=locked|released` lists deals.
- `GET /demo/deals/:id` returns the full detail (section 4).
- `GET /demo/deals/:id/contract.pdf` returns the stored PDF.

## 3. Stages and approvals
Each stage has an actor. Only that actor's approve button advances it: `POST /demo/deals/:id/approve {rid, stage}`. The server refuses a wrong actor (403) and a wrong order (409). Stages, in order:

| # | Stage | Actor |
|---|---|---|
| 1 | Contract signed (PDF minted as NFT) | auto at creation |
| 2 | Sender passport verified | sender |
| 3 | Recipient passport verified | recipient |
| 4 | Sender keys set up (FROST DKG + PQ binding) | sender |
| 5 | Recipient keys set up | recipient |
| 6 | Escrow funded (amount locked) | sender |
| 7 | Wallet locked and checked | auto after 6 |
| 8 | Shipment signed | recipient |
| 9 | Receipt signed | sender |
| 10 | Sender approves release | sender |
| 11 | Recipient approves release | recipient |
| 12 | Release gate (17 checks) | auto after 11 |
| 13 | Funds released to recipient | auto after 12 |
| 14 | Wallet closed | auto after 13 |

- An "auto" stage runs right after the stage before it.
- Each approval records `{rid, name, at, signatureFingerprint}`. The signature fingerprint is the first 16 hex characters of SHA-256 of the actor's Ed25519 signature over `tupleHash("legx/demo-approve/v1", [dealId, stage, rid])`.
- Every change pushes a `walkthrough.step` feed row with the deal ID, so all screens sync live.

## 4. Deal summary (what a lawyer needs to see)
```
{ id, dealId, createdAt, status: 'locked'|'released',
  sender: {rid,name,fingerprint,xrplAddress}, recipient: {...},
  amountXrp, terms,
  contract: { sha256, pdfUrl, nftId, nftOwner(deal wallet), mintTx },
  escrow: { status: 'not funded'|'locked'|'released', amountXrp, walletAddress, fundTx?, releaseTx?, closeTx?,
            keys: { done: n, of: 2, by: [{rid,name,at}] },
            passports: { done: n, of: 2, by: [...] },
            approvals: { done: n, of: 2, by: [{rid,name,at,signatureFingerprint}] } },
  stages: [{ n, name, actor, status: 'pending'|'done'|'failed', at?, by?, txHashes[] }],
  gate?: { passed, findings[17] },
  releasedAt?, releasedBy?: [{rid,name,signatureFingerprint}],
  ledger: { network, explorerBase? } }
```

## 5. Screens (web)
- **`/register` (phone):** name field, Register button, then shows "You are Alice · rid_…" with the fingerprint. The RID is remembered in localStorage for this device.
- **`/me` (phone, user page):**
  - the deals I'm in (as sender or recipient);
  - per deal: the **progress artifact** (section 6), plus big buttons for MY next stage only ("Verify my passport", "Set up my keys", "Fund escrow: 50 XRP", "Sign shipment", "Sign receipt", "Approve release");
  - other actors' stages show "Waiting for Bob".
- **`/deals` (laptop, deal page):**
  - **Create deal:** a sender dropdown and a recipient dropdown (every registered participant, shown as name · RID; sender and recipient must differ), amount, terms, contract PDF upload, and a Create button.
  - Tabs **Locked escrows** and **Released escrows**. Each row shows names, amount, status and progress dots. Clicking a row opens the detail.
- **Detail view:**
  - **Locked:** status (for example "Keys 1/2 · Passports 1/2 · Approvals 0/2"), each with who did it; escrow status; the progress artifact.
  - **Released:** a concise summary card covering:
    - parties (name, RID, fingerprint);
    - amount; terms; contract (PDF link, SHA-256, NFT ID, owner);
    - times;
    - who released, with signature fingerprints;
    - the 17 gate checks;
    - transaction hashes;
    - an expandable "All metadata" JSON section.
- **`/present/:id` (projector):** the progress artifact full screen, plus the escrow card.

## 6. Progress artifact (shared component in `packages/ui`)
- One dot per stage, in order, with its name under it: grey for pending, green for done, red for failed.
- The current stage pulses, unless reduced motion is set.
- Live via the feed. The same component is used on `/me`, `/deals`, the detail view and `/present`.
