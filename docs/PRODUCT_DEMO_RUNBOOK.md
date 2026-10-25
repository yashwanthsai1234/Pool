# Product demo runbook (two phones, one laptop, one projector)

Spec: `build/PRODUCT_DEMO.md`. Demo profile only; every screen says "demo: keys held by the server".

## Start
```
export PATH="$PWD/.tools/node/bin:$PATH"
pnpm demo:seed
pnpm demo:phones        # stack + web app + HTTPS tunnel; prints QR codes and laptop URLs
```
The tunnel URL changes on every start; scan fresh codes. Without phones (laptop only): `node scripts/dev.ts` in one shell, `./node_modules/.bin/vite --port 5173` in `apps/web` in another, then use `http://127.0.0.1:5173`. Other ports: `LEGX_DEV_PREFIX`, `LEGX_PG_PORT`, `LEGX_LEDGER_PORT`, `LEGX_REGISTRY_PORT`, `LEGX_PORT`, `WEB_PORT`.

## URLs
- Alice's phone: `<tunnel>/register`, then `<tunnel>/me` (use the Alice QR printed by `pnpm demo:phones`).
- Bob's phone: the same pages, from his QR.
- Laptop: `<tunnel or http://127.0.0.1:5173>/deals`.
- Projector: `/present/<deal id>` (click the deal on `/deals` for its ID, or read it from `GET /api/demo/deals`).

## Click order
1. Alice's phone: `/register`, type "Alice", Register. Bob's phone: the same with "Bob". Each shows "You are Name · rid_...".
2. Laptop `/deals`: Sender = Alice, Recipient = Bob, amount 25, terms, upload a PDF, Create deal. The row appears under Locked escrows.
3. Open `/present/<id>` on the projector: 14 grey dots (stage 1 is already green).
4. Approve in this order, each on the named person's `/me` (the big button shows only for the right person; the other sees "Waiting for ..."):
   Alice passport, Bob passport, Alice keys, Bob keys, Alice fund escrow, (wallet check runs by itself), Bob sign shipment, Alice sign receipt, Alice approve release, Bob approve release. The gate, release and wallet close run by themselves.
5. Laptop: Released escrows tab, click the row.

## What the judges see
The projector dots turn green one by one with no reload; phones show only their own next action; the Released card lists names with RIDs and key fingerprints, amount, terms, the contract PDF, SHA-256, NFT ID and owner (the deal wallet), who released with signature fingerprints, the 17 gate checks, the transaction hashes and an "All metadata" JSON section.

## Automated check
`pnpm demo:product [web-url]` runs this whole flow (Chromium laptop, WebKit iPhone phones), screenshots into `demo/product-e2e/`, and exits non-zero on failure.

## Reset
```
node scripts/demo/reset.ts && node scripts/dev.ts --down
```
then start again from "Start". (`pnpm dev:down` also removes the containers.)
