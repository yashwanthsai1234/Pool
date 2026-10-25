# ship-web (OD-37 UI)
State: in-progress (screens, vault confirmation, dashboard done; host wiring open)

## Tests
- `LEGX_BROWSER=1 pnpm vitest run --project browser apps/web/test/party/ship.browser.test.tsx`: 10/10 (Chromium + WebKit), axe clean.
- `LEGX_BROWSER=1 pnpm vitest run --project browser apps/web/test/dashboard.browser.test.tsx`: 77 pass, 1 skipped (snapshot baseline regenerated: 3 attack buttons + timeline).
- `LEGX_BROWSER=1 pnpm vitest run --project vault-browser packages/vault/test/vault.browser.test.ts`: 44/44.
- `pnpm --filter @legx/web test` (build tests, 250 kB route budget, xrpl out of entry): 19/19.
- tsc web + vault clean; biome clean on my files.
- `apps/web/test/lawyers/walkthrough.browser.test.tsx`: 14 failures (form labels not found). Not touched by me; belongs to the walkthrough work in `src/routes/lawyers/-walkthrough`.

## Done
- Vault: `confirmationFor` decodes manifest root, carrier, tracking, condition from the tupleHash parts; `deps.confirm` must return true or `signFrost` throws APPROVAL_REFUSED (after the allow-list check).
- `-ship.tsx`: Ship (Bob) and Confirm delivery (Alice) with live root, confirm dialog, green tick / red mismatch, dispute note. Home lists it when `services.ship` exists.
- Dashboard: shipping timeline, 3 attack buttons, walkthrough.step timeline, gate panel driven by the gate step findings. Lawyer console already lists all 17 codes.

## Known gaps / Requests
- `createPartyServices` does not yet build a real `ShipPort` (needs a phone hybrid evidence signer to post `shipment.signed` / `receipt.signed`; the frame's `signHybrid` is lawyer-only). Screens run on the port interface.
- `apps/vault-host` does not yet supply `confirm`, so shipment/receipt signing is refused there until its frame UI is added.
- Console gate rows for SHIPMENT_SIGNED_OK / RECEIPT_SIGNED_OK: `it.todo` until the test world carries those events.
- Server demo-attack routes for the 3 new attacks are another agent's; the buttons call them.
