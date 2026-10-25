# walkthrough-web
State: done

## Built
- `/lawyers`: "New deal" button + form (amount fixed at 50 XRP, read-only; identity zk|chip; delivery removed per OD-38), "Deal walkthrough" stepper
  (Run enabled only for the next step, status, tx hashes with Testnet links via `?network=testnet`, gate findings, Bob before/after, Run all with pause, error alert, retry).
- Shown only when `GET /api/demo/attack` is 200 (demo profile). Uses plain fetch like the attack panel (demo routes are unsigned), not the vault-signed client.
- Steps come from the server's `steps[]` (12 steps incl. shipment and receipt). No animation, so reduced motion is respected; large type.

## Tests
- `LEGX_BROWSER=1 pnpm vitest run --project browser apps/web/test/lawyers/walkthrough`: 18/18 (chromium + webkit), incl. axe.
- `pnpm --filter @legx/web test`: 19/19. tsc: no errors in my files. biome: clean.
- Real server (ports 5721/6721/7721/8781, vite 5181, demo:seed, Playwright Run all): all 12 steps done through release and close, no errors. Stack stopped, containers removed.

## Files
apps/web/src/routes/lawyers/index.tsx, -walkthrough/api.ts, -walkthrough/ui.tsx, apps/web/test/lawyers/walkthrough.browser.test.tsx

## Known gaps
- Bundle size and xrpl exclusion: the stepper imports only zod, @legx/ui and the dashboard explorer helper (no xrpl); the web-build bundle budget test was not run separately.
- Form is rendered above the console in the same page; not lazy-loaded.
