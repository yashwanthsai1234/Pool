# product-me
State: done

Scope: apps/web/src/routes/register/, apps/web/src/routes/me/, apps/web/test/me/.
Implementation was handed over by product-web (untested); I tested it, no source change needed (biome only reformatted nothing).

## Tests
- `LEGX_BROWSER=1 pnpm vitest run --project browser apps/web/test/me`: 18/18 pass (9 tests x Chromium + WebKit, 390x844, MSW).
  Covers register (POST body, name/RID/fingerprint, localStorage, link to /me, 44px target), unregistered redirect link,
  only-my-deals, only-my-button (exactly one button), POST {rid, stage}, "Waiting for <name>", Fund escrow label, 403 and 409 alerts, axe (serious/critical).
- `pnpm --filter @legx/web test`: 4 files, 19 pass. `tsc -p apps/web`: clean. `biome check` on my files: clean.
- Size: /me and /register gz JS+deps = 158 kB (index 106 kB) < 250 kB.

## Notes
- DealProgress is imported from `@legx/ui` (P2's file exists; `@legx/ui/DealProgress` subpath resolved to .ts and failed until P2 fixed it).
- Mock deals need a UUIDv7 dealId, because the live feed validates `subscribe`.
- /me does not redirect automatically; it shows "Not registered" with a link to /register.

## Known gaps
- Stage labels for 3 and 5 reuse the sender labels ("Verify my passport", "Set up my keys").
