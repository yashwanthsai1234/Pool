# UX U1: shared primitives, home, /register, /me, DealProgress

## Done
- `apps/web/src/lib/demo-ui.tsx`: Page (nav with aria-current, 28 px title, subtitle, `action` slot), Card, StatusChip (locked/released/failed/pending, SVG icons), RidChip (name, short RID, copy button, fingerprint tooltip), PrimaryAction (fixed bottom on phones with safe-area inset, static and first on sm+, spinner, aria-busy, disabled reason), TurnBanner, Toast, SuccessMessage, useToast, Skeleton, EmptyState, TxLink, Icon, WELCOME_KEY. The old exports (shortRid, who, DemoLabel, NAV_LINKS, Nav, Page, Field, INPUT) still work.
- `packages/ui/src/theme.css`: additive tokens warn, surface, soft, pass-bg, fail-bg, warn-bg (light and projector themes).
- `packages/ui/src/DealProgress.tsx`: 36 px dots (64 px when large) with a check, a cross or the step number; a ring and pulse on the current step (motion-safe); a compact track for cards with "Now: …" and n/14. The data-status, aria-current and sr-only contracts are unchanged.
- `/register`: one field and a PrimaryAction ("Type your name first" while empty); on success it saves the RID and navigates to /me, which shows a welcome toast. An already-registered device sees its RidChip.
- `/me`: a TurnBanner, deal cards (StatusChip, compact dots, whose turn), and ONE PrimaryAction for my next step. Success toasts carry a TxLink, errors are in plain words with the server text in small print, and there are skeletons and empty states. The live dots come from `useDealStages` (polling, no /ws). After an approval it calls setQueryData and invalidates, so the dot turns green at once.
- Home: step tiles. Someone else added a "scan to register" QR card here concurrently; it is left untouched.

## Gates
- Browser tests: me, present, deals, routes and packages/ui all pass (90/90, Chromium and WebKit). New tests cover the redirect with the welcome toast, the turn banner, the success toast with the tx link and the instant dot, the skeleton and empty state, and the bottom-pinned 48 px button.
- `pnpm --filter @legx/web test` 19/19 (bundle budget); tsc for web and ui is clean; biome is clean on the owned files; axe passes in the tests.

## Screenshots
`build/tmp/ux/{phone,desktop}-*.png`: WebKit 390x844 and Chromium 1440x900, against the dev server on :5173. They use Playwright route mocks of /api/demo (MSW-equivalent fixtures), not the MSW service worker.

## Not done
- There is no system dark theme for the demo pages; the projector theme is the dark one. Adding prefers-color-scheme would move the party/dashboard screenshot baselines.
