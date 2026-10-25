# product-progress: DealProgress and /present/:id

- `packages/ui/src/DealProgress.tsx`: `{stages, current?, compact?, large?}`; list with `aria-current="step"`, grey/green/red dots, pulse on current (motion-safe), state also as text.
- `apps/web/src/routes/present/-stages.tsx`: `useDealStages(dealId)` (GET /api/demo/deals/:id, applies `walkthrough.step` rows `{n, ok}` at once, then refetches) and `DealFeed` (opens the feed by the deal's UUID once loaded).
- `apps/web/src/routes/present/$id.tsx`: projector view, escrow card (amount, status, Keys/Passports/Approvals x/2, names), sender to recipient with RIDs.
- Test: `apps/web/test/present.browser.test.tsx` (MSW deal + live mock; green dots on feed rows, pulse, axe). Passes on Chromium and WebKit; tsc and biome clean.
- Note: the hook lives in the web app (the ui package cannot import the web feed client); `@legx/ui` exports `DealProgress` from the index.
