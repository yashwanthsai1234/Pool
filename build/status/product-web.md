# product-web
State: in-progress (my scope now: apps/web/src/routes/deals/ only)

## Handover (already written by me, untested, biome-formatted, never run; P2 and P3 take over)
- P2: packages/ui/src/DealProgress.tsx (props: stages[{n,name,status}], compact), exported from packages/ui/src/index.ts; apps/web/src/routes/present/$id.tsx
- P3: apps/web/src/routes/register/index.tsx, apps/web/src/routes/me/index.tsx
- Shared helpers I wrote (used by deals too, keep the exports): apps/web/src/lib/demo-deals.tsx (API client, types, hooks,
  LiveProgress = DealProgress + feed invalidation of ['demo'] queries on any row for deal.dealId), apps/web/src/lib/demo-ui.tsx.
- Assumptions: approve body {rid, stage: <stage number n>}; stage.actor is 'sender'|'recipient'|'auto'; API at /api/demo/*;
  routeTree.gen.ts needs regenerating (vite build/dev) for the new routes; theme.css biome parse error is pre-existing.

## deals (my scope)
Files: routes/deals/index.tsx, routes/deals/-detail.tsx, test/deals/deals.browser.test.tsx (renders Route.options.component, MSW + live mock).
Tests: `LEGX_BROWSER=1 pnpm vitest run --project browser apps/web/test/deals`: 10/10 (Chromium + WebKit): dropdowns, same-party refusal,
multipart PDF upload, tabs, released detail + All metadata, dots green on walkthrough.step row, axe.
biome clean on my files. Not done: real-server Playwright run, full `pnpm --filter @legx/web test`, route-tree regeneration, bundle budget.
