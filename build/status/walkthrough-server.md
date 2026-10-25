# walkthrough-server (guided deal walkthrough, server side; build/WALKTHROUGH.md)
State: done

## What
- `apps/server/src/demo-walkthrough/` (types, steps, walkthrough, routes, index). `POST /demo/walkthrough` `{amountXrp, identity}`
  -> `{id, dealId, steps[]}`; `POST /demo/walkthrough/:id/next` -> `{step, n, status, txHashes, explorer?, ledgerIndex, detail, gate?, bob?}`;
  `GET /demo/walkthrough/:id` -> state (adds `wallet`, `ledgerDealId`, `results`, `status`).
- Registration: `apps/server/src/demo.ts`, one import plus the `demo:` line: `withWalkthrough(demoAttacks(...), {env, ledgerWs, pgUrl})`.
  The server has a single demo hook, so `withWalkthrough` wraps attack mode; the combined prefix is `/demo/`.
- Reuses `packages/xrpl/test-int/deal.ts` + `roles.ts` (relative import, as demo-attacks). Steps call deal.ts stages and runFlow's
  calls in T-I-01 order: enroll(onboarded), deal(coordinator), contract, funding, identity-keys(keys), lock(locked + lock check + the
  wiped key refused tefMASTER_DISABLED), shipment, receipt, presence(readInput), gate(17 codes), release(EscrowFinish with gate memo,
  then 4-of-4 exit to Bob, balances before/after), close(closeShell: 256 x `ledger_accept`, then AccountDelete; checks actNotFound).
- A `WalkDeal` subclass of `Deal` adds the OD-37 `shipment.signed` (slot B over shipMsg) and `receipt.signed` (slot A over rcptMsg, condition ok)
  records to `readInput`, so the real core gate sees them.
- Coordinator: `deals.create` signed with demo key lawyer-a (scripts/demo/sign.ts) via `app.inject` at walkthrough creation (genesis
  event -> evidence log and `deal.event` feed row); step 2 reads it back signed with the observer key. Each step adds one
  `walkthrough.step` outbox row (deal's next seq under the same advisory lock as OutboxRepo.enqueueNext).

## Tests
- `pnpm vitest run --project unit apps/server/test/demo-walkthrough.test.ts` : 3/3 pass (demo mounts; bad body 400; amount 422; unseeded 409;
  unknown 404; production: 401 on all three routes, and refuses to start with the hook).
- `XRPLD_WS=ws://127.0.0.1:6200 LEGX_PG_URL=postgres://postgres:pw@127.0.0.1:5600/postgres pnpm vitest run --project integration apps/server/test-int/demo-walkthrough.int.test.ts` :
  2/2 pass (all 12 steps ok, every tx validated tesSUCCESS, 17/17 gate, Bob +50 XRP, wallet actNotFound, feed rows, `next` after last -> 409 walkthrough_done).
- tsc: no errors in my files. biome: clean.
- Manual: `pnpm dev` with LEGX_DEV_PREFIX=legx-walk, ports 5711/6711/7711/8771, `pnpm demo:seed`, restart, curl through all 12 steps
  (enroll 9 tx, contract 1, funding 2, lock 12, release 2 with Bob 99999800 -> 149999800, close at ledger 321), then 409. Stack stopped, containers removed.
  `pnpm demo:seed` wrote `demo/state.json` (git-ignored).

## Design questions
- DQ-W1: OD-38 makes delivery mandatory; `delivery` is accepted (optional) and ignored for older clients. Shipment/receipt are skipped (with
  the reason in the step list) only if `build/tmp/ship-core-ready` is absent at creation.
- DQ-W2: WALKTHROUGH.md lists identity (4) before keys (5) before funding (6); T-I-01 runs funding before keys and deal.ts makes the
  onboarding records inside its keys stage, so the walkthrough has one `identity-keys` step after `funding` (12 steps).
- DQ-W3: `identity: 'zk'` sets the coordinator deal's identityPolicy, but the T-I-01 script records the chip path; the step detail says so.

## Requests
- packages/xrpl test-int: make the escrow amount a `DealOptions` field (`ESCROW_DROPS` is fixed at 50 XRP); until then any other `amountXrp` -> 422 `amount_fixed`.
- packages/contracts: add `walkthrough.step` to `OutboxTopic` (ws.ts); the server sends it, but a client that parses `WsServerMessage` strictly will reject it.

## Known gaps
- Only `deals.create` goes through the coordinator. The deal's other events (contract, DKG, pq, shipment.signed, receipt.signed, gate) are made by
  the role script locally; appending them needs the deal's enrolled holder keys (ANY_DEAL_ROLE), which the walkthrough does not enroll. So no
  waiting/retry on the coordinator's shipment routes is needed or implemented; the coordinator deal stays DRAFT while the ledger deal closes.
- A connected phone does not take over the shipment/receipt signature; the server's simulated phone always signs.
- Walkthroughs live in memory (lost on restart); explorer links only on Testnet (the demo profile uses standalone).
