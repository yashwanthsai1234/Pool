# Zero-knowledge flow on the ledger (task 2.9, T-I-12)

`zk-flow.int.test.ts` runs the full flow P0 to P8 with ZKPassport identity on a real standalone ledger.

- Roles, records and ledger reads come from `../roles.ts` (task 2.5). `zkFlow.ts` is the 2.5 flow with the chip
  identity replaced per side by ZK proofs. `openChain` has `idle()` (see below). `zkTools.ts` makes proofs.
- Proofs are FRESH. The vendored headless prover (`packages/zk/tools/zk-prove/`) proves, on mock passports:
  onboarding at P5 (bound to the contract root and the planned slot key) and release at P7 (bound to the real
  `presenceMsg`: deal seal, fresh ledger hash, lawyer nonce). Each proof set takes about 20 s.
- Verification goes through `@legx/zk-verifier` (task 3.11): the real SDK 0.19.2, `verifierMode: "local"`, devMode on,
  Sepolia registry roots. The gate runs in the **demo profile**; the same records fail in the production profile.

Run: `XRPLD_WS=ws://127.0.0.1:6111 pnpm vitest run --project integration packages/xrpl/test-int/zk` (about 3 minutes).

## Needs the network
Sepolia RPC (`SEPOLIA_RPC_URL` replaces the registry's built-in endpoint) and ZKPassport's circuit CDN. Without
them the file fails at once; it is not a pull-request test until a mirror of both exists (issue I-2.9-a). The
offline real-SDK check of the recorded proofs on every pull request is task 1.17's `packages/zk/test/offline.test.ts`.

## Trade-offs
- Fresh proofs prove the whole path (a new presenceMsg, a new ledger hash each run) but cost network and time. The
  recorded proofs (`packages/zk/fixtures/`) replay offline but cannot be bound to a new deal. Both are used.
- A passing face match cannot be made headless, so release proofs have the face match off (`faceMatchOptional`,
  deal data allows it, O12). The flow records `face_match_passed` false, the honest result (OD-34, I-DOC-1): the demo
  profile accepts it for a dev-mode proof and the gate adds a `DEMO_NO_FACE_MATCH` warning; production refuses it.
- The gate trusts the lawyer's attestation for "the proof is bound to this presenceMsg" (OD-2 style): a proof bound to an
  old ledger hash is stopped where the lawyer checks (`checkZkResult` gives `BOUND_VALUE_MISMATCH`); a lawyer who lies is
  caught only by an arbitrator's offline re-verification, not by the gate.
- `idle()` stops the background ledger closer while a proof is made: a standalone server keeps 256 ledgers, and the
  mint transaction would be forgotten before the gate reads it.
- P2.9-01 replays each recorded set with the clock at its recording day (the SDK's expiry check counts whole days),
  and expects the services adapter to refuse the `other.app` set (`WRONG_DOMAIN`).

## Sources
- ZKPassport SDK verify and query builder: https://docs.zkpassport.id ; SDK 0.19.2 typings (see `packages/zk/SOURCES.md`)
- Registry `isRootValid`: https://github.com/zkpassport/zkpassport-packages/blob/a61b0cf461f1fab10e1b838dacd81e862107acb0/packages/registry-sdk/src/client.ts
- rippled ledger history in standalone: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/server-info-methods/server_info (`complete_ledgers`)
