# demo-final
**State:** done.
## Tests
- `pnpm vitest run --project unit tools/zk-prove`: 3 passed (recorded proofs load in demo; production refuses; verifier adapter gives DEVMODE_REFUSED).
- `pnpm demo:dry-run`: 13/13 on my own stack (prefix legx-demo-ph, ports 5530/6130/7080/8730). Order: reset, seed, THEN start `scripts/dev.ts` (server reads keys from state.json at start). Then `pnpm demo:reset`, stack stopped.
- `scripts/demo/phone-check.ts` through a live Cloudflare tunnel, WebKit iPhone 14: alice and bob party pages HTTP 200, isSecureContext, crypto.subtle, PublicKeyCredential all present.
## Built
- `tools/zk-prove/cli.ts` (+ `src/recorded.ts`): fresh release proof bound to `--presence-msg`; recorded fallback on network failure or `--recorded`. The fresh path was NOT run here (needs Sepolia and the CDN, about 20 s); it is the recipe of `packages/zk/tools/record.ts`.
- `demo/recorded-proofs/` (3 sets + README), `demo/rehearsal/` (4 screenshots), `pnpm demo:rehearse`, `pnpm demo:phones` (cloudflared installed with brew, plus qrencode), dry-run steps replaced.
- Docs: `docs/DEMO.md` "Two phones" section; I-D-5 and I-D-6 closed. I-D-8 stays: a human records the video.
## Known gaps
- Real phones, iPhone FIDO2 and the ZKPassport app are untested. The tunnel URL changes per start. Recorded proofs are not bound to the live presenceMsg.
- Root `package.json` got the `demo:rehearse` and `demo:phones` aliases (not my file; same as earlier C2c aliases).
