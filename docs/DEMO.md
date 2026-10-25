# Judge demo script (task 5.6)

## Two phones
1. `brew install cloudflared qrencode` (once). Run `pnpm demo:seed` first, then `pnpm demo:phones`.
2. It starts a free Cloudflare HTTPS tunnel (no account) to the web app, sets `LEGX_TUNNEL_URL` and the WebAuthn RP ID and origin to the tunnel host, starts the stack, and prints a QR code for Alice's phone, one for Bob's, and the laptop URLs (`/lawyers`, `/dashboard`).
3. Phones need HTTPS for WebCrypto and WebAuthn: a LAN `http://` address will not work. The tunnel URL changes on every start, so scan fresh codes each time (and passkeys made under an old URL do not carry over).
4. Check without phones: `node scripts/demo/phone-check.ts <tunnel-url>` (WebKit at iPhone size: page loads, `crypto.subtle` and `PublicKeyCredential` exist).
5. Other ports: `LEGX_DEV_PREFIX`, `LEGX_PG_PORT`, `LEGX_LEDGER_PORT`, `LEGX_REGISTRY_PORT`, `LEGX_PORT`, `WEB_PORT`.

Shell: `export PATH="$PWD/.tools/node/bin:$PATH"`. Scripts live in `scripts/demo/`; state is `demo/state.json` (git-ignored, holds seeds). Profile: demo (see IMPLEMENTATION section 3 for every shortcut: mock registry, fixture passports, local key file, local WORM folder, in-process log, ZKR mock passports on Sepolia roots).

## Before the day
| When | Command | Notes |
|---|---|---|
| Day before | `node scripts/demo/seed.ts --network testnet` | Funds 6 accounts (6 faucet calls), makes the observer key. Idempotent: a second run calls no faucet. |
| Day before | rehearse the fallback twice (below) | |
| Morning | `node scripts/dev.ts` then `node scripts/demo/check.ts` | One GREEN or RED line per item. Set `LEGX_TUNNEL_URL`, `LEGX_ZK_RPC` first. Tick manual items in `demo/state.json` `manual`. |
| 30 min before | start deal #2 (to `VERIFIED`, short `CancelAfter`) | NOT BUILT (I-D-5, remaining part): expiry and close scenes need it. |
| Day before | `pnpm demo:rehearse` | Screenshots of each scene into `demo/rehearsal/` (needs the web app running). |
| Any time | `node scripts/demo/dry-run.ts` | Walks the demo; prints failing steps with exact errors. |

## Script (about 9 min)
Setup: Alice and Bob on phones (`/party/alice`, `/party/bob` through the tunnel), Lawyer A and B in two tabs on one laptop, dashboard on the projector (observer key).

| # | Min | Step | Fallback |
|---|---|---|---|
| 1 | 0:00 | Say: "everything here is a demo: fake lawyers, fake passports, real XRPL Testnet." Show the DEMO banner. | none needed |
| 2 | 0:30 | Dashboard on projector: live ledger index ticking, 19 ports healthy (`/health`). | `/health` in a browser |
| 3 | 1:00 | Lawyers A and B enrolled; show both ACTIVE in the mock bar registry (`DEMO-0001`, `DEMO-0002`). | registry page `http://127.0.0.1:7070` |
| 4 | 2:00 | Alice proves identity with ZKPassport (ZKR mock passport). | recorded ZK proofs in `demo/recorded-proofs/`, or headless prover (`tools/zk-prove`). Both built: `tools/zk-prove/cli.ts`, `demo/recorded-proofs/README.md`. |
| 5 | 3:00 | Bob reads the fixture passport chip (`bob`). | fixture passport in the browser |
| 6 | 4:00 | Each phone signs with its two shares. If a phone has no FIDO2 key, SAY ALOUD: "Single-device mode: no theft protection on this phone." | the screens show the label |
| 7 | 5:00 | Deal created, funded, verified: open the transaction on the Testnet explorer. | screenshots of the explorer in `demo/` |
| 8 | 6:30 | Release: gate runs, payment lands. | standalone ledger, `ledger_accept` |
| 9 | 8:00 | Deal #2 (started 30 min ago): expiry and close scenes. | standalone: advance time |
| 10 | 9:00 | Record award (teammate), exit. | |

Steps 3 to 10 are only partly wired today: see `build/ISSUES.md` I-D-1 to I-D-8.

## Fallbacks
- **Offline (dead Wi-Fi, Testnet, faucet or explorer down):** `node scripts/demo/reset.ts && node scripts/dev.ts && node scripts/demo/seed.ts --network standalone`. This runs Postgres, the standalone ledger (`rippleci/xrpld:3.4.1`), the registry and the server, all on `127.0.0.1`. Open the pages on the laptop instead of the phones. (A dedicated `demo:fallback` that rewrites a live deployment is NOT BUILT, I-D-7.)
- **ZKPassport relay, CDN, Sepolia RPC or phone app down:** play the recorded proofs (`demo/recorded-proofs/`), or run the headless prover. built: `tools/zk-prove/cli.ts`, `demo/recorded-proofs/README.md`.
- **Tunnel down:** Tailscale Funnel first, `cloudflared tunnel --url http://127.0.0.1:8710` second, laptop-only as last resort.
- **Everything down:** show the screenshots in `demo/rehearsal/` (made by `pnpm demo:rehearse`). A human records the backup video `demo/backup.mp4` by walking the demo once while following those screenshots; an agent cannot record video (I-D-8, human task).

## Reset
`node scripts/demo/reset.ts` (removes the Postgres and ledger containers and `demo/state.json`). `--keep-testnet` keeps a Testnet state (the funded accounts) and only resets the local stack.
