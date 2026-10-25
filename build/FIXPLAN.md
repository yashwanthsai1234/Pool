# Fix fleet (Wave H): lanes and ownership

Every open row in `build/ISSUES.md` belongs to exactly one lane, by the package it touches. If a row touches two lanes, the first lane in this list owns it and files a request to the other.

| Lane | Owns | Main issues |
|---|---|---|
| F1 contracts+auth | `packages/contracts`, `packages/db`, `services/coordinator`, `services/recovery-agent`, `services/firm-cosigner` | I-S-A1 (role from holder, not slot), I-S-M1..M4, I-S-F1, I-S-F3, `keys.register` and other 501 inputs, I-21, I-26, I-28, I-29 contexts, I-3.5-b/c, `account_info` route, I-W-14, I-W-16, `pg_notify` on outbox insert |
| F2 core | `packages/core`, `packages/chip-link`, `packages/zk` | I-S-G1 (OD-29), I-S-G2, I-S-G3, I-S-G5, I-S-P1, I-22..25, I-E1..E6, I-30 tsc, DQ-1 `phase` in lockcheck, kinds `release-code-handover` and `chip-link` |
| F3 server wiring | `apps/server`, `services/{watcher,evidence,verifier,zk-verifier,renewal}`, `packages/{signer,storage,observability}`, `tools/verifier-cli`, `scripts/demo` | I-S-E1..E5, I-W-15, 501 routes, the real release gate, watching deal wallets, checkpoint job, `deal.state` and `signature.request` producers, production adapters (I-3.7-g), demo signing helper (I-D-*), observer key (OD-31) |
| F4 web | `apps/web`, `packages/vault`, `packages/ui` | proxy port and prefix, I-S-A2 `frame-ancestors`, I-31, I-29 binding screen, ceremonies in vault iframe, OD-32, I-W-17 browser flakes |
| F5 ledger | `packages/xrpl`, `ci/` | I-2.5-a..f, I-2.6-a..e, I-2.8-a..d, I-2.9-a..f, I-27 network test |

**Order.**
1. F1 lands the contracts changes FIRST.
2. When they are in, F1 writes `build/tmp/contracts-ready`.
3. The other lanes code against the new contracts after that file exists.
4. Until then, they work on issues that need no contract change.

**Done means:**
- the issue's pinned test passes (an `it.fails` flips to a plain `it`; a `tests/break-it` test passes);
- the row is marked `fixed (<lane>)` in ISSUES.md;
- your packages' unit and integration tests, tsc and biome are green.
