# Sources for spec/ (task 5.1)

| What for | URL |
|---|---|
| Quint CLI: `typecheck`, `test`, `run` (`--max-steps`, `--max-samples`, `--n-traces`, `--out-itf`, `--witnesses`), `verify` (`--backend`, `--temporal`, `--random-transitions`, `--tlc-config`) | https://quint.sh/docs/quint |
| Apalache is the default `verify` backend and is downloaded on first use; TLC with `--backend=tlc` needs bounded domains | https://quint.sh/docs/model-checkers |
| Quint syntax: sum types, records, `nondet`, `any`, runs with `.then`, `.expect`, `.fail` | https://quint.sh/docs/lang |
| Invariants and temporal properties | https://quint.sh/docs/checking-properties |
| How Quint runs TLC: the `.cfg` (INIT, NEXT, INVARIANT, PROPERTY only), `-deadlock`, TLC from the Apalache jar, the `tlc-config` keys | https://github.com/quint-co/quint/blob/main/quint/src/tlc.ts |
| `weakFair` and `strongFair` definitions | `node_modules/@informalsystems/quint/dist/src/builtin.qnt` (Quint 0.33.0) |
| Apalache `check` and `simulate` options, deadlock checking with `discard-disabled` | https://apalache-mc.org/docs/apalache/running.html |
| Apalache tuning options | https://apalache-mc.org/docs/apalache/tuning.html |
| ITF trace format (read by the export test and the 1.14 replay) | https://apalache-mc.org/docs/adr/015adr-trace.html |
| XRPL multi-signing: every signer must be in the list, quorum by weight | https://xrpl.org/docs/concepts/accounts/multi-signing |
| XRPL master key, regular key | https://xrpl.org/docs/concepts/accounts/cryptographic-keys |
| XRPL DepositAuth: the sender of EscrowFinish is checked | https://xrpl.org/docs/concepts/accounts/depositauth |
| States, I1 to I8, FROST slots, identity, release gate | DESIGN.md 5.1, 5.4, 6.4, 6.10, 6.15, 6.17, Appendix C |
