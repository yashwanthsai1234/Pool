# Phase 7 cleanup (Wave I): lanes and rules

| Lane | Owns |
|---|---|
| C1 core | `packages/{core,contracts,chip-link,zk}`, root config (installs the tools) |
| C1b ledger+infra libs | `packages/{xrpl,fixtures,db,signer,storage,observability,fuzz}`, `tools/*`, `spec/`, `.github/` |
| C2 auth services | `services/{coordinator,recovery-agent,firm-cosigner}`, `apps/server` |
| C2b data services | `services/{evidence,verifier,zk-verifier,renewal,watcher}`, `apps/mock-bar-registry` |
| C2c scripts+tests | `scripts/`, `tests/*`, `demo/` |
| C3 web app | `apps/web` |
| C3b vault+ui | `packages/{vault,ui}`, `apps/vault-host` |

**Tools.** C1 installs `knip`, `jscpd` and `dependency-cruiser` at the root (exact versions, through `scripts/pnpm-safe add -D -w`), writes their config, then `touch build/tmp/cleanup-tools-ready`. C2 and C3 wait for that file before running the tools; meanwhile, they start on the open issues.

**Rules.**
1. **No behavior change.** Every test that passed before must still pass. Take a baseline of the counts before you start, and compare after (that is the before/after A/B).
2. **Dead code:** unused files, exports, dependencies and types (knip). Remove them, unless something outside your lane uses them; check with grep.
3. **Duplication:** jscpd at a minimum of 30 tokens. Merge duplicates into one place within your lane. If the shared home is in another lane, file a request.
4. **Simplicity:** look for 200 lines that could be 50. Remove needless layers, one-call wrappers and over-general helpers. Keep the code readable. Do not golf it.
5. **Architecture rules (dependency-cruiser):**
   - core imports no service, app or Node-only module (OD-27);
   - services never import `@noble/post-quantum` sign or keygen (OD-24);
   - no import cycles;
   - apps never import service internals.
6. **Stale content:** comments that describe old behavior, TODOs without a DQ reference, `console.log`, skipped tests with no reason, and leftover `build/tmp` experiments referenced by code.
7. **Open issues:** every row in `build/ISSUES.md` without "fixed" whose package is in your lane. Verify it. If it is already fixed, mark it `fixed (verified C<n>)` with the test that shows it. Otherwise fix it test first, or mark it `wontfix: <reason>` only with evidence.
8. **Report the line counts** of your lane, before and after (`find ... -name '*.ts*' | xargs wc -l`).
