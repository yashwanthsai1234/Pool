# Final cleanup (packages, services, apps)

State: done for the gates; open items listed below.

Lines (ts+tsx, before -> after): packages 54648 -> 54650, services 22110 -> 22083, apps 18519 -> 18596 (new `deps.ts`, `router-context.ts`, core `xwingShareCipher.ts`; the formatter touched files).

dependency-cruiser: 3 no-circular errors -> 0 (holder/policy: Sign* types moved to policy.ts; router: RouterContext in lib/router-context.ts; server: ServerDeps in deps.ts).

knip (whole repo): unused files 6 -> 9, deps 26 -> 17, devDeps 17 -> 10, exports 57 -> 16, types 11 -> 3 (the remaining rows are mostly in tests/, tools/, scripts/, other lanes).
Removed deps: server (renewal, kysely), vault-host core, observability resources, coordinator noble-hashes, evidence (xrpl, zod, pglite, fast-check, pg, @types/pg), recovery-agent noble-hashes, renewal (db, pg, @types/pg), zk-verifier storage, watcher pglite.
Kept (knip is blind to their users): @zkpassport/registry, utils, bb.js, noir_js (zk src/sdk.ts and tools/zk-prove), xrpl fixtures and zk-verifier (test-int), ui deps (src), coordinator pg and @types/pg (test-int), coverage-v8 and browser-playwright (vitest config), tailwindcss (css).
Unused test-helper exports un-exported; ones used by test-int or other lanes were restored (tsc is the check).

jscpd: 3.85% -> 3.84% lines (444 clones). Merged the X-Wing share cipher (vault + recovery-agent -> core `xwingShareCipher.ts`). Remaining src clones are 13-27 lines (import blocks, cross-package vault/recovery-agent holder); not merged.

Gates: unit 3095 pass; typecheck 0 errors; biome 0 errors; browser/vault-browser/core-browser 933 pass; web 19 pass.

Not done: open ISSUES rows (I-7, I-12, I-13, I-14, I-15, I-18, I-19, I-3.7-e/f, I-S-A3, I-S-X1, I-2) need feature work, not cleanup; none verified fixed or marked wontfix here.
