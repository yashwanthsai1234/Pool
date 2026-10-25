# cleanup C3b (packages/{vault,ui}, apps/vault-host)
State: stopped at deadline; NO code changed.

Baseline (no edits made):
- vault+ui unit: 4 files / 12 tests pass.
- vault-host unit: 4 pass, 2 fail by 5 s timeout (P4.10-01, P4.10-02 build tests, machine under load from parallel agents; not logic). Re-run with a longer timeout when quiet.
- LEGX_BROWSER=1 vault-browser: not captured (invocation with path filter printed no counts).

Verified:
- I-20: already `fixed (verified C3)`; unchanged.
- OD-36a vault side: `packages/vault/src/seal.ts` pins the seal at join (set once) and recomputes `dealSeal` over public data; accepts only on match. Test: `packages/vault/test/seal.browser.test.ts`.

Not done:
- Ceremony duplication across frost/pq/single ops (ceremony.ts 277 lines; not analysed).
- jscpd in lane found only test/config clones (6 lines each: vault-host frame.browser.test/world.ts, vitest.browser.config.ts x3); not merged.
- knip, dependency-cruiser, line counts before/after.
