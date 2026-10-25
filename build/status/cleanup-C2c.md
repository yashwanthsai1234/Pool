# cleanup-C2c
State: done (time-boxed)

Baseline (before, one file at a time, ports 5580/6190): catalogue 2 pass 1 fail (REGRESSION.md stale, other lanes edit ISSUES.md), console 2/2, ui 3 pass + 3 expected fail, wiring 83 pass + 9 expected fail, sys.test.ts no summary printed (not investigated), break-it 30 pass 1 fail (I-S-A3, pinned, issue open), demo dry run needs the dev stack (ECONNREFUSED 6113, not started).
After: REGRESSION.md regenerated (catalogue test passes after regen; see below). Full after-run not done.

Done: `demo:seed|reset|check|dry-run` aliases in root package.json (I-D-5 partly); I-8 fixed (image digest pinned in packages/storage test-int + SOURCES.md, small edit outside lane); I-D-7 and I-D-9 wontfix with reason; REGRESSION.md regenerated.

Not done: I-D-5 prestart/rehearse/FROST DKG seed/HSM start; I-W-10 `it.fails` stays (web env needs a release-signed vault origin); no `it.fails` flipped (I-14, I-31, I-W-5, I-W-11 pins unverified: I-W-11 is "fixed (F4)" but ui.test pin still expected-fail, needs an observer key in the system env); sys.test.ts baseline; after-run of all suites; knip/jscpd and line counts; demo dry run.
Note: REGRESSION.md must be regenerated (`node tests/system/support/regression.ts`) whenever ISSUES.md changes.
