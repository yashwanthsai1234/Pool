# Rules for every build agent (read fully before you start)

Repo: `/Users/sreeyashwanthsaivenkatesh/Workspace/Hackathon/pool/Pool`.

The specs are `DESIGN.md` (what to build) and `IMPLEMENTATION.md` (how to build it, task by task). Also read `build/DECISIONS.md`: it holds the orchestrator's binding answers to the design questions agents have raised. Read your task's section in IMPLEMENTATION.md and the DESIGN sections it cites. Use `grep` and `sed -n`; do not read whole files at once.

## 1. Environment
- **Shell setup.** Always run `export PATH="/Users/sreeyashwanthsaivenkatesh/Workspace/Hackathon/pool/Pool/.tools/node/bin:$PATH"` first. This gives Node 24.22.1 and pnpm 12.11.2. Never use the system Node 22.
- **No git.** Do not run git commands.
- **Package installs: always through the lock wrapper.**
  - Install packages ONLY with `scripts/pnpm-safe add <pkg>@<exact-version> --filter <your-package>`, or `scripts/pnpm-safe install`. The wrapper takes a lock, so two agents never write `pnpm-lock.yaml` at once.
  - Pin exact versions: use the ones in IMPLEMENTATION section 4 unless your research shows they are wrong (then record the evidence, see rule 3).
  - Disk is tight (about 20 GB free). Do not install large extras: no Playwright browsers except the Chromium and WebKit the web tasks need, and no Rust toolchain.
- **Packages and the TypeScript setup.**
  - A new package has a `package.json` with `"name": "@legx/<name>"`, `"type": "module"` and `"exports": { ".": "./src/index.ts" }`.
  - It also has a `tsconfig.json` with `{"extends": "../../tsconfig.base.json", "include": ["src", "test", "test-int"]}`.
  - Workspace dependencies use `"@legx/x": "workspace:*"`.
  - Relative imports always end in `.ts`, so Node 24 can strip the types.
  - Do not use `enum`, `namespace`, parameter properties or decorators (the `erasableSyntaxOnly` rule). If a library forces decorators, isolate them in one file and say so in your status file.
- **Tests: run only your own.**
  - Unit tests: `pnpm vitest run --project unit <your-package-path>`.
  - Integration tests: `pnpm vitest run --project integration <your-package-path>`.
  - Browser tests (web tasks only): `LEGX_BROWSER=1 pnpm vitest run --project browser`.
  - Typecheck: `pnpm exec tsc -p <your-package>/tsconfig.json`.
  - Lint: `pnpm exec biome check <your-package>`. Use `--write` ONLY on files you own, listed explicitly, never on a whole shared package.
- **Docker: your own containers only.**
  - Names: `legx-<taskid>-<what>`, for example `legx-2.1-xrpld`. Ports come from your prompt.
  - Image: `rippleci/xrpld:3.4.1` with `--platform linux/amd64`, started with `--standalone` and `ci/xrpld.cfg` mounted at `/etc/xrpld/`.
  - Postgres: `postgres:18.6-trixie`.
  - Stop and remove your containers when you finish. Docker has only 8 GB of memory, so run at most 2 containers at a time.
- **Networks.** Never connect to XRPL Mainnet. Testnet and Devnet are allowed for network tests only.

## 2. How to work: test-driven, in small steps
Follow the six steps of IMPLEMENTATION section 1.1, in this order:
1. **Research.** The web tools are deferred, so first load them with the ToolSearch tool, query `select:WebSearch,WebFetch`. Then use them; research is required, not optional.
   - Use WebSearch and WebFetch on primary sources: specs, RFCs, official docs, library source and changelogs. Do this for every nuance, and whenever you suspect a better approach.
   - Check that the API you plan to call really exists in the pinned version. Read its types in `node_modules`, or run a 5-line sandbox script.
2. **Test.**
   - Write the task's listed tests first.
   - Run them and watch each fail for the right reason.
3. **Think.** Decide the smallest types and API.
4. **Test in all directions.** Add property tests (fast-check), boundary tests, hostile input, concurrency tests, and a second implementation where one exists.
5. **Think hard.**
   - Ask how it could fail in production, how an attacker could use it, and whether it breaks a hard rule (IMPLEMENTATION 1.3).
   - Add a test for each risk you find.
6. **Implement.**
   - Write the smallest code that turns every test green.
   - Refactor while the tests stay green.

Work in small increments: one test, then the code for it, then run the tests. Never write a large body of code before running anything. Tests are the spec. Keep the code minimal and readable. 500 clear lines beat 200 clever ones, but nothing should be written twice, and nothing should be unused.

## 3. Evidence before change
If you want to do something different from IMPLEMENTATION.md or DESIGN.md (a different library, API or recipe), first prove it with a sandbox experiment in `build/tmp/<taskid>/`. Record the evidence (commands and output) in your status file. Never change DESIGN behavior on your own. If the design looks wrong, write it under "Design questions" in your status file and follow the design meanwhile, with an `it.todo('DQ: ...')`.

## 4. Cite your sources
Every non-trivial function gets a comment `// Source: <url>` for the spec or doc it implements, even if IMPLEMENTATION.md already names it. Each package also keeps a `SOURCES.md` that lists every URL used and what for.

## 5. Ownership
- Edit ONLY the folders your prompt lists.
- You may read anything.
- If you need a change in another package, write it under "Requests" in your status file and code against a stub meanwhile.
- `packages/contracts` is frozen after task 1.2. To change it, put a request in your status file.

## 6. Status file (required)
Write `build/status/<taskid>.md` when you start, and update it before you finish. It holds:
- **State:** `in-progress`, `done` or `blocked`.
- **Tests:** the exact commands you ran and their final pass/fail counts.
- **Coverage:** where your task requires it.
- **Research notes:** each with its source URLs.
- **Evidence:** the sandbox experiments for any deviation from the plan.
- **Files created.**
- **Design questions.**
- **Requests to other tasks.**
- **Known gaps.**

Be honest: a skipped test or an unresolved failure must be written down, never hidden.

## 7. Quality gates before you say done
- Your tests pass.
- `tsc` passes for your package.
- `biome check` passes for your package.
- No `console.log` debugging is left.
- No dead code, commented-out code or unused exports.
- No TODO without a design-question reference.
