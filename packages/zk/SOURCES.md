# Sources for `@legx/zk`

| URL | Used for |
|---|---|
| DESIGN.md 6.2, 6.10, 6.15 (this repo) | scope, domain, bound values, trust record, production refusals, offline re-verification |
| https://docs.zkpassport.id | request builder, `verify()`, dev mode and mock passports |
| https://github.com/zkpassport/zkpassport-packages/blob/a61b0cf461f1fab10e1b838dacd81e862107acb0/packages/e2e/src/prove.ts | the vendored headless prover (`tools/zk-prove/prove.ts`) |
| https://github.com/zkpassport/zkpassport-packages/blob/a61b0cf461f1fab10e1b838dacd81e862107acb0/packages/zkpassport-sdk/LICENSE | Apache License 2.0 of the vendored prover (`tools/zk-prove/LICENSE`) |
| https://github.com/zkpassport/zkpassport-packages/blob/a61b0cf461f1fab10e1b838dacd81e862107acb0/packages/registry-sdk/src/client.ts | `isRootValid` eth_call layout (selector `0x2aae4296`, registry id, root, timestamp), URL generators |
| https://github.com/zkpassport/zkpassport-packages/blob/a61b0cf461f1fab10e1b838dacd81e862107acb0/packages/zkpassport-utils/src/circuit-matcher.ts | `getExpiryDateCircuitInputs` (gt adds one day; `min_date`/`max_date`) |
| `@zkpassport/sdk` 0.19.2 `dist/esm/index-D9GMXc4k.d.ts` and `dist/cjs/index.cjs` | `QueryBuilder` API (`gt`, `facematch(mode = "strict")`, `bind`), `verify({ config })` passing `config` to `createRegistryClient`, `checkCurrentDate`, facematch checks |
| `@zkpassport/registry` 0.15.3 `dist/esm/client-D-z_zVp1.d.ts` | `RegistryClientOptions` loaders (`rpcUrl`, `circuitManifestUrlGenerator`, `packagedCircuitUrlGenerator`, `packagedCertsUrlGenerator`, `sanctionsTreeUrlGenerator`) |
| https://nodejs.org/api/module.html#modulecreaterequirefilename | loading the SDK through CommonJS |
| https://www.rfc-editor.org/rfc/rfc2606#section-2 | `.invalid` host names for the offline loader URLs |
| https://www.apache.org/licenses/LICENSE-2.0#redistribution | section 4(b): marking the changes in the vendored prover |
| https://biomejs.dev/linter/rules/no-restricted-imports/ | the core lint rule that bans `@zkpassport/*` |
