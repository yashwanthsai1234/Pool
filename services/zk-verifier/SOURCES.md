# Sources for `@legx/zk-verifier`

| URL | Used for |
|---|---|
| DESIGN.md 6.10 "Trust anchors", "Offline re-verification"; IMPLEMENTATION 3.11 (this repo) | local mode only, two RPC providers, pinned SDK, trust record, production refusals, retry errors |
| https://docs.zkpassport.id | `verify()`, `verifierMode`, `devMode`, the Sepolia registry for mock passports |
| `@zkpassport/sdk` 0.19.2 `dist/cjs/index.cjs` | the hosted verifier URL constant `https://verifier.zkpassport.id`; `checkRegistryRoot` swallows a failed registry read and reports `verified: false` (so the egress guard records the real cause) |
| `@zkpassport/registry` 0.15.3 `dist/cjs/index.cjs` | default circuit, certificate, sanctions and IPFS hosts (`*.zkpassport.id`); `createRegistryClient('ethereum_sepolia').rpcUrl` |
| https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_call | the second provider repeats the recorded `eth_call`s at the same block number |
| https://aws.amazon.com/builders-library/timeouts-retries-and-backoff-with-jitter/ | exponential backoff for the retry wrapper |
| https://nodejs.org/api/errors.html#err_unsupported_dir_import | the plain ESM import failure documented by P3.11-09 |
