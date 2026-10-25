# Recorded ZKPassport mock-passport proofs (task 1.17)

Recorded on 24 Oct 2026 (21:28 local, `recordedAt` 2026-10-25T04:28Z) with `node packages/zk/tools/record.ts`.
Tests replay these files offline; they never need a phone, a passport or the network.

## Versions

- `@zkpassport/sdk` 0.19.2, `@zkpassport/utils` 0.40.0-beta.2 (the version the SDK pins), `@zkpassport/registry` 0.15.3.
- Circuit manifest 0.21.1 from ZKPassport's testnet CDN (`circuits2.zkpassport.id/testnet`).
- Registry: Sepolia (chain 11155111), root registry `0x1d0000020038d6e40e1d98e09fa1bb3a7daa8b70`, certificate root
  `0x136ca5db66602ac8a50b8d3a1de146bbb18445bbdccc50efe05f7c5e352fa248`. Each set pins its own block (`loaders.block`).
- Every set names the versions it was recorded with; `test/offline.test.ts` fails when the installed versions differ.

## How

For each set, `tools/record.ts`:
1. makes a ZKR mock passport with `createMockPassport` (all RSA-2048/SHA-256, so they share circuits);
2. builds the request with `src/request.ts` (domain `legx.app`, scope `legx/v1/<dealId>`, devMode);
3. proves it with the vendored headless prover `tools/zk-prove/prove.ts` (about 10 to 25 s per set);
4. verifies it with the SDK (`verifierMode: "local"`) through `src/verify.ts`, which pins every registry `eth_call`
   to one block and records the answers, the circuit manifest and the circuit files.

| Set | What it shows | Recorded verdict |
|---|---|---|
| `alice-onboarding` | onboarding request: age, four disclosed facts, expiry after CancelAfter + 30 days, bound contract root and slot key | verified |
| `alice-release` | release request, same passport, domain and scope: same identifier as onboarding | verified |
| `alice-release-facematch` | release request with the strict face match; no headless prover can make a face match proof | not verified (`facematch`) |
| `alice-deal2` | same passport and domain, second scope: another identifier | verified |
| `bob-release` | second passport, same scope: another identifier | verified |
| `alice-other-domain` | same passport and scope under the domain `other.app`: another identifier | verified |
| `expired` | passport expired 2020-01-01, proved with the clock at 2019-06-01: the expiry check is stale | not verified (`date`) |

## Files

- `sets/<name>.json`: the request record (stage, domain, scope, devMode, validity, original query), the proofs as the
  SDK returns them, the query result (mock passport data, Secret in production), the `ZkVerification` with its trust
  record, and the recorded loaders (registry answers, file hashes, block, verification day).
- `files/manifest-<version>.json`, `files/circuit-<vkey hash>.json`: the file bodies, shared by all sets.
- `SHA256SUMS`: the hash of every file. A test fails when a file changes without a new recording.

## Not covered

- The real (non-mock) identifier formula: T-U-28c needs one run with a real passport and the phone app (`it.todo`).
- A passing face match: it needs the ZKPassport app's attestation.
