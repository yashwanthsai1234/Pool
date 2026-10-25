# Recorded demo proofs

Three ZKPassport proof sets (`alice-onboarding`, `alice-release`, `bob-release`) copied from `packages/zk/fixtures/`
(recorded 24 Oct 2026, SDK 0.19.2, Sepolia, mock passports). `files/` holds the circuit files they need to verify offline.

## Use (demo profile only)
- Fallback when the ZKPassport relay, circuit CDN, Sepolia RPC or the phone app is down.
- `node tools/zk-prove/cli.ts --person alice --recorded` prints the recorded release proof. Without `--recorded` the CLI
  makes a FRESH proof bound to `--presence-msg` and falls back to this one if the network fails (stderr says so).
- They are devMode mock-passport proofs and are NOT bound to the live deal's presenceMsg: show them as "proof replay",
  and verify through the demo-profile adapter (`devMode: true`). Say aloud that they are recordings.

## Production refuses them
`loadRecorded(name, 'production')` throws `RECORDED_PROOFS_DEMO_ONLY`, and the production verifier adapter refuses any
devMode proof with `ZK_REFUSED` / `DEVMODE_REFUSED`. Test: `pnpm vitest run --project unit tools/zk-prove`.
