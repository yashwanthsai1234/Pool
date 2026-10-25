# frost-ref: reference vectors for `@legx/core/frost` (task 1.15)

Vector files only. There is no Rust toolchain in this build (AGENT_RULES), so the planned Rust helper
(P1.15-13, a live ZF `frost-ed25519` 3.0.0 run in both directions) is not here. These committed files are the
"ZF Rust" A/B test: they are the outputs of the ZF Rust code and the RFC, and `packages/core/test/frost.vectors.test.ts`
runs them through our wrapper on every commit.

| File | Source (downloaded 24 Oct 2026) | SHA-256 | Licence | Used by |
|---|---|---|---|---|
| `vectors/rfc9591.txt` | https://www.rfc-editor.org/rfc/rfc9591.txt (Appendix E.1 is parsed from it) | `fd8366795c833348d552e6a4141e8bf413310940fd50af484283207716d1a6a7` | IETF Trust; code components under the Revised BSD licence | T-U-21a |
| `vectors/zf-vectors.json` | https://raw.githubusercontent.com/ZcashFoundation/frost/frost-ed25519/v3.0.0/frost-ed25519/tests/helpers/vectors.json | `758b15f8ca7f6e18dae2ce907ab727717e19a6476ae62fc3406b82a58470a128` | MIT or Apache-2.0 (ZF frost repo `LICENCE`) | T-U-21b |
| `vectors/zf-vectors-big-identifier.json` | https://raw.githubusercontent.com/ZcashFoundation/frost/frost-ed25519/v3.0.0/frost-ed25519/tests/helpers/vectors-big-identifier.json | `a7861e00487f42dc079e8f0d65a38699ae8a71e2de8e1fb74854b4cfe73aaa05` | MIT or Apache-2.0 | T-U-21b |
| `vectors/zf-vectors_dkg.json` | https://raw.githubusercontent.com/ZcashFoundation/frost/frost-ed25519/v3.0.0/frost-ed25519/tests/helpers/vectors_dkg.json | `ab1cb3c50d18e59eb15b099ac4faad5240b5cde5eeeb6305dbd9601b70a15c7c` | MIT or Apache-2.0 | T-U-21c |
| `vectors/zf-repair-share.json` | https://raw.githubusercontent.com/ZcashFoundation/frost/frost-ed25519/v3.0.0/frost-ed25519/tests/helpers/repair-share.json | `2f0c6fae5a29a48606865b68e76c90f75393a612111a192a4179704fba2d9b2b` | MIT or Apache-2.0 | T-U-30c |

Tag `frost-ed25519/v3.0.0` of https://github.com/ZcashFoundation/frost (tag object `2016e44ba4a4757a996300350063b937a2ad33e8`).

Field notes:
- `zf-vectors.json` holds the same keys and signature as RFC 9591 E.1 but different nonce randomness, so both run.
- In `zf-vectors_dkg.json`, `signing_key` is a participant's constant term a_i0 and `coefficient` is a_i1; `signing_shares[j]`
  is the share participant i *received* from j (see ZF `frost-core/src/tests/vectors_dkg.rs`). The proof-of-knowledge
  nonce is not in the file, so our test checks the vector's proofs and reproduces commitments, shares and outputs.
- `zf-repair-share.json` holds only sums (ZF `check_repair_share_part2/3`); part 1 is checked as a property.
- ZF has no refresh vectors; T-U-23c compares our refresh with a transliteration of ZF `refresh_dkg_shares`.
