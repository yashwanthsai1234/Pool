# Vendored test vectors

Files are copied byte for byte from the pinned commit named below. Do not edit them or run a formatter on them
(the root `biome.json` and `packages/core/biome.json` exclude this folder). Total size: about 2.4 MB.
Vendored on 24 Oct 2026 by task 1.3. The tests that use them are `test/vectors.test.ts` (T-U-12) and `test/pending.test.ts`.

| Folder or file | Source (pinned commit) | Licence | Used by |
|---|---|---|---|
| `wycheproof/ed25519_test.json`, `wycheproof/hkdf_sha256_test.json` | https://github.com/C2SP/wycheproof `testvectors_v1/` at `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9` | Apache-2.0 (`LICENSES/wycheproof.txt`) | `test/vectors.test.ts` |
| `wycheproof/ecdsa_secp256r1_sha256_test.json` (DER), `wycheproof/ecdsa_secp256r1_sha256_p1363_test.json` (plain `r\|\|s`), `wycheproof/ecdsa_brainpoolP256r1_sha256_test.json` (DER), `wycheproof/ecdsa_brainpoolP256r1_sha256_p1363_test.json` (plain `r\|\|s`) | same commit and folder | Apache-2.0 | file only until task 1.9 (passport attestation) |
| `ed25519/speccheck-cases.json` | https://github.com/novifinancial/ed25519-speccheck `cases.json` at `65519336fda78a3d016e947df6d82848aca0c9da` | Apache-2.0 (`LICENSES/ed25519-speccheck.txt`) | `test/vectors.test.ts` |
| `ed25519/noble-zip215.json` | https://github.com/paulmillr/noble-curves `test/vectors/ed25519/zip215.json` at `e7316eb26d4d052bd6786cd954c1ed33b8484ec0`. Origin: https://gist.github.com/hdevalence/93ed42d17ecab8e42138b213812c8cc7 | MIT (`LICENSES/noble-curves.txt`) | `test/vectors.test.ts` |
| `hkdf/rfc5869-appendix-a.json` | RFC 5869 Appendix A, https://www.rfc-editor.org/rfc/rfc5869#appendix-A, converted to JSON by `scripts/rfc5869-to-json.ts` (the RFC text is not copied) | IETF Trust, RFC text; the test values are data | `test/vectors.test.ts` |
| `crypto-conditions/0000_*.json` to `0017_*.json` | https://github.com/rfcs/crypto-conditions `test-vectors/valid/` at `e3b4209040b97934e3ee10e8ffa102fb06c28753` (draft-thomas-crypto-conditions-04) | Apache-2.0 per the `license` field of the repository `package.json`; the repository has no LICENSE file | `test/vectors.test.ts` |
| `merkle/inclusion/**`, `merkle/consistency/**` (196 files) | https://github.com/transparency-dev/merkle `testdata/` at `c39fbf350a405f68571bf4c42a6a518eb0a46a4b` (the `subtreeinclusion` and `subtreeconsistency` folders are not vendored) | Apache-2.0 (`LICENSES/transparency-dev-merkle.txt`) | inclusion: `test/vectors.test.ts`; consistency: file only until task 1.13 |
| `jcs/input`, `jcs/output`, `jcs/outhex` | https://github.com/cyberphone/json-canonicalization `testdata/` at `32a48195b9b20fe67b1795e39e4509f14d860b45` | Apache-2.0, per the licence header in `LICENSES/cyberphone-json-canonicalization.txt` (GitHub does not detect it) | file only until task 3.4 |

Not vendored here: RFC 8032 section 7.1 (covered by Wycheproof and speccheck), FROST vectors (task 1.15), post-quantum
vectors (task 1.16), the RSA-PSS Wycheproof files (not needed yet).

## Merkle inclusion vectors: what runs

The vectors give a leaf hash, and `verifyInclusion` takes leaf data. So only vectors whose leaf hash is the hash of
one of the eight RFC 6962 reference leaves can run (62 of 98). The "single-entry" vectors, `wrong-leaf`, `random-leaf` and
the empty-leaf cases use a hash we cannot invert and stay unrun.
