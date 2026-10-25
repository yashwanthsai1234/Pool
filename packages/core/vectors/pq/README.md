# Post-quantum test vectors (task 1.16)

Downloaded on 24 Oct 2026 by `scripts/pq-vectors.ts` from the pinned commits below (run it again to reproduce the
subsets). Do not edit the files or run a formatter on them. Total size: about 1.3 MB.

| File | Source (pinned commit) | What is kept | Licence | Used by |
|---|---|---|---|---|
| `acvp/ml-dsa-keygen.json` | https://github.com/usnistgov/ACVP-Server `gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json` at `975de31eb83d87039ec88934fdc47d8c312b892d` | ML-DSA-44 (5 cases), ML-DSA-65 (10 cases) | NIST work, not subject to copyright in the US (`LICENSES/nist-acvp.txt`) | `test/pq.test.ts` (T-U-27a) |
| `acvp/ml-dsa-sigver.json` | same commit, `ML-DSA-sigVer-FIPS204` | groups 1 (ML-DSA-44 external pure), 3 (ML-DSA-65 external pure, with contexts), 9 (ML-DSA-65 internal, external mu); `sk` dropped | same | `test/pq.test.ts` |
| `acvp/ml-dsa-siggen.json` | same commit, `ML-DSA-sigGen-FIPS204` | groups 3 (ML-DSA-65 deterministic, external pure) and 9 (deterministic, external mu), 5 cases each | same | `test/pq.test.ts` |
| `acvp/ml-kem-keygen.json` | same commit, `ML-KEM-keyGen-FIPS203` | ML-KEM-768, 10 cases | same | `test/pq.test.ts` |
| `acvp/ml-kem-encapdecap.json` | same commit, `ML-KEM-encapDecap-FIPS203` | ML-KEM-768 encapsulation and decapsulation, 10 cases each | same | `test/pq.test.ts` |
| `xwing-draft-11.json` | https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem `spec/test-vectors.json` at `984c2f7a93b8f8d8f8073ebb53f9f4ce50b5babd` (the same 3 vectors as Appendix C of draft-connolly-cfrg-xwing-kem-11) | all | IETF Contribution (BCP 78, IETF Trust Legal Provisions; code components under the Simplified BSD licence) | `test/pqHpke.test.ts` (P1.16-08) |
| `c2sp/ml-dsa.txt`, `c2sp/ml-dsa-counted-by-go.txt`, `c2sp/signed-note-example.txt` | https://github.com/hupe1980/doubleentry `tests/vectors/c2sp/` at `2d76ec5641d0adf7bdd1b144319d855a1dc5cd9d`. Made from fixed seeds by the Go reference code (`transparency-dev/formats` with `filippo.io/mldsa`, `golang.org/x/mod/sumdb/note`) | a tlog policy with an Ed25519 log key and an ML-DSA-44 cosigner key, a checkpoint signed by both, and the signed-note document example key | Apache-2.0 (`LICENSES/doubleentry.txt`) | `test/pqCheckpoint.test.ts` (P1.16-05) |
| `legx-checkpoint-golden.txt` | ours: `signCheckpoint` with the fixed keys and close_time of `test/pqCheckpoint.test.ts` | our golden hybrid checkpoint (0x01 and 0x06 lines) | this repository | `test/pqCheckpoint.test.ts` (P1.16-13) |

The ACVP `internalProjection.json` files hold the prompts and the expected results together. Hex in the ACVP files is
uppercase; the tests compare in lowercase.
