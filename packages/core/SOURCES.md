# Sources for `@legx/core`

| URL | Used for |
|---|---|
| DESIGN.md Appendix A (this repo) | the starting code, extracted by `scripts/extract-appendix.ts` |
| https://spec.commonmark.org/0.31.2/#fenced-code-blocks | the fence rule the extraction script follows |
| https://www.rfc-editor.org/rfc/rfc5869#appendix-A | HKDF test vectors (`scripts/rfc5869-to-json.ts`) |
| https://www.rfc-editor.org/rfc/rfc8410#section-4 | Ed25519 SubjectPublicKeyInfo prefix, used to give keys to Node crypto in the vector tests |
| https://github.com/C2SP/wycheproof | Ed25519, HKDF and ECDSA vectors |
| https://github.com/novifinancial/ed25519-speccheck and https://eprint.iacr.org/2020/1244 | Ed25519 edge cases (cases.json and the condition table) |
| https://github.com/paulmillr/noble-curves | `zip215.json`; the `zip215` option of `ed25519.verify` |
| https://zips.z.cash/zip-0215 | the lenient rule that `zip215: false` turns off |
| https://github.com/rfcs/crypto-conditions | valid vectors 0000 to 0017 |
| https://datatracker.ietf.org/doc/html/draft-thomas-crypto-conditions-04 | condition and fulfillment encoding |
| https://github.com/transparency-dev/merkle/tree/main/testdata | Merkle inclusion and consistency vectors |
| https://www.rfc-editor.org/rfc/rfc9162#section-2.1 | the Merkle tree and inclusion proof algorithm |
| https://github.com/cyberphone/json-canonicalization | RFC 8785 test data |
| https://nodejs.org/api/modules.html#loading-ecmascript-modules-using-require | `require(esm)` and `ERR_REQUIRE_CYCLE_MODULE` |
| https://github.com/XRPLF/rippled/blob/develop/src/libxrpl/protocol/PublicKey.cpp | 1.4: XRPL key types (33 bytes, `ED`/`02`/`03`), SHA-512Half for secp256k1, fully canonical (low-S) DER, Ed25519 S < L |
| https://github.com/XRPLF/rippled/blob/develop/src/libxrpl/protocol/STTx.cpp | 1.4: multi-signing message and sorted `Signers` |
| https://www.rfc-editor.org/rfc/rfc8032#section-5.1.7 | 1.4: strict Ed25519 verification |
| https://xrpl.org/docs/concepts/accounts/multi-signing | 1.4: `verifyMultisigned` |
| https://xrpl.org/docs/references/protocol/transactions/types/nftokenmint | 1.5: URI up to 256 bytes, hex in JSON |
| https://xrpl.org/docs/references/protocol/transactions/common-fields | 1.5: `Memos` at most 1 KB serialized; `MemoType` characters |
| https://xrpl.org/docs/references/protocol/transactions/types/accountset | 1.6: `Domain` up to 256 bytes |
| https://xrpl.org/docs/concepts/accounts/cryptographic-keys | 1.7: master key (unless disabled) or regular key may sign |
| https://xrpl.org/docs/references/protocol/ledger-data/ledger-entry-types/accountroot | 1.7: `lsfDisableMaster` = 0x00100000, `RegularKey` |
| tools/py-ref/vectors/*.json (this repo, task 5.3a) | 1.5 to 1.7: independent reference vectors, loaded by the tests |
| DESIGN.md 6.2, 6.16, 6.17 (this repo) | 1.10: LC recipe, BarVerification and BarDealLink checks, 30-day age rule |
| https://www.iso.org/iso-3166-country-codes.html and https://www.iso.org/obp/ui/#iso:code:3166:US-CA | 1.10: ISO 3166-1 alpha-2 and 3166-2 subdivision code format (no `:`) |
| https://github.com/secure-systems-lab/dsse/blob/master/protocol.md | 1.10: envelopes are verified by the injected hybrid verifier |
| tools/py-ref/vectors/identity.json (`bar`) | 1.10: independent LC vector |
| https://www.rfc-editor.org/rfc/rfc9162#section-2.1.4 | 1.13: consistency proof generation and verification (`merkle.ts`) |
| https://github.com/transparency-dev/merkle/tree/c39fbf350a405f68571bf4c42a6a518eb0a46a4b/testdata | 1.13: consistency vectors (98 files); size 0 is refused, as in its `size1-is-zero` vectors |
| https://c2sp.org/tlog-checkpoint, https://c2sp.org/signed-note | 1.13: checkpoint note layout (origin, size, root, blank line, signature lines); signing is `pqCheckpoint.ts` (1.16) |
| https://github.com/C2SP/C2SP/blob/main/tlog-proof.md | 1.13: offline receipt shape (leaf, index, inclusion path, checkpoint) |
| https://github.com/secure-systems-lab/dsse/blob/master/protocol.md | 1.13: PAE, cross-checked with `@sigstore/core` `dsse.preAuthEncoding` (devDependency 3.2.0) |
| https://github.com/XRPLF/rippled/blob/ef5064eeb9e0ce467fae4694d58609de84109131/include/xrpl/protocol/detail/ledger_entries.macro | 1.11: the 29 ledger entry types on `develop` (2026-10-20) and the owner field of each; snapshot in `build/tmp/1.11/` |
| https://github.com/XRPLF/rippled/pull/8255 | 1.11: "Remove XChainBridge feature": `Bridge`, `XChainOwnedClaimID`, `XChainOwnedCreateAccountClaimID` left the macro; still covered by the table |
| https://xrpl.org/docs/references/protocol/ledger-data/ledger-entry-types/accountroot | 1.11: `lsf*` flags and AccountRoot fields of the lock checker |
| https://xrpl.org/docs/references/protocol/ledger-data/ledger-entry-types/oracle | 1.11: DQ-11, an Oracle names its owner in `Owner` |
| ripple-binary-codec 2.11.0 `dist/enums/definitions.json` (`LEDGER_ENTRY_TYPES`) | 1.11: second source for the ledger entry type list |
| DESIGN.md 6.6, 6.9; IMPLEMENTATION Appendix B (this repo) | 1.11: seal rules, allow-list, DQ-1, 2, 4, 5, 11, 12, 13 |
| https://www.rfc-editor.org/rfc/rfc9591 (sections 4.2, 5.1 to 5.4, 7.3, 7.7; Appendix E.1) | 1.15: FROST(Ed25519, SHA-512) signing rules, nonce rules, identifiable abort, vectors (`tools/frost-ref/vectors/rfc9591.txt`) |
| https://github.com/paulmillr/noble-curves/blob/2.4.0/src/abstract/frost.ts | 1.15: the wrapped `ed25519_FROST` API (DKG round1/2/3, commit, signShare, verifyShare, aggregate); read in `node_modules` |
| https://github.com/ZcashFoundation/frost/tree/frost-ed25519/v3.0.0 (`frost-core/src/keys/{dkg,refresh,repairable}.rs`, tests) | 1.15: PoK challenge, refresh (zero constant term, threshold fixed, caller authenticates), repairable; vector files in `tools/frost-ref/` |
| https://frost.zfnd.org/tutorial/dkg.html, https://frost.zfnd.org/tutorial/refreshing-shares.html | 1.15: DKG needs a broadcast channel and authenticated, confidential round 2; old shares deleted only after every holder refreshed |
| https://eprint.iacr.org/2020/852 | 1.15: FROST paper (Komlo, Goldberg), Pedersen DKG with Schnorr proofs of knowledge |
| https://doi.org/10.1109/SFCS.1987.4 | 1.15: Feldman VSS, the sub-share check in DKG and refresh |
| https://doi.org/10.1007/s00145-006-0347-3 | 1.15: GJKR DKG complaint phase (our complaints reveal the per-session KEM key so anyone can judge) |
| https://doi.org/10.1007/3-540-44750-4_27 | 1.15: proactive secret sharing (Herzberg et al.), the zero-sum refresh |
| https://eprint.iacr.org/2017/1155 | 1.15: Laing and Stinson repairable threshold schemes (ZF `repairable`) |
| https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion | 1.15: `approvalCheck` (type, challenge, rpIdHash, UP and UV flags, ES256 signature) |
| https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/ | 1.15: X-Wing HPKE for DKG round 2 and refresh sub-shares (tests use `@hpke/hybridkem-x-wing` 0.7.0) |
| https://xrpl.org/docs/references/protocol/transactions/types/payment#payment-flags | 1.15: allow-list refuses tfPartialPayment and every flag except tfFullyCanonicalSig |
| https://csrc.nist.gov/pubs/fips/204/final (Algorithms 2, 3, 7; section 5.2; table 2) | 1.16: ML-DSA contexts, mu for EXTERNAL_MU (`muFor`), key and signature sizes |
| https://csrc.nist.gov/pubs/fips/203/final | 1.16: ML-KEM-768 (inside X-Wing), ACVP vectors |
| https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files | 1.16: FIPS 203 and 204 ACVP vectors (`vectors/pq/acvp/`, `scripts/pq-vectors.ts`) |
| https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html, https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html | 1.16: KMS `ML_DSA_SHAKE_256`, RAW up to 4 KB, `EXTERNAL_MU` |
| https://nodejs.org/api/crypto.html (`crypto.sign`/`verify` `context` option, `raw-public` and `raw-seed` formats) | 1.16: P1.16-04 noble against Node's built-in ML-DSA |
| https://github.com/paulmillr/noble-post-quantum (0.7.1) | 1.16: `ml_dsa44`, `ml_dsa65` (`internal.sign` with `externalMu`), `ml_kem768`, `ml_kem768_x25519`; read in `node_modules` |
| https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/ (draft-11, section 5.6, Appendix C), https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem/blob/984c2f7a93b8f8d8f8073ebb53f9f4ce50b5babd/spec/test-vectors.json | 1.16: X-Wing HPKE packages (`sealPackage`/`openPackage`), KEM ID 0x647a, vectors |
| https://www.rfc-editor.org/rfc/rfc9180.html | 1.16: HPKE single-shot Seal/Open (`@hpke/core` 1.9.0 with `@hpke/hybridkem-x-wing` 0.7.0) |
| https://github.com/secure-systems-lab/dsse/blob/master/protocol.md | 1.16: hybrid envelope = two DSSE signatures over one PAE |
| https://c2sp.org/signed-note@v1.1.0, https://c2sp.org/tlog-checkpoint@v1.1.0, https://c2sp.org/tlog-cosignature@v1.1.0 | 1.16: note framing, key IDs, vkeys, the 0x01 line and the 0x06 `CosignedSubtree` line |
| https://github.com/FiloSottile/torchwood/blob/main/cosignature.go, https://github.com/transparency-dev/formats/blob/main/note/note_cosigv1.go, https://github.com/cloudflare/azul/blob/main/crates/tlog_cosignature/src/subtree_v1.rs | 1.16: the 0x06 signature uses the EMPTY ML-DSA context in all three (Go `crypto/mldsa`, `filippo.io/mldsa`, RustCrypto `ml-dsa`) |
| https://github.com/hupe1980/doubleentry/tree/2d76ec5641d0adf7bdd1b144319d855a1dc5cd9d/tests/vectors/c2sp | 1.16: a Go-made hybrid checkpoint (0x01 + 0x06) our verifier must accept |
| https://www.npmjs.com/package/@cloudflare/signed-note-wasm (0.3.0) | 1.16: second implementation that verifies our 0x01 and 0x06 lines (P1.16-06, P1.16-13) |
| https://www.rfc-editor.org/rfc/rfc4648#section-3.5 | 1.16: canonical base64 only (`fromBase64Strict`) |
| https://www.rfc-editor.org/rfc/rfc4998#section-5 | 1.16: renewal statement chain (`renewalStatement`, `verifyRenewalChain`) |
| https://github.com/XRPLF/XRPL-Standards/discussions/295 | 1.16: the ledger has no post-quantum keys yet: the binding proves consent, it does not protect the money |
| https://www.icao.int/sites/default/files/publications/DocSeries/9303_p11_cons_en.pdf | 1.9: passive authentication steps (5.1.1), Active Authentication (6.1: 8-byte RND.IFD, RSA ISO/IEC 9796-2 scheme 1 with trailers BC/38CC/34CC/36CC/35CC, ECDSA plain format), DG14 ActiveAuthenticationInfo (9.2.4), the Appendix F worked example used as a test vector |
| https://www.icao.int/sites/default/files/publications/DocSeries/9303_p10_cons_en.pdf | 1.9: EF.SOD (tag 77, SignedData profile Table 37), LDSSecurityObject (4.6.2.3), DG1 (61/5F1F), DG14 (6E), DG15 (6F) |
| https://www.icao.int/sites/default/files/publications/DocSeries/9303_p12_cons_en.pdf | 1.9: CSCA and DS certificate profiles (key usage, basicConstraints, validity) for the chain check |
| https://www.icao.int/sites/default/files/publications/DocSeries/9303_p4_cons_en.pdf and https://www.icao.int/sites/default/files/publications/DocSeries/9303_p3_cons_en.pdf | 1.9: TD3 MRZ field positions and check digits (7-3-1 weights) |
| https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03105/BSI_TR-03105-5_ReferenceDataSet_zip.zip | 1.9: BSI TR-03105-5 reference data set: the 1024-bit RSA Active Authentication key (`DG15_sk.pkcs8`), DG15, DG1, DG14 and a real-world EF.SOD (RSA-PSS DS) in `test/passport/data/bsi-tr03105-5/` |
| https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_V-2-1_pdf.pdf?__blob=publicationFile | 1.9: ecdsa-plain-SHA* OIDs and the plain r‖s format for EC Active Authentication; explicit EC domain parameters |
| https://www.iso.org/standard/54788.html | 1.9: ISO/IEC 9796-2:2010 digital signature scheme 1 (the standard itself is not public; the ICAO text and BouncyCastle are the readable references) |
| https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/crypto/signers/ISO9796d2Signer.java | 1.9: ISO/IEC 9796-2 verification: header bits, padding nibbles B/A, the n − J recovery step |
| https://github.com/PeculiarVentures/PKI.js/blob/v3.4.3/src/SignedData.ts and .../src/CryptoEngine/CryptoEngine.ts and .../src/SignedAndUnsignedAttributes.ts | 1.9: SOD parsing, `verifyWithPublicKey` (RSA, RSA-PSS, ECDSA DER conversion), the signed attributes re-tagged as SET (0x31) |
| https://www.rfc-editor.org/rfc/rfc5652#section-5.4 | 1.9: the signature over signed attributes covers their DER SET OF encoding; messageDigest and contentType attributes |
| https://www.rfc-editor.org/rfc/rfc5280#section-6.1.3 | 1.9: certificate path processing (name chaining, validity, keyCertSign, signature algorithm match 4.1.1.2) |
| https://www.rfc-editor.org/rfc/rfc3279#section-2.3.5 and https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1.1 and https://www.rfc-editor.org/rfc/rfc5639 | 1.9: EC named curve OIDs (NIST, brainpool) and explicit ECParameters matched to a named curve |
| https://blog.protocolbench.org/2014/04/update-tr-03105-part-3-2-available/ | 1.9: decide which data groups a chip has from EF.SOD (signed), not EF.COM |
| DESIGN.md 6.2, 6.10, 6.15 (this repo) | 1.17: `C_side` recipe, bound values, trust record, production refusals, identity changes, disputes |
| tools/py-ref/vectors/identity.json and presence.json (this repo, task 5.3a) | 1.17: `zkIdentityCommitment` and `presenceMsg` cross-checks |
| https://github.com/zkpassport/zkpassport-packages/tree/a61b0cf461f1fab10e1b838dacd81e862107acb0/packages/zkpassport-sdk | 1.17: the SDK's error keys (`date`, `facematch`) that `checkZkResult` classifies; `formatBoundData` 509-byte cap (506 for `custom_data`) |
| https://www.rfc-editor.org/rfc/rfc9180.html | 1.17: salt and disclosure boxes (single-shot Seal/Open through the task 1.16 X-Wing suite) |
| packages/zk/fixtures/ (this repo, task 1.17) | 1.17: recorded mock-passport results the core tests replay |
| DESIGN.md 6.17, D22, D23, 6.15, 6.16, 6.14, 6.13, 6.10, 6.4 (this repo); build/DECISIONS.md OD-2, OD-21 | 1.12: the 15 gate codes, the `release.gate.passed` record, signer binding to the sealed pqKeyHash |
| https://xrpl.org/docs/references/protocol/data-types/nftoken | 1.12: NFTokenID layout (flags, transfer fee, 20-byte issuer, scrambled taxon, sequence); issuer decoded locally with xrpl.js 5.3.0 `parseNFTokenID` |
| https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/transaction-methods/tx | 1.12: `validated`, `hash`, `tx_blob` (binary mode); the gate rehashes the blob (`hashes.hashSignedTx`, prefix TXN) so the memo and URI come from the transaction named by the stored hash |
| https://xrpl.org/docs/references/protocol/ledger-data/ledger-entry-types/credential | 1.12: ATTORNEY_CREDENTIAL_*: `lsfAccepted` 0x00010000, `Issuer`, `Expiration` against the validated close_time |
| https://xrpl.org/docs/references/protocol/transactions/common-fields | 1.12: the EscrowFinish memo (`gateMemo`), Memos at most 1 KB |
| tools/py-ref/vectors/gate_memo.json (this repo, task 5.3a) | 1.12: `gateMemo` cross-check |

- https://github.com/paulmillr/scure-base : base64 and base64url for @legx/core (no Buffer, OD-27, I-17).
- https://vitest.dev/guide/browser/playwright : the core-browser smoke project.

## Fix fleet F2 (Wave H)
- https://www.npmjs.com/package/@zkpassport/utils/v/0.40.0-beta.2 — `getScopeHash`/`getServiceScopeHash` (SHA-256, first 31 bytes) and `getService(Sub)ScopeFromDisclosureProof` (public inputs 2 and 3); used by `attest.ts` `checkProofBinding` (I-S-G3). Checked on the recorded sets in `packages/zk/fixtures/sets` (build/tmp/F2/scope.mjs).
- https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/ and https://www.rfc-editor.org/rfc/rfc9794 — both components of a hybrid signature bound to one identity; `hybridEnvelope.ts` `pair` (I-S-P1).
- https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf (6.1 AA, 6.2 CA) — `chip_auth_available` (OD-22, I-S-G5).
- https://www.unicode.org/reports/tr15/ (NFC) and https://www.rfc-editor.org/rfc/rfc3629 (UTF-8 has no surrogates) — `contract.ts` `clauseBytes` (I-E1).
