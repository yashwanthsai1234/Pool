# Sources for @legx/fixtures

| URL | Used for |
|---|---|
| https://www.icao.int/sites/default/files/publications/DocSeries/9303_p3_cons_en.pdf | MRZ check digits (weights 7, 3, 1; `<` = 0) |
| https://www.icao.int/sites/default/files/publications/DocSeries/9303_p4_cons_en.pdf | TD3 MRZ layout, the specimen MRZ in `test/mrz.test.ts` |
| https://www.icao.int/sites/default/files/publications/DocSeries/9303_p10_cons_en.pdf | DG1 tags `61`/`5F1F`, DG14 `6E`, DG15 `6F`, EF.SOD `77`; LDSSecurityObject ASN.1 (4.6.2.3, SIZE 2..16, v1 with LDSVersionInfo); SignedData profile (Table 37); NULL parameters rule (4.6.2.3 Note 2) |
| https://www.icao.int/sites/default/files/publications/DocSeries/9303_p11_cons_en.pdf | Active Authentication (6.1: 8-byte RND.IFD, ISO/IEC 9796-2 scheme 1 for RSA with trailers BC / 34CC, plain ECDSA), DG14 SecurityInfos and ActiveAuthenticationInfo (9.2, 9.2.4), passive authentication (5.1) |
| https://www.icao.int/sites/default/files/publications/DocSeries/9303_p12_cons_en.pdf | CSCA and Document Signer certificate profile (Table 1 validity, Table 5 fields, Table 6 extensions, 7.1.1.2 alt names, 7.1.1.6 documentTypeList) |
| https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_V-2-1_pdf.pdf?__blob=publicationFile | Plain ECDSA signature format and the ecdsa-plain-SHA256 OID 0.4.0.127.0.7.1.1.4.1.3 |
| https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/internal/asn1/bsi/BSIObjectIdentifiers.html | Cross-check of the ecdsa-plain OIDs |
| https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/crypto/signers/ISO9796d2Signer.java | ISO/IEC 9796-2 scheme 1 representative layout (header 6A, M1, hash, trailer) |
| https://www.rfc-editor.org/rfc/rfc5869 | HKDF, the seed stream |
| https://www.rfc-editor.org/rfc/rfc5652#section-5.4 | CMS SignedData, signed attributes, the SET OF encoding that is signed |
| https://www.itu.int/rec/T-REC-X.690 | DER lengths and the SET OF sort order |
| https://www.rfc-editor.org/rfc/rfc5280 | Certificate structure, key identifiers (4.2.1.2), keyUsage bits |
| https://www.rfc-editor.org/rfc/rfc5480#section-2 | EC SubjectPublicKeyInfo with a named curve |
| https://www.rfc-editor.org/rfc/rfc5758#section-3.2 | ecdsa-with-SHA256 without parameters |
| https://www.rfc-editor.org/rfc/rfc4055#section-3.1 | id-RSASSA-PSS parameters |
| https://www.rfc-editor.org/rfc/rfc8017 | RSASSA-PSS encoding (9.1.1), the RSA private operation with CRT (5.2.1) |
| https://www.rfc-editor.org/rfc/rfc6979 | Deterministic ECDSA nonces (why noble signs, not WebCrypto) |
| https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf | EC secret key from extra random bits (A.2.1), Miller-Rabin (B.3) |
| https://github.com/li0ard/tsemrtd | Reference LDSObject schema (`dist/asn1/sod.js`) and the P1.8-10 cross-check parser |
| https://github.com/cheminfo/mrz | Independent MRZ validator in tests |
| https://github.com/PeculiarVentures/PKI.js | Independent SignedData and certificate verification in tests (pinned 3.4.3) |
| https://github.com/PeculiarVentures/asn1-schema | ASN.1 classes used to build certificates and SignedData |
| https://docs.openssl.org/3.6/man1/openssl-cms/ | `openssl cms -verify`, the differential check P1.8-04 |
| https://github.com/paulmillr/noble-curves | P-256 and brainpoolP256r1 signing (`@noble/curves/misc.js`), `lowS` behavior |
