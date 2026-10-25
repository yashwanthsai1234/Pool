# Sources (task 3.6, signer)

- AWS KMS `Sign` (MessageType RAW, DIGEST, EXTERNAL_MU; RAW limit 4096 bytes; EXTERNAL_MU is a 64-byte mu): https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html
- AWS KMS ML-DSA keys (`ML_DSA_65`, signing algorithm `ML_DSA_SHAKE_256`): https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html
- AWS KMS key spec reference (`ED25519_SHA_512` needs RAW, `ED25519_PH_SHA_512` needs DIGEST, not interchangeable): https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html
- ML-DSA with an external mu on KMS (GetPublicKey returns SPKI; Sign takes mu): https://nsmith.net/aws-kms-mldsa-external-mu
- AWS blog on ML-DSA in KMS: https://aws.amazon.com/blogs/security/how-to-create-post-quantum-signatures-using-aws-kms-and-ml-dsa/
- FIPS 204 (ML-DSA, context string, mu): https://csrc.nist.gov/pubs/fips/204/final
- RFC 8410 (Ed25519 SubjectPublicKeyInfo): https://www.rfc-editor.org/rfc/rfc8410#section-4
- RFC 9881 (ML-DSA in X.509, SPKI): https://www.rfc-editor.org/rfc/rfc9881
- Node.js `crypto.sign` with the `context` option: https://nodejs.org/docs/latest-v24.x/api/crypto.html
- C2SP tlog-checkpoint / tlog-cosignature (the 0x01 and 0x06 lines, empty ML-DSA context): https://c2sp.org/tlog-checkpoint , https://c2sp.org/tlog-cosignature@v1.1.0
- LocalStack KMS docs (no mention of ML_DSA or EXTERNAL_MU): https://docs.localstack.cloud/aws/services/kms/
- Floci KMS ML-DSA support (RAW only): https://github.com/floci-io/floci/pull/3047
