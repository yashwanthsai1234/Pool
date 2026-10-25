# Sources
- https://github.com/XRPLF/xrpl-py (xrpl-py 5.2.0 binary codec: encode, encode_for_signing, encode_for_multisigning)
- https://xrpl.org/docs/references/protocol/binary-format (the canonical encoding both libraries implement)
- https://csrc.nist.gov/pubs/fips/204/final (ML-DSA, context and mu)
- https://nodejs.org/api/crypto.html (ML-DSA keys and `context` in Node 24)
- https://www.rfc-editor.org/rfc/rfc9591 and the ZF frost-ed25519 3.0.0 vectors in tools/frost-ref/vectors
- https://github.com/bryc/code/blob/master/jshash/PRNGs.md#mulberry32 (seeded PRNG)
