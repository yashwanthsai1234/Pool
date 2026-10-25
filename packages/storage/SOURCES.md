# Sources (task 3.6, storage)

- S3 Object Lock (compliance and governance modes, retention, versioned delete): https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
- S3 conditional writes (`If-None-Match: *`): https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html
- S3 PutObject (ChecksumSHA256, ObjectLockMode, ObjectLockRetainUntilDate): https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html
- MinIO object retention: https://min.io/docs/minio/linux/administration/object-management/object-retention.html
- Container image used for tests: `pgsty/minio@sha256:b6bfe7239bfc83fb90d31612d9704d86039dd714f7904b3f1ad68f211e602372` (RELEASE.2026-08-04), a community build of MinIO; `minio/minio` and `quay.io/minio/minio` could not be pulled on 24 Oct 2026.
- `link(2)` (EEXIST makes create-if-absent atomic): https://man7.org/linux/man-pages/man2/link.2.html
- RFC 9162 section 2.1 (Merkle tree hash, audit path, consistency proof, and their verifiers): https://www.rfc-editor.org/rfc/rfc9162#section-2.1
- RFC 6962 test vectors (from the CT reference tests): https://github.com/google/certificate-transparency/blob/master/python/ct/crypto/merkle_test.py
- C2SP tlog-tiles (paths, tile height 8, partial tiles): https://c2sp.org/tlog-tiles
- C2SP tlog-checkpoint, tlog-cosignature, signed-note: https://c2sp.org/tlog-checkpoint , https://c2sp.org/tlog-cosignature@v1.1.0 , https://c2sp.org/signed-note
- Tessera POSIX conformance binary (`POST /add`, body is the entry, response is the decimal index): https://github.com/transparency-dev/tessera/blob/main/cmd/conformance/posix/main.go
