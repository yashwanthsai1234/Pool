# Sources for `@legx/verifier-cli`

| URL | Used for |
|---|---|
| DESIGN.md 8.8, 6.10, 6.17 (this repo) | the thirteen bundle items, offline zero-knowledge re-verification, the release gate |
| https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT | ZIP end of central directory, central directory, local header, methods 0 and 8 |
| https://github.com/secure-systems-lab/dsse/blob/master/protocol.md | DSSE pre-authentication encoding (manifest envelope) |
| https://github.com/C2SP/C2SP/blob/main/tlog-proof.md | `.tlog-proof` file layout |
| https://www.rfc-editor.org/rfc/rfc9162#section-2.1 | inclusion and consistency proofs (through core) |
| https://www.rfc-editor.org/rfc/rfc3161 | time-stamp tokens (through `@legx/evidence/tsa`) |
| https://esbuild.github.io/api/ | the single-file bundle |
| https://www.rfc-editor.org/rfc/rfc3161#section-4 | the relying party trusts the TSA roots it chooses (`--tsa-roots`, default system roots), never the bundle's own (I-S-E3) |
| DESIGN 8.8 | a service key must be pinned (`--service-key`); `--insecure-unpinned` is for tests (I-S-E2) |
