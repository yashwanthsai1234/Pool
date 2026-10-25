# Sources (task 3.9: recovery agent and the FROST relay in `services/coordinator/src/frost/`)

| URL | Used for |
|---|---|
| https://www.rfc-editor.org/rfc/rfc9591 | nonces used once (5.1, 5.2), signers validate the message (5.2, 7.7), identifiable abort (5.4) |
| https://frost.zfnd.org/tutorial/dkg.html | DKG needs a broadcast channel and authenticated, confidential round 2 |
| https://frost.zfnd.org/tutorial/refreshing-shares.html | delete old shares only after every refresher is confirmed working |
| https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/ | X-Wing HPKE for share transport |
| https://www.rfc-editor.org/rfc/rfc9180 | HPKE base mode, associated data |
| https://csrc.nist.gov/pubs/sp/800/38/d/final | AES-GCM: unique 96-bit IV per key, AAD (share vault) |
| https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion | user-verified approvals (T-U-31a) |
| https://fastify.dev/docs/latest/Reference/ContentTypeParser/ | raw-body JSON parser for signed requests |
| https://kysely.dev/docs/recipes/raw-sql | relay queue and agent tables |
| https://www.postgresql.org/docs/current/sql-grant.html | the agent's own database role |
| https://xrpl.org/docs/references/protocol/binary-format | multisign message layout decoded by the allow-list |
| https://xrpl.org/docs/references/protocol/transactions/common-fields | Memos for the key-list anchor |
