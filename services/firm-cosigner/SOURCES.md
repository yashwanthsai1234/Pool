# Sources (task 3.10: firm HSM co-signer)

| URL | Used for |
|---|---|
| https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion | user-verified approval over the message hash (challenge, UP/UV flags, signature counter) |
| https://simplewebauthn.dev/docs/packages/server | `verifyAuthenticationResponse` of @simplewebauthn/server 14.0.3 (checked against its `.d.ts`: `expectedChallenge`, `credential {id, publicKey (COSE), counter}`, `requireUserVerification` default true) |
| https://www.w3.org/TR/webauthn-3/#sctn-op-get-assertion | the fixture authenticator's assertion layout |
| https://www.rfc-editor.org/rfc/rfc9591#section-7.7 | a signer validates the message before it signs |
| https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6 | Ed25519 is deterministic: basis of the wrap-key derivation from `SignerPort` |
| https://www.rfc-editor.org/rfc/rfc5869 | HKDF for the wrap key |
| https://csrc.nist.gov/pubs/sp/800/38/d/final | AES-GCM share vault |
| https://www.postgresql.org/docs/current/plpgsql-trigger.html | append-only audit trigger |
| https://xrpl.org/docs/references/protocol/transactions/common-fields | Memos for the key-list anchor |
