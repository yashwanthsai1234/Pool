# Sources for @legx/verifier

| URL | Used for |
|---|---|
| https://xrpl.org/docs/references/protocol/transactions/types/credentialcreate | 0a fields, 64-byte type, 256-byte URI, Expiration |
| https://xrpl.org/docs/references/protocol/transactions/types/credentialaccept | 0b |
| https://xrpl.org/docs/references/protocol/transactions/types/credentialdelete | re-verification and revoke (issuer deletes) |
| https://xrpl.org/docs/references/protocol/ledger-data/ledger-entry-types/credential | `lsfAccepted` 0x00010000, URI, Expiration, PreviousTxnID |
| https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_objects | reading the credential (through `LedgerPort.snapshot`) |
| https://xrpl.org/docs/references/protocol/transactions/metadata | ModifiedNode.PreviousTxnID gives the create hash |
| https://github.com/XRPLF/rippled/blob/develop/src/libxrpl/tx/transactors/credentials/CredentialCreate.cpp | `tecNO_TARGET` for a missing subject (P3.3-04) |
| https://github.com/timgit/pg-boss/tree/master/docs | pg-boss 12.38.0: `createQueue`, `send`, `work`, retry options, `stop` |
| https://developer.mozilla.org/en-US/docs/Web/API/AbortSignal/timeout_static | adapter time-outs |
| https://github.com/secure-systems-lab/dsse/blob/master/protocol.md | hybrid envelopes (through `@legx/core/hybridEnvelope`) |
