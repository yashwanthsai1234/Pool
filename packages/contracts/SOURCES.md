# Sources for @legx/contracts

| URL | Used for |
|---|---|
| https://zod.dev/json-schema | `z.toJSONSchema` (draft 2020-12, `additionalProperties: false` for strict objects, metadata copied into output, refinements not exported) |
| https://zod.dev/api?id=branded-types | `.brand<...>()` value types and the `Secret<>` brand (type-only, no runtime cost) |
| https://zod.dev/api | `z.strictObject`, `z.discriminatedUnion`, `z.uuid({ version: 'v7' })`, `z.base64`, `z.iso.datetime` |
| https://github.com/standard-schema/standard-schema | Zod 4 schemas are Standard Schema v1, which `@orpc/contract` 1.16.0 accepts (`Schema = StandardSchemaV1`) |
| https://orpc.dev/docs/contract-first/define-contract | `oc.route().input().output()` contract-first route table |
| https://orpc.dev/docs/metadata | typed per-route metadata (`$meta`, `.meta`) that holds each route's auth rule |
| https://github.com/secure-systems-lab/dsse/blob/master/protocol.md | DSSE envelope shape (`payloadType`, `payload`, `signatures[{keyid, sig}]`) |
| https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md | in-toto Statement v1 (`_type`, `subject`, `predicateType`, `predicate`) |
| https://www.rfc-editor.org/rfc/rfc9591 | FROST(Ed25519, SHA-512) message parts: commitments (hiding, binding), signature shares |
| https://www.rfc-editor.org/rfc/rfc9562.html | UUIDv7 for deal and event ids |
| https://www.rfc-editor.org/rfc/rfc4648#section-4 | exact-length padded base64 |
| https://www.rfc-editor.org/rfc/rfc6455 | WebSocket application close codes 4000 to 4999 |
| https://www.rfc-editor.org/rfc/rfc3161.html | `TsaPort` time stamps |
| https://c2sp.org/tlog-checkpoint | `Checkpoint` signed note (0x01 Ed25519 and 0x06 ML-DSA-44 lines) |
| https://csrc.nist.gov/pubs/fips/204/final | ML-DSA-65 sizes: public key 1,952 B, signature 3,309 B |
| https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/ | X-Wing encapsulated key 1,120 B (ML-KEM-768 1,088 + X25519 32) in `SealedBox` |
| https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion | `WebAuthnApproval` fields (authenticator data, client data JSON, signature) |
| https://xrpl.org/docs/references/protocol/data-types/base58-encodings | XRPL base58 alphabet and the classic address checksum |
| https://xrpl.org/docs/concepts/accounts/addresses#address-encoding | classic address = version 0x00 + AccountID + double-SHA-256 checksum |
| https://xrpl.org/docs/concepts/accounts/cryptographic-keys | public key forms: `ED` + 32 bytes, `02`/`03` + 32 bytes |
| https://xrpl.org/docs/references/protocol/data-types/basic-data-types | drops (max 10^17), Ripple epoch time (UInt32) |
| https://xrpl.org/docs/references/protocol/data-types/nftoken | NFTokenID (32 bytes, uppercase hex) |
| https://xrpl.org/docs/concepts/transactions/reliable-transaction-submission | `SubmitResult` outcomes (validated, rejected, expired) |
| https://docs.zkpassport.id | ZKPassport verify result and request parameters; `NullifierType` names read from `@zkpassport/utils` typings |
| DESIGN.md 6.2 to 6.17, 8.1, 8.10, 9 | every record, event and field |
| IMPLEMENTATION.md 1.2, 3, 4.3, 4.9, 1.15 to 1.17, 2.2, 3.2 to 3.12 | ports, route needs, research facts |

## OD-37
- build/SHIP_RECEIPT.md 2, 3: `shipment.signed`, `receipt.signed`, `ReceiptCondition`, `Manifest`, `ManifestItem`, gate codes 16 and 17, deal states SHIPPED and RECEIVED.
