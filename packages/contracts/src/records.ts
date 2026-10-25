// Signed records and their parts: DSSE envelopes, attestations (DESIGN 6.15, 6.16, 6.10), findings
// (6.9, 6.17), enrollment keys (6.3), post-quantum bindings (6.13) and the recorded ZK result (6.10).
import { z } from 'zod';
import { secret } from './secret.ts';
import {
  Base64,
  Base64Bytes,
  Drops,
  Ed25519PublicKeyHex,
  Ed25519SigB64,
  Ed25519SigHex,
  EthAddress,
  EthHash,
  Hex32,
  HexBytes,
  IdMethod,
  Jurisdiction,
  KeyId,
  LawyerRole,
  LawyerSlot,
  LedgerAnchor,
  MlDsa65PublicKey,
  MlDsa65Signature,
  RippleTime,
  SequenceNumber,
  Side,
  Slot,
  XrplAddress,
  XrplEd25519PublicKey,
  XrplKeySigHex,
  XrplPublicKey,
} from './values.ts';

// ---------- DSSE envelopes (DESIGN 8.1, 6.13) ----------
// Source: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md (v1.0.2)

export const EVENT_PAYLOAD_TYPE = 'application/vnd.legx.event+json;v=1';
export const ATTEST_PAYLOAD_TYPE = 'application/vnd.legx.attest+json;v=1';
export const PayloadType = z.enum([EVENT_PAYLOAD_TYPE, ATTEST_PAYLOAD_TYPE]);

/** Envelope bytes (never re-serialized, DESIGN 8.1) carried in JSON as base64, max 64 KiB. */
export const EnvelopeBytesB64 = Base64(65536);

/** Signature algorithms a record lists in its signed payload as `sig_algs` (DESIGN 8.1, 6.13). */
export const SigAlg = z.enum(['ed25519', 'ml-dsa-65']);
/** As read from a record. The verifier's own table decides what is required (DESIGN 6.13); this is only a second check. */
export const SigAlgs = z.array(SigAlg).min(1).max(4);

export const DsseSignature = z.strictObject({ keyid: KeyId, sig: Base64(8192) });

/** Any DSSE envelope as parsed from storage. Verifiers decide whether its signatures suffice. */
export const Envelope = z.strictObject({
  payloadType: PayloadType,
  payload: Base64(65536),
  signatures: z.array(DsseSignature).min(1).max(8),
});
export type Envelope = z.infer<typeof Envelope>;

/** The hybrid signatures list (DESIGN 6.13): Ed25519 first, ML-DSA-65 second, both over the same PAE. */
export const HybridSignatures = z.tuple([
  z.strictObject({ keyid: KeyId, sig: Ed25519SigB64 }),
  z.strictObject({ keyid: KeyId, sig: MlDsa65Signature }),
]);
/** A well-formed hybrid envelope, the only kind the evidence service stores (IMPLEMENTATION P3.4-14). */
export const HybridEnvelope = Envelope.extend({ signatures: HybridSignatures });

// ---------- Secrets that cross a boundary (never logged, never in a response or event) ----------

/** Bar number as given to the verifier (only its SHA-256 is ever stored, DESIGN 9 `lawyer`). */
export const BarNumber = secret(z.string().regex(/^[A-Za-z0-9-]{1,32}$/));
/** The 32-byte salt of a commitment: per-deal bar salt (6.2, 6.16), or zkSalt32 (6.2). */
export const Salt32 = secret(HexBytes(32));
/** The 32-byte release code (DESIGN 6.7). Lives only on lawyer B's console. */
export const ReleasePreimage = secret(HexBytes(32));
/** Identity facts disclosed at onboarding, only inside the X-Wing box to the client's own lawyer (DESIGN 6.10). */
export const DisclosedFacts = z.strictObject({
  firstname: secret(z.string().max(128)),
  lastname: secret(z.string().max(128)),
  birthdate: secret(z.iso.date()),
  nationality: secret(z.string().regex(/^[A-Z]{3}$/)),
});

/** A package sealed with HPKE X-Wing (DESIGN 6.13; IMPLEMENTATION P1.16-07 suite tag). */
export const SealedBox = z.strictObject({
  suite: z.literal('hpke-xwing-v1'),
  recipient_key_id: KeyId,
  enc: Base64Bytes(1120), // X-Wing encapsulated key: ML-KEM-768 ciphertext (1,088) + X25519 (32)
  ciphertext: Base64(65536),
});

// ---------- ZKPassport (DESIGN 6.10) ----------

/** SDK `NullifierType` names (`@zkpassport/utils` 0.40: NON_SALTED=0 .. NONE=4). Mock types are refused in production. */
export const ZkIdentifierType = z.enum(['NON_SALTED', 'SALTED', 'NON_SALTED_MOCK', 'SALTED_MOCK', 'NONE']);
/** The deal-scoped unique identifier N_side, a field element as a decimal string. */
export const ZkIdentifier = z.string().regex(/^[0-9]{1,78}$/);
export const ZK_DOMAIN = 'legx.app';
export const SEPOLIA_CHAIN_ID = 11155111;

/** The trust record in camelCase, as the ZkVerifierPort returns it (IMPLEMENTATION P1.2-08). */
export const ZkTrust = z.strictObject({
  chainId: z.int().min(1),
  blockNumber: z.int().min(0),
  blockHash: EthHash,
  registryAddress: EthAddress,
  root: EthHash,
  circuitManifestVersion: z.string().regex(/^[0-9]+\.[0-9]+\.[0-9]+$/),
  vkeyHashes: z.array(EthHash).min(1).max(16),
  devMode: z.boolean(),
});

/** One proof of a stored proof set, exactly as the SDK returns it (IMPLEMENTATION 4.9; recorded 24 Oct 2026). */
export const ZkProof = z.strictObject({
  name: z.string().regex(/^[a-z0-9_]{1,128}$/),
  proof: z
    .string()
    .regex(/^[0-9a-f]*$/)
    .max(131072),
  vkeyHash: EthHash,
  version: z.string().regex(/^[0-9]+\.[0-9]+\.[0-9]+$/),
  index: z.int().min(0).max(31),
  total: z.int().min(1).max(32),
  // Exactly as the SDK returns it; verify() needs it to re-verify a stored set (task 1.17). Secret: the disclose
  // proof's inputs hold the disclosed facts in clear, so it never goes into a stored or public record.
  committedInputs: secret(z.record(z.string().max(64), z.unknown())).optional(),
});

/**
 * The recorded result of one ZKPassport verification (IMPLEMENTATION P1.2-08). The SDK result has no scope or
 * domain, so the request records them. `committedInputs` keeps only the bound value, never disclosed facts,
 * and `queryResultErrors` keeps only messages (category -> check -> message), never received values.
 */
export const ZkVerification = z.strictObject({
  verified: z.boolean(),
  uniqueIdentifier: ZkIdentifier.nullable(),
  uniqueIdentifierType: ZkIdentifierType.nullable(),
  queryResultErrors: z.record(z.string().max(64), z.record(z.string().max(64), z.string().max(1024))),
  proofSha256: Hex32,
  vkeyHash: EthHash,
  version: z.string().regex(/^[0-9]+\.[0-9]+\.[0-9]+$/),
  committedInputs: z.strictObject({ custom_data: z.string().max(509) }),
  scope: z.string().max(128),
  domain: z.string().max(253),
  trust: ZkTrust,
});
export type ZkVerification = z.infer<typeof ZkVerification>;

/**
 * Input of ZkVerifierPort.verify: the stored proof set plus the original query (IMPLEMENTATION 1.17).
 * `queryResult` can hold disclosed facts at onboarding, so it is Secret.
 */
export const ZkVerifyRequest = z.strictObject({
  stage: z.enum(['onboarding', 'release']),
  domain: z.string().max(253), // must be "legx.app"; recorded so a wrong one fails with WRONG_DOMAIN
  scope: z.string().max(128), // "legx/v1/" + dealId
  devMode: z.boolean(),
  proofs: z.array(ZkProof).min(1).max(32),
  originalQuery: z.record(z.string().max(64), z.unknown()),
  queryResult: secret(z.record(z.string().max(64), z.unknown())),
});
export type ZkVerifyRequest = z.infer<typeof ZkVerifyRequest>;

/** The trust record in snake_case inside a signed attestation (DESIGN 6.15). */
export const ZkTrustRecord = z.strictObject({
  chain_id: z.int().min(1),
  block_number: z.int().min(0),
  block_hash: EthHash,
  registry_address: EthAddress,
  root: EthHash,
  circuit_manifest_version: z.string().regex(/^[0-9]+\.[0-9]+\.[0-9]+$/),
  vkey_hashes: z.array(EthHash).min(1).max(16),
  identifier_type: ZkIdentifierType,
  dev_mode: z.boolean(),
});

// ---------- Passport attestation at release (DESIGN 6.15) ----------

const ChipChecks = z.strictObject({
  sod_signature_valid: z.boolean(),
  ds_cert_chains_to_csca: z.boolean(),
  dg1_hash_in_sod: z.boolean(),
  document_not_expired: z.boolean(),
  commitment_opens: z.boolean(),
  chip_authentication: z.enum(['AA', 'CA', 'none']),
  chip_auth_available: z.boolean(), // DG14 or DG15 present; then `none` is refused (OD-22)
  face_match: z.boolean().optional(),
});

const ZkReleaseChecks = z.strictObject({
  proof_verified: z.boolean(),
  identifier_matches: z.boolean(),
  bound_value_is_presence_msg: z.boolean(),
  document_not_expired: z.boolean(),
  face_match_passed: z.boolean(),
  proof_sha256: Hex32,
  trust: ZkTrustRecord,
});

const PassportBase = {
  deal_id: z.uuid({ version: 'v7' }),
  contract_root: Hex32,
  deal_seal: Hex32,
  side: Side,
  commitment: Hex32, // C_side
  ledger_anchor: LedgerAnchor,
  presence_sig: Ed25519SigHex, // the client's slot key (FROST) over presenceMsg
  lawyer_nonce: HexBytes(32), // the single-use nonce inside presenceMsg
  checked_by_role: LawyerRole,
  sig_algs: SigAlgs,
};

/** PassportAttestation, a union on `method`, with one checks shape per method (DESIGN 6.15). */
export const PassportAttestation = z.discriminatedUnion('method', [
  z.strictObject({ ...PassportBase, method: z.literal('zkpassport'), checks: ZkReleaseChecks }),
  z.strictObject({ ...PassportBase, method: z.literal('nfc-chip'), checks: ChipChecks }),
]);
export type PassportAttestation = z.infer<typeof PassportAttestation>;

// ---------- Onboarding attestation, `identity.onboarded` (DESIGN 6.10, 6.17 ONBOARDING_OK, 8.1) ----------

const OnboardingBase = {
  deal_id: z.uuid({ version: 'v7' }),
  contract_root: Hex32,
  side: Side,
  slot_pub: XrplEd25519PublicKey, // the planned client slot key the onboarding proof binds
  commitment: Hex32, // C_side
  disclosure_box_sha256: Hex32, // SHA-256 of the X-Wing box with the disclosed facts, sealed to this lawyer only
  checked_by_role: LawyerRole,
  // OD-29: tupleHash("legx/id-distinct/v1", [utf8(dealId), X]), X = utf8(N_side) (zkpassport) or SHA-256(DG1)
  // (nfc-chip). IDS_DISTINCT needs distinct_tag_A != distinct_tag_B, required.
  distinct_tag: Hex32,
  sig_algs: SigAlgs,
};

export const IdentityOnboarded = z.discriminatedUnion('method', [
  z.strictObject({
    ...OnboardingBase,
    method: z.literal('zkpassport'),
    checks: z.strictObject({
      proof_verified: z.boolean(),
      bound_value_matches: z.boolean(), // custom_data == hex(tupleHash("legx/zk-onboard/v1", [contractRoot, slotPub]))
      expiry_after_cancel_plus_30d: z.boolean(),
      age_over_18: z.boolean(),
      scope: z.string().max(128),
      domain: z.string().max(253),
      unique_identifier: ZkIdentifier, // N_side; IDS_DISTINCT compares the two sides
      proof_sha256: Hex32,
      trust: ZkTrustRecord,
    }),
  }),
  z.strictObject({ ...OnboardingBase, method: z.literal('nfc-chip'), checks: ChipChecks }),
]);

// ---------- Bar records (DESIGN 6.16) ----------

export const BarSourceKind = z.enum(['registry-api', 'registry-page', 'manual']);

export const BarVerification = z.strictObject({
  jurisdiction: Jurisdiction,
  bar_number_sha256: Hex32,
  status: z.enum(['active', 'not_active']), // the gate needs 'active' (DESIGN 6.17 BAR_*_OK)
  source: z.strictObject({ kind: BarSourceKind, url: z.url({ protocol: /^https?$/ }), evidence_sha256: Hex32 }),
  ops_account: XrplAddress,
  checked_at_ledger: LedgerAnchor,
  verifier_key_id: KeyId,
  sig_algs: SigAlgs,
});

export const BarDealLink = z.strictObject({
  deal_id: z.uuid({ version: 'v7' }),
  contract_root: Hex32,
  role: LawyerSlot,
  lawyer_pub: XrplEd25519PublicKey,
  bar_commitment: Hex32, // LC_role
  ops_account: XrplAddress,
  verification_sha256: Hex32, // SHA-256 of the BarVerification envelope bytes
  sig_algs: SigAlgs,
});

/** Every payload with `payloadType` = attest: the strict shapes make the union unambiguous. */
export const AttestationPayload = z.union([PassportAttestation, IdentityOnboarded, BarVerification, BarDealLink]);

// ---------- Findings (DESIGN 6.9 lock checker, 6.17 release gate) ----------

/** Lock checker codes with a fixed name (DESIGN 6.9 and the Appendix A checker). */
export const LOCK_CODES = [
  'MASTER_DISABLED',
  'DEPOSIT_AUTH_ON',
  'DISALLOW_NFT_OFFER',
  'DISALLOW_CHECK',
  'DISALLOW_PAYCHAN',
  'DISALLOW_TRUSTLINE',
  'NO_REGULARKEY',
  'NO_NFTOKENMINTER',
  'NO_MINTEDNFTOKENS',
  'NO_AMMID',
  'NO_VAULTID',
  'NO_LOANBROKERID',
  'NO_SPONSOR',
  'NO_SPONSORINGOWNERCOUNT',
  'NO_SPONSORINGACCOUNTCOUNT',
  'DOMAIN_IS_SEAL',
  'RELEASER_IS_OPS_B',
  'ONE_SIGNER_LIST',
  'SIGNERS_MATCH_KEYS',
  'QUORUM_MATCH',
  'QUORUM_NEEDS_EVERY_SIGNER',
  'ONE_PREAUTH',
  'PREAUTH_ONLY_RELEASER',
  'CREDENTIAL_SUBJECT_EXPECTED',
  'CREDENTIAL_ACCEPTED',
  'TICKET_ALLOWED',
  'OWNER_COUNT_MATCHES',
  'QUARANTINE_PRESENT',
  'ESCROW_AMOUNT_AND_CONDITION',
  'NO_FINISH_DELAY_TRAP',
  'CANCEL_AFTER_MARGIN',
  'FOREIGN_INCOMING_ESCROW',
] as const;
/** `UNEXPECTED_OWNED_<TYPE>` (blocking) and `INCOMING_<TYPE>` (warning), TYPE = upper-cased LedgerEntryType. */
export const LockDynamicCode = z.string().regex(/^(?:UNEXPECTED_OWNED|INCOMING)_[A-Z0-9_]{1,64}$/);
export const LockCode = z.union([z.enum(LOCK_CODES), LockDynamicCode]);

// ---------- Shipment manifest (OD-37, build/SHIP_RECEIPT.md 1) ----------

/** One manifest line. Its RFC 8785 (JCS) bytes are one leaf of the signed manifest root. */
export const ManifestItem = z.strictObject({
  sku: z.string().min(1).max(64),
  description: z.string().max(512),
  qty: z.int().min(1).max(1_000_000),
  weight_g: z.int().min(0).max(1_000_000_000),
});
export type ManifestItem = z.infer<typeof ManifestItem>;
/** The full manifest Bob attaches as evidence; only the root over `items` is signed. */
export const Manifest = z.strictObject({
  items: z.array(ManifestItem).min(1).max(1000),
  packed_at: z.iso.datetime({ offset: true }),
  total_weight_g: z.int().min(0).max(Number.MAX_SAFE_INTEGER),
});
export type Manifest = z.infer<typeof Manifest>;

/** The 17 release gate codes (DESIGN 6.17; OD-37 added the shipment and the receipt). */
export const GATE_CODES = [
  'LOCK_OK',
  'CONTRACT_SEAL_OK',
  'PASSPORT_A_OK',
  'PASSPORT_B_OK',
  'BAR_A_OK',
  'BAR_B_OK',
  'ATTORNEY_CREDENTIAL_A_OK',
  'ATTORNEY_CREDENTIAL_B_OK',
  'RELEASER_SEALED',
  'OPS_BINDINGS_OK',
  'ONBOARDING_OK',
  'IDS_DISTINCT',
  'IDENTITY_POLICY_OK',
  'PQ_BINDINGS_OK',
  'SLOT_SETUP_OK',
  'SHIPMENT_SIGNED_OK',
  'RECEIPT_SIGNED_OK',
] as const;
export const GateCode = z.enum(GATE_CODES);
/** A warning of the release gate (`level: 'warn'`, `ok: true`): the demo profile accepted a release proof without a face match (OD-34). */
export const GateWarnCode = z.literal('DEMO_NO_FACE_MATCH');

/** One named result of the lock checker or the release gate (Appendix A `Finding`). */
export const Finding = z.strictObject({
  ok: z.boolean(),
  level: z.enum(['block', 'warn']),
  code: z.union([GateCode, GateWarnCode, LockCode]),
  detail: z.string().max(1024).optional(),
});
export type Finding = z.infer<typeof Finding>;

/** The record lawyer B signs when the gate passes (DESIGN 6.17); carried by the `release.gate.passed` event. */
export const ReleaseGateRecord = z
  .strictObject({
    deal_id: z.uuid({ version: 'v7' }),
    deal_seal: Hex32,
    ledger: LedgerAnchor, // the one validated ledger the gate read
    findings: z.array(Finding).min(GATE_CODES.length).max(256),
    relied_on: z
      .array(z.strictObject({ name: z.string().max(128), sha256: Hex32 }))
      .min(1)
      .max(256),
    slot_lb_sig: Ed25519SigHex, // FROST signature by slot LB over the record hash (recipe: core, task 1.12)
  })
  // A passed gate lists all 17 codes, each passing (DESIGN 6.17; IMPLEMENTATION P3.2-13).
  .refine((g) => GATE_CODES.every((c) => g.findings.some((f) => f.code === c && f.ok && f.level === 'block')), {
    path: ['findings'],
    message: 'a passed gate lists all 17 gate codes as passing',
  });

// ---------- Enrollment keys and slot policy (DESIGN 6.3, 6.4) ----------

/** Share holder roles (DESIGN 6.4; IMPLEMENTATION P1.15-09, P1.15-21). */
export const HolderRole = z.enum([
  'phone',
  'second-authenticator',
  'passkey-same-device',
  'recovery-agent',
  'console',
  'firm-hsm',
  'partner',
]);

/** One row of the append-only `enrollment_key` registry (DESIGN 9; IMPLEMENTATION P1.16-09 validity window). */
export const EnrollmentKey = z.strictObject({
  key_id: KeyId,
  slot: Slot,
  holder_role: HolderRole,
  ed25519_pub: Ed25519PublicKeyHex,
  mldsa65_pub: MlDsa65PublicKey,
  valid_from: RippleTime,
  valid_to: RippleTime.optional(),
});
export type EnrollmentKey = z.infer<typeof EnrollmentKey>;

/** A service holder's signed key list, anchored on the ledger from `account` (DESIGN 6.3). */
export const EnrollmentKeyList = z.strictObject({
  holder: z.enum(['recovery-agent', 'firm']),
  account: XrplAddress,
  keys: z.array(EnrollmentKey).min(1).max(64),
  issued_at: RippleTime,
  sig_algs: SigAlgs,
});

/** The inputs of `slotPolicy` (DESIGN 6.4): threshold 2 of 3 and the holder roles, never verifying shares. */
export const SlotPolicyInput = z.strictObject({
  slot: Slot,
  threshold: z.literal(2),
  participants: z.literal(3),
  roles: z.tuple([HolderRole, HolderRole, HolderRole]),
});

// ---------- Per-role public key data and the post-quantum binding (DESIGN 6.5, 6.13, 6.14, 9 deal_key) ----------

const KeyBase = {
  xrpl_pubkey: XrplEd25519PublicKey,
  xrpl_account: XrplAddress,
  commitment: Hex32, // C_side (clients) or LC_side (lawyers)
  binding_sig: Ed25519SigHex, // bindSig (DESIGN 6.5)
  slot_policy: Hex32,
  pq_key_hash: Hex32,
};

/** Public data one role contributes (DESIGN 9 `deal_key`, without the post-quantum binding, which comes after the seal). */
export const DealKey = z.discriminatedUnion('role', [
  z.strictObject({ ...KeyBase, role: z.enum(['alice', 'bob']), id_method: IdMethod }),
  z.strictObject({
    ...KeyBase,
    role: LawyerRole,
    contract_sig: Ed25519SigHex,
    ops_account: XrplAddress,
    ops_pub: XrplPublicKey, // the operations account's master or regular key (DESIGN 6.14)
    ops_bind_sig_ops: XrplKeySigHex,
    ops_bind_sig_lawyer: Ed25519SigHex,
  }),
]);

/** The post-quantum binding of one slot (DESIGN 6.13): two holder ML-DSA-65 signatures plus the slot key's cross-signature. */
export const PqBinding = z.strictObject({
  slot: Slot,
  deal_seal: Hex32,
  slot_pub: XrplEd25519PublicKey,
  pq_key_hash: Hex32,
  holder_sigs: z.tuple([
    z.strictObject({ key_id: KeyId, sig: MlDsa65Signature }),
    z.strictObject({ key_id: KeyId, sig: MlDsa65Signature }),
  ]),
  cross_sig: Ed25519SigHex,
});

/** A quarantine escrow as recorded by the deal (DESIGN 7.3 step 3, 9). */
export const EscrowRecord = z.strictObject({
  owner: XrplAddress,
  offer_sequence: SequenceNumber,
  amount_drops: Drops,
  condition: z.string().regex(/^A0258020[0-9A-F]{64}810120$/), // PREIMAGE-SHA-256, 39 bytes (DESIGN 6.7)
  cancel_after: RippleTime,
});
