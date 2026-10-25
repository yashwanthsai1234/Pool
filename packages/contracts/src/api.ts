// The API route table, declared once and shared by the server and the web client (IMPLEMENTATION 4.3).
// oRPC contract-first: every route has a request schema, a response schema and an auth rule in its meta.
// Source: https://orpc.dev/docs/contract-first/define-contract and https://orpc.dev/docs/metadata
// Every request is signed (DESIGN 8.10 access rule): the `x-legx-auth` header carries the caller's hybrid
// enrollment-key signatures over the api-request message, which hashes the raw body. So the server must see
// the raw body bytes (the oRPC Fastify adapter bypasses Fastify body parsing, IMPLEMENTATION 4.3).
import { oc } from '@orpc/contract';
import { z } from 'zod';
import { DomainHex, PublicDealData } from './deal.ts';
import { FrostIdentifier, FrostSignedMessage, TaggedPreimage, WebAuthnApproval } from './frost.ts';
import {
  BarNumber,
  DealKey,
  EnrollmentKey,
  EnvelopeBytesB64,
  EscrowRecord,
  HolderRole,
  HybridSignatures,
  Salt32,
  SealedBox,
  ZkVerification,
  ZkVerifyRequest,
} from './records.ts';
import {
  Base64,
  DealId,
  DealState,
  Drops,
  Ed25519SigHex,
  Hex32,
  HexBytes,
  HexBytesRange,
  IdentityPolicy,
  Jurisdiction,
  KeyId,
  LawyerSlot,
  LedgerIndex,
  Network,
  NFTokenId,
  Payout,
  Profile,
  RippleTime,
  Role,
  SequenceNumber,
  Side,
  Slot,
  Uuid7,
  XrplAddress,
  XrplEd25519PublicKey,
  XrplHash,
  XrplKeySigHex,
  XrplPublicKey,
} from './values.ts';

/** The request header that carries the caller's signatures. */
export const API_AUTH_HEADER = 'x-legx-auth';
/** Tag of the signed message: tupleHash(API_REQUEST_TAG, [utf8(method), utf8(path), SHA-256(body), nonce32, uint32_be(ledgerIndex)]). */
export const API_REQUEST_TAG = 'legx/api-request/v1';
/** The server refuses a request whose ledger index is more than this many ledgers older than the validated one. */
export const API_MAX_LEDGER_AGE = 20;

/**
 * The `x-legx-auth` header value (JSON). Both signatures are over the api-request message, made with the
 * caller's pinned enrollment keys (DESIGN 6.3, 8.10); the key ids name the `enrollment_key` rows. The server
 * refuses a reused nonce and a ledger index more than API_MAX_LEDGER_AGE ledgers old.
 * Source: DESIGN.md 8.10 "Access"
 */
export const ApiAuth = z.strictObject({
  nonce: HexBytes(32),
  ledgerIndex: LedgerIndex,
  signatures: HybridSignatures,
});

/**
 * Who may sign a request to a route. A deal role means a pinned enrollment key of a PRIMARY holder of that role's
 * slot in the request's `dealId`: `phone`, `second-authenticator` or `passkey-same-device` for a client, `console`
 * for a lawyer (OD-17). The other holders of a slot (`recovery-agent`, `firm-hsm`, `partner`) are never the party or
 * the lawyer (DESIGN 6.4, 8.10). `lawyer`: a lawyer console key whose operations account holds LEGX_ATTORNEY.
 * `share-holder`: any holder of a slot of the deal, primary or not; the route itself checks the FROST session.
 * `enrolled`: any pinned enrollment key. `operator`: a verifier-service operator key. `observer`: the projector
 * dashboard's pinned key (OD-31), which may only read.
 */
export const Caller = z.enum([...Role.options, 'lawyer', 'share-holder', 'enrolled', 'operator', 'observer']);

/** Holder roles that act as the party or the lawyer of their slot (OD-17; DESIGN 6.4, 8.10). */
export const PRIMARY_HOLDER_ROLES = ['phone', 'second-authenticator', 'passkey-same-device', 'console'] as const;

/**
 * Tag of a new enrollment key's proof of possession: both halves of the new key sign
 * tupleHash(ENROLLMENT_POP_TAG, [utf8(dealId), utf8(key_id), utf8(slot), utf8(holder_role), ed25519_pub, mldsa65_pub]),
 * the ML-DSA half with context ENROLLMENT_POP_TAG. Signature key ids are `<key_id>#ed25519` and `<key_id>#ml-dsa-65`.
 */
export const ENROLLMENT_POP_TAG = 'legx/enrollment-pop/v1';
/**
 * Tag of a lawyer recovery request (DESIGN 6.4, I-S-F1). The firm's operations account signs
 * tupleHash(LAWYER_RECOVERY_TAG, [utf8(dealId), utf8(slot), utf8(newKeyId), uint32_be(ledgerIndex)]), outside the body.
 */
export const LAWYER_RECOVERY_TAG = 'legx/lawyer-recovery/v1';

/** Every route uses the signed request; the rule names the callers it accepts. */
export const AuthRule = z.strictObject({
  kind: z.literal('signed-request'),
  callers: z.array(Caller).min(1),
  // DESIGN 8.10: the client of the request's `side`, or that client's own lawyer, and nobody else.
  ownSideOnly: z.literal(true).optional(),
});
export type AuthRule = z.infer<typeof AuthRule>;

type CallerName = z.infer<typeof Caller>;
// No default: every route states its own rule, and a test fails on a route without one (P1.2-05).
const base = oc.$meta<{ auth?: AuthRule }>({});
const signedBy = (...callers: CallerName[]) => ({ auth: { kind: 'signed-request' as const, callers } });
const ANY_DEAL_ROLE = signedBy('alice', 'lawyerA', 'bob', 'lawyerB');
/** Read routes: the deal's parties and lawyers, and the projector's observer key (OD-31). */
const READ = signedBy('alice', 'lawyerA', 'bob', 'lawyerB', 'observer');
const HOLDERS = signedBy('alice', 'lawyerA', 'bob', 'lawyerB', 'share-holder');
const LAWYERS = signedBy('lawyerA', 'lawyerB');
const OWN_SIDE = { auth: { ...ANY_DEAL_ROLE.auth, ownSideOnly: true as const } };

// ---------- Shared response shapes ----------

export const DealView = z.strictObject({
  dealId: DealId,
  state: DealState,
  network: Network,
  identityPolicy: IdentityPolicy,
  amountDrops: Drops,
  payoutA: Payout,
  payoutB: Payout,
  lawyerOpsA: XrplAddress,
  lawyerOpsB: XrplAddress,
  contractRoot: Hex32.optional(),
  walletAddress: XrplAddress.optional(),
  signedContractSeal: Hex32.optional(),
  dealSeal: Hex32.optional(),
  nftTokenId: NFTokenId.optional(),
  mintTxHash: XrplHash.optional(),
  escrow: EscrowRecord.optional(),
  exitSlot: SequenceNumber.optional(),
});

const ChainHead = z.strictObject({ nextSeq: z.int().min(0), prevHash: Hex32 });

export const SignaturePurpose = z.enum([
  'pay_bob',
  'refund_alice',
  'close',
  'ticket_create',
  'signer_list_update',
  'seal_update',
  'escrow_finish',
]);

export const SignatureRequest = z.strictObject({
  requestId: Uuid7,
  dealId: DealId,
  purpose: SignaturePurpose,
  unsignedTx: z.record(z.string(), z.unknown()),
  lastLedger: LedgerIndex,
  status: z.enum(['open', 'complete', 'expired', 'void']),
  signedRoles: z.array(Role).max(4),
});

const RecoveryStatus = z.strictObject({
  recoveryId: Uuid7,
  dealId: DealId,
  slot: Slot,
  state: z.enum(['waiting', 'ready', 'cancelled', 'done']),
  readyAt: RippleTime, // start + 72 hours, by ledger time (DESIGN 6.4)
});

/** One client record with its three checks (DESIGN 8.10). */
const ClientRecord = z.strictObject({
  seq: z.int().min(0),
  leafHash: Hex32,
  envelope: EnvelopeBytesB64,
  checks: z.strictObject({
    signature: z.boolean(),
    chain: z.boolean(),
    ledger: z.enum(['linked', 'none', 'mismatch']),
  }),
});

/** A records request (DESIGN 8.10); nonce and ledger index travel in the auth header. */
const RecordsRequest = z.strictObject({ dealId: DealId, side: Side });

/** What a FROST signing session signs, as JSON (bytes as lowercase hex; task 4.7 `requestToJson`). */
export const SignRequest = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('xrpl-multisign'), tx: z.record(z.string(), z.unknown()) }),
  z.strictObject({ kind: z.literal('tagged'), ...TaggedPreimage.shape }),
  z.strictObject({ kind: z.literal('gate-record'), envelope: HexBytesRange(1, 65536) }),
]);

/** The lawyer's presence request (DESIGN 6.15): presenceMsg is built from these and the sealed deal. */
export const PresenceRequest = z.strictObject({
  method: z.enum(['zkpassport', 'nfc-chip']),
  lawyerNonce: Hex32,
  ledgerHash: XrplHash,
  ledgerIndex: LedgerIndex,
});
const PresenceState = z.strictObject({
  status: z.enum(['none', 'open', 'signed']),
  request: PresenceRequest.optional(),
  signature: Ed25519SigHex.optional(), // the client's slot key over presenceMsg, once signed
});
const OWN_SIDE_LAWYER = { auth: { ...LAWYERS.auth, ownSideOnly: true as const } };
const OWN_SIDE_CLIENT = { auth: { ...signedBy('alice', 'bob').auth, ownSideOnly: true as const } };

// ---------- The route table ----------

export const contract = {
  health: base
    .route({ method: 'GET', path: '/health' })
    .meta(signedBy('enrolled', 'operator'))
    .input(z.strictObject({}))
    .output(
      z.strictObject({
        profile: Profile,
        ports: z.record(
          z.string().max(64),
          z.strictObject({ impl: z.string().max(64), status: z.enum(['ok', 'down']) }),
        ),
      }),
    ),

  deals: {
    create: base
      .route({ method: 'POST', path: '/deals' })
      .meta(signedBy('lawyer'))
      .input(
        z.strictObject({
          network: Network,
          identityPolicy: IdentityPolicy,
          amountDrops: Drops,
          payoutA: Payout,
          payoutB: Payout,
          lawyerOpsA: XrplAddress,
          lawyerOpsB: XrplAddress,
        }),
      )
      .output(DealView),
    // The deals the caller is party to (I-W-10): a lawyer directory key gets the deals of its operations account and
    // those its console key was enrolled in; a deal key gets its own deal; the observer key gets every deal (OD-31).
    mine: base
      .route({ method: 'GET', path: '/deals' })
      .meta(signedBy('lawyer', 'enrolled', 'observer'))
      .input(z.strictObject({}))
      .output(
        z.strictObject({
          deals: z.array(z.strictObject({ dealId: DealId, role: Role.optional(), state: DealState })).max(200),
        }),
      ),
    get: base
      .route({ method: 'GET', path: '/deals/{dealId}' })
      .meta(READ)
      .input(z.strictObject({ dealId: DealId }))
      .output(DealView),
    setWallet: base
      .route({ method: 'POST', path: '/deals/{dealId}/wallet' })
      .meta(signedBy('alice'))
      .input(z.strictObject({ dealId: DealId, walletAddress: XrplAddress }))
      .output(DealView),
    setContract: base
      .route({ method: 'POST', path: '/deals/{dealId}/contract' })
      .meta(signedBy('lawyerA'))
      .input(z.strictObject({ dealId: DealId, contractRoot: Hex32 }))
      .output(DealView),
    keys: base
      .route({ method: 'GET', path: '/deals/{dealId}/keys' })
      .meta(READ)
      .input(z.strictObject({ dealId: DealId }))
      .output(z.strictObject({ keys: z.array(DealKey).max(4) })),
    publicData: base
      .route({ method: 'GET', path: '/deals/{dealId}/public-data' })
      .meta(READ)
      .input(z.strictObject({ dealId: DealId }))
      .output(
        z.discriminatedUnion('status', [
          z.strictObject({
            status: z.literal('complete'),
            publicData: PublicDealData,
            dealSeal: Hex32,
            domain: DomainHex,
          }),
          z.strictObject({ status: z.literal('incomplete'), missing: z.array(z.string().max(64)).min(1).max(29) }),
        ]),
      ),
  },

  // Every party action is a signed evidence event; the coordinator applies it, stores it and the state change
  // and an outbox row in one transaction (IMPLEMENTATION P3.2-03).
  events: {
    head: base
      .route({ method: 'GET', path: '/deals/{dealId}/events/head' })
      .meta(READ)
      .input(z.strictObject({ dealId: DealId }))
      .output(ChainHead),
    append: base
      .route({ method: 'POST', path: '/deals/{dealId}/events' })
      .meta(ANY_DEAL_ROLE)
      .input(z.strictObject({ dealId: DealId, envelope: EnvelopeBytesB64 }))
      .output(
        z.discriminatedUnion('status', [
          z.strictObject({ status: z.literal('stored'), seq: z.int().min(0), leafHash: Hex32, state: DealState }),
          z.strictObject({ status: z.literal('seq_taken'), head: ChainHead }),
        ]),
      ),
    list: base
      .route({ method: 'GET', path: '/deals/{dealId}/events' })
      .meta(READ)
      .input(z.strictObject({ dealId: DealId, afterSeq: z.int().min(-1), limit: z.int().min(1).max(500) }))
      .output(z.strictObject({ events: z.array(z.strictObject({ seq: z.int().min(0), envelope: EnvelopeBytesB64 })) })),
  },

  signatures: {
    create: base
      .route({ method: 'POST', path: '/deals/{dealId}/signature-requests' })
      .meta(ANY_DEAL_ROLE)
      .input(z.strictObject({ dealId: DealId, purpose: SignaturePurpose }))
      .output(SignatureRequest),
    list: base
      .route({ method: 'GET', path: '/deals/{dealId}/signature-requests' })
      .meta(READ)
      .input(z.strictObject({ dealId: DealId }))
      .output(z.strictObject({ requests: z.array(SignatureRequest) })),
    submit: base
      .route({ method: 'POST', path: '/deals/{dealId}/signature-requests/{requestId}/signatures' })
      .meta(ANY_DEAL_ROLE)
      .input(
        z.strictObject({
          dealId: DealId,
          requestId: Uuid7,
          role: Role,
          signerBlob: z.string().regex(/^(?:[0-9A-F]{2}){1,10000}$/), // wallet.sign(tx, true).tx_blob
        }),
      )
      .output(
        z.strictObject({
          status: z.enum(['accepted', 'duplicate']),
          signedRoles: z.array(Role).max(4),
          submitted: z.boolean(),
        }),
      ),
  },

  records: {
    list: base
      .route({ method: 'POST', path: '/deals/{dealId}/records' })
      .meta(OWN_SIDE)
      .input(RecordsRequest)
      .output(z.strictObject({ records: z.array(ClientRecord) })),
    bundle: base
      .route({ method: 'POST', path: '/deals/{dealId}/bundle' })
      .meta(OWN_SIDE)
      .input(RecordsRequest)
      .output(z.strictObject({ filename: z.string().max(128), sha256: Hex32, zip: Base64(67108864) })),
  },

  bar: {
    verify: base
      .route({ method: 'POST', path: '/bar/verifications' })
      .meta(signedBy('lawyer'))
      .input(z.strictObject({ opsAccount: XrplAddress, jurisdiction: Jurisdiction, barNumber: BarNumber }))
      .output(
        z.strictObject({
          status: z.enum(['active', 'not_active', 'not_found']),
          verificationSha256: Hex32.optional(),
          envelope: EnvelopeBytesB64.optional(),
        }),
      ),
    manualEvidence: base
      .route({ method: 'POST', path: '/bar/manual-evidence' })
      .meta(signedBy('operator'))
      .input(
        z.strictObject({
          opsAccount: XrplAddress,
          jurisdiction: Jurisdiction,
          barNumber: BarNumber, // the manual adapter looks the number up; never stored
          status: z.enum(['active', 'not_active', 'not_found']), // what the operator read on the registry page
          url: z.url({ protocol: /^https?$/ }),
          evidence: Base64(10485760),
        }),
      )
      .output(z.strictObject({ evidenceSha256: Hex32 })),
    dealLink: base
      .route({ method: 'POST', path: '/deals/{dealId}/bar-links' })
      .meta(LAWYERS)
      .input(
        z.strictObject({
          dealId: DealId,
          role: LawyerSlot,
          lawyerPub: XrplEd25519PublicKey,
          barCommitment: Hex32,
          barNumber: BarNumber, // with the salt, opens LC; never stored (P3.3-08)
          barSalt: Salt32, // lets the verifier open LC; never stored (P3.3-08)
          opsAccount: XrplAddress,
          verificationSha256: Hex32,
        }),
      )
      .output(z.strictObject({ linkSha256: Hex32, envelope: EnvelopeBytesB64 })),
    record: base
      .route({ method: 'GET', path: '/bar/records/{sha256}' })
      .meta(signedBy('enrolled')) // records hold only the bar number hash
      .input(z.strictObject({ sha256: Hex32 }))
      .output(z.strictObject({ envelope: EnvelopeBytesB64 })),
  },

  keys: {
    // Pinning a key into a deal (DESIGN 6.3). The request is signed by the out-of-band channel that vouches for the
    // key: a primary holder of the same slot (the QR scan between a client's devices; a lawyer's console pinning its
    // firm's signed key list), the client's own lawyer (onboarding), or a lawyer directory key pinning its own console
    // key into its slot. The new key proves possession with ENROLLMENT_POP_TAG.
    register: base
      .route({ method: 'POST', path: '/deals/{dealId}/enrollment-keys' })
      .meta(signedBy('alice', 'lawyerA', 'bob', 'lawyerB', 'lawyer'))
      .input(z.strictObject({ dealId: DealId, key: EnrollmentKey, proofOfPossession: HybridSignatures }))
      .output(z.strictObject({ keyId: KeyId, status: z.enum(['created', 'exists']) })),
    get: base
      .route({ method: 'GET', path: '/enrollment-keys/{keyId}' })
      .meta(signedBy('enrolled'))
      .input(z.strictObject({ keyId: KeyId }))
      .output(EnrollmentKey),
  },

  frost: {
    openSession: base
      .route({ method: 'POST', path: '/deals/{dealId}/frost-sessions' })
      .meta(HOLDERS)
      .input(
        z.strictObject({
          dealId: DealId,
          slot: Slot,
          purpose: z.enum(['dkg', 'sign', 'refresh', 'repair']),
          participants: z
            .array(z.strictObject({ identifier: FrostIdentifier, keyId: KeyId, role: HolderRole }))
            .length(3),
          // For signing: the two holders asked to sign (task 4.7). Absent: the first two participants as listed.
          pair: z.tuple([FrostIdentifier, FrostIdentifier]).optional(),
        }),
      )
      .output(z.strictObject({ sessionId: Hex32 })),
    send: base
      .route({ method: 'POST', path: '/frost/sessions/{sessionId}/messages' })
      .meta(signedBy('share-holder'))
      .input(z.strictObject({ sessionId: Hex32, message: FrostSignedMessage }))
      .output(z.strictObject({ seq: z.int().min(0) })),
    receive: base
      .route({ method: 'GET', path: '/frost/sessions/{sessionId}/messages' })
      .meta(signedBy('share-holder'))
      .input(z.strictObject({ sessionId: Hex32, recipient: FrostIdentifier, afterSeq: z.int().min(-1) }))
      .output(
        z.strictObject({ messages: z.array(z.strictObject({ seq: z.int().min(0), message: FrostSignedMessage })) }),
      ),
  },

  recovery: {
    start: base
      .route({ method: 'POST', path: '/deals/{dealId}/recoveries' })
      .meta(ANY_DEAL_ROLE)
      .input(
        z.discriminatedUnion('kind', [
          // Client recovery: a fresh ZK proof with the onboarding identifier, plus a face match (DESIGN 6.4).
          z.strictObject({
            kind: z.literal('client'),
            dealId: DealId,
            slot: z.enum(['A', 'B']),
            newKeyId: KeyId,
            proof: ZkVerification,
          }),
          // Lawyer recovery: signed by the firm's operations account (DESIGN 6.4).
          z.strictObject({
            kind: z.literal('lawyer'),
            dealId: DealId,
            slot: LawyerSlot,
            newKeyId: KeyId,
            ledgerIndex: LedgerIndex, // inside the signed message, so an old signature cannot start a new recovery
            opsSig: z.strictObject({ opsPub: XrplPublicKey, sig: XrplKeySigHex }), // over LAWYER_RECOVERY_TAG
          }),
        ]),
      )
      .output(RecoveryStatus),
    cancel: base
      .route({ method: 'POST', path: '/recoveries/{recoveryId}/cancel' })
      .meta(ANY_DEAL_ROLE) // the old device cancels
      .input(
        z.strictObject({
          dealId: DealId,
          recoveryId: Uuid7,
          cancelSig: Ed25519SigHex, // the old device's slot key over the cancel statement (DESIGN 6.4)
          oldDevicePub: XrplEd25519PublicKey,
        }),
      )
      .output(RecoveryStatus),
    get: base
      .route({ method: 'GET', path: '/recoveries/{recoveryId}' })
      .meta(ANY_DEAL_ROLE)
      .input(z.strictObject({ dealId: DealId, recoveryId: Uuid7 }))
      .output(RecoveryStatus),
  },

  zk: {
    verify: base
      .route({ method: 'POST', path: '/deals/{dealId}/zk/verify' })
      .meta(LAWYERS)
      // The server derives the expectation (stage, bound value, CancelAfter, the sealed C_side) from the deal itself.
      .input(z.strictObject({ dealId: DealId, side: Side, request: ZkVerifyRequest, zkSalt32: Salt32 }))
      .output(ZkVerification),
  },

  // The firm HSM service (task 3.10) joins a FROST signing session of a lawyer slot as holder 2 (task 4.7). The firm's
  // operations account authorizes it over `legx/firm-cosign-request/v1` [dealId, slot, sessionId, seal, pair]. The
  // message itself arrives in the aggregator's `sign.begin`; `request` is needed only when the HSM aggregates (pair
  // [2, 3], the recovery pair). Refusals are logged in the HSM's audit log and end the session.
  firmHsm: {
    sign: base
      .route({ method: 'POST', path: '/deals/{dealId}/firm-hsm/sign' })
      .meta(LAWYERS)
      .input(
        z.strictObject({
          dealId: DealId,
          slot: LawyerSlot,
          sessionId: Hex32,
          pair: z.tuple([z.int().min(1).max(3), z.int().min(1).max(3)]),
          seal: Hex32,
          operator: z.strictObject({ opsPub: XrplPublicKey, sig: XrplKeySigHex }),
          // When the HSM aggregates: the exact message and what it is (its allow-list check needs both)
          message: HexBytesRange(32, 16384).optional(),
          request: SignRequest.optional(),
          approval: WebAuthnApproval.optional(), // the lawyer's user-verified approval (DESIGN 6.4)
        }),
      )
      .output(z.strictObject({ status: z.literal('started') })),
  },

  // The coordinator's read-only relay of the validated ledger, for clients without their own XRPL connection.
  ledger: {
    accountInfo: base
      .route({ method: 'GET', path: '/ledger/accounts/{address}' })
      .meta(signedBy('enrolled'))
      .input(z.strictObject({ address: XrplAddress }))
      .output(
        z.discriminatedUnion('exists', [
          z.strictObject({
            exists: z.literal(true),
            ledgerIndex: LedgerIndex,
            flags: z.int().min(0).max(0xffffffff),
            sequence: SequenceNumber,
            balanceDrops: Drops,
          }),
          z.strictObject({ exists: z.literal(false), ledgerIndex: LedgerIndex }),
        ]),
      ),
    submit: base
      .route({ method: 'POST', path: '/ledger/submit' })
      .meta(signedBy('enrolled'))
      .input(z.strictObject({ txBlob: z.string().regex(/^(?:[0-9A-F]{2}){1,100000}$/) }))
      .output(
        // As LedgerPort.submitReliable reports it (IMPLEMENTATION 2.2): validated (tes or tec), rejected, or expired.
        z.discriminatedUnion('status', [
          z.strictObject({
            status: z.literal('validated'),
            result: z.string().regex(/^te[cs][A-Z_]{1,64}$/),
            hash: XrplHash,
            ledgerIndex: LedgerIndex,
          }),
          z.strictObject({ status: z.literal('rejected'), result: z.string().regex(/^[a-z]{3}[A-Z_]{1,64}$/) }),
          z.strictObject({ status: z.literal('expired'), lastLedgerSequence: LedgerIndex }),
        ]),
      ),
    // The release gate's input (core `ReleaseInput`), as validated ledger data; bytes are `{"$b64": ...}`.
    snapshot: base
      .route({ method: 'GET', path: '/deals/{dealId}/ledger-snapshot' })
      .meta(LAWYERS)
      .input(z.strictObject({ dealId: DealId }))
      .output(z.strictObject({ releaseInput: z.record(z.string().max(64), z.unknown()) })),
  },

  // The client's salt and ZK disclosure proof, sealed to its own lawyer (OD-36 b). The coordinator keeps each box as
  // received (one per kind, never replaced) and serves them only to that side's lawyer console key; it never sees plaintext.
  identityBox: {
    put: base
      .route({ method: 'POST', path: '/deals/{dealId}/identity-box/{side}' })
      .meta(OWN_SIDE_CLIENT)
      .input(z.strictObject({ dealId: DealId, side: Side, kind: z.enum(['zk-salt', 'zk-disclosure']), box: SealedBox }))
      .output(z.strictObject({ status: z.literal('stored') })),
    get: base
      .route({ method: 'GET', path: '/deals/{dealId}/identity-box/{side}' })
      .meta(OWN_SIDE_LAWYER)
      .input(z.strictObject({ dealId: DealId, side: Side }))
      .output(
        z.strictObject({
          boxes: z.array(z.strictObject({ kind: z.enum(['zk-salt', 'zk-disclosure']), box: SealedBox })).max(2),
        }),
      ),
  },

  // Passport presence (DESIGN 6.15): the lawyer posts the request, the client's slot key signs presenceMsg.
  presence: {
    open: base
      .route({ method: 'POST', path: '/deals/{dealId}/presence/{side}' })
      .meta(OWN_SIDE_LAWYER)
      .input(z.strictObject({ dealId: DealId, side: Side, request: PresenceRequest }))
      .output(PresenceState),
    get: base
      .route({ method: 'GET', path: '/deals/{dealId}/presence/{side}' })
      .meta(OWN_SIDE)
      .input(z.strictObject({ dealId: DealId, side: Side }))
      .output(PresenceState),
    submit: base
      .route({ method: 'POST', path: '/deals/{dealId}/presence/{side}/signature' })
      .meta(OWN_SIDE_CLIENT)
      .input(z.strictObject({ dealId: DealId, side: Side, lawyerNonce: Hex32, signature: Ed25519SigHex }))
      .output(PresenceState),
  },
};
