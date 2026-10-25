// The evidence event: an in-toto Statement v1 carried in a hybrid DSSE envelope (DESIGN 8.1).
// Source: https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
// `sig_algs` sits inside the signed predicate (DESIGN 8.1, 6.13). `data` holds the public, per-kind facts the
// table in DESIGN 8.1 lists; it never holds personal data (invariant I7). Off-ledger payloads are only
// referenced through `payload_commitment`.
import { z } from 'zod';
import { FrostIdentifier } from './frost.ts';
import {
  EnvelopeBytesB64,
  EscrowRecord,
  Finding,
  HolderRole,
  PqBinding,
  ReleaseGateRecord,
  SigAlgs,
} from './records.ts';
import {
  ActorRole,
  Drops,
  Ed25519SigHex,
  Hex32,
  Hex32Point,
  IdentityPolicy,
  KeyId,
  LawyerSlot,
  LedgerAnchor,
  LedgerIndex,
  Network,
  NFTokenId,
  Payout,
  RippleTime,
  SequenceNumber,
  Side,
  Slot,
  XrplAddress,
  XrplEd25519PublicKey,
  XrplHash,
  XrplKeySigHex,
  XrplPublicKey,
} from './values.ts';

const ExitPurpose = z.enum(['pay_bob', 'refund_alice']);
const VerifyingShare = z.strictObject({ identifier: FrostIdentifier, share: Hex32Point });
const KeySig = z.strictObject({ key_id: KeyId, sig: Ed25519SigHex });
/** What a server share holder decided for one request (firm HSM audit row, task 3.10; recovery agent, task 3.9). */
const FrostDecision = z.strictObject({
  slot: Slot,
  reason: z.string().regex(/^[A-Za-z_]{1,64}$/), // `signed`, or the refusal code
  message_hash: Hex32.or(z.literal('')).optional(), // empty when refused before a message was known
  seal: Hex32.or(z.literal('')).optional(), // empty before the seal exists
  audit_hash: Hex32.optional(), // the hash-chained audit row (P3.10-07)
  kind: z.enum(['xrpl-multisign', 'tagged']).optional(),
  tag: z
    .string()
    .regex(/^legx\/[a-z0-9-]{1,64}\/v[0-9]{1,3}$/)
    .optional(),
  credential: z.string().max(1024).optional(), // the WebAuthn credential id that approved (base64url)
  commitment_id: Hex32.optional(),
});
/** Carrier name or tracking ID: 1 to 64 printable characters, no control characters (OD-37). */
const ShipText = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[^\p{Cc}]+$/u);
/** Delivery condition of a receipt; rcptMsg carries its index as uint8 (0 ok, 1 damaged, 2 missing). */
export const ReceiptCondition = z.enum(['ok', 'damaged', 'missing']);
/** OD-37 (build/SHIP_RECEIPT.md 2): Bob's slot B FROST signature over shipMsg; the manifest itself is an attachment. */
export const ShipmentSigned = z.strictObject({
  manifest_root: Hex32, // RFC 9162 Merkle root over the JCS bytes of the manifest items
  carrier: ShipText,
  tracking_id: ShipText,
  ledger_index: LedgerIndex, // a recent validated ledger, signed inside shipMsg
  ship_msg_hash: Hex32, // SHA-256(shipMsg) = shipmentHash
  slot_sig: Ed25519SigHex,
});
export type ShipmentSigned = z.infer<typeof ShipmentSigned>;
/** OD-37 (build/SHIP_RECEIPT.md 3): Alice's slot A FROST signature over rcptMsg, bound to one shipment. */
export const ReceiptSigned = z.strictObject({
  shipment_hash: Hex32,
  manifest_root: Hex32,
  condition: ReceiptCondition,
  ledger_index: LedgerIndex,
  rcpt_msg_hash: Hex32, // SHA-256(rcptMsg)
  slot_sig: Ed25519SigHex,
});
export type ReceiptSigned = z.infer<typeof ReceiptSigned>;
const Recovery = { recovery_id: z.uuid({ version: 'v7' }), slot: Slot };

/** Per-kind event data, keyed by EventKind (DESIGN 8.1). */
const EVENT_DATA = {
  'contract.lawyer_signed': z.strictObject({
    role: LawyerSlot,
    contract_root: Hex32,
    wallet_address: XrplAddress,
    lawyer_pub: XrplEd25519PublicKey,
    contract_sig: Ed25519SigHex,
  }),
  'nft.minted': z.strictObject({
    nftoken_id: NFTokenId,
    mint_tx_hash: XrplHash,
    minter: XrplAddress,
    signed_contract_seal: Hex32,
  }),
  'shell.opened': z.strictObject({ wallet_address: XrplAddress, funding_tx_hash: XrplHash }),
  'escrow.created': z.strictObject({ escrow: EscrowRecord, tx_hash: XrplHash }),
  'key.bound': z.strictObject({
    slot: Slot,
    xrpl_pubkey: XrplEd25519PublicKey,
    commitment: Hex32,
    binding_sig: Ed25519SigHex,
  }),
  'ops.bound': z.strictObject({
    role: LawyerSlot,
    ops_account: XrplAddress,
    ops_pub: XrplPublicKey,
    lawyer_pub: XrplEd25519PublicKey,
    bar_commitment: Hex32,
    sig_ops: XrplKeySigHex,
    sig_lawyer: Ed25519SigHex,
  }),
  'bar.verified': z.strictObject({ ops_account: XrplAddress, verification_sha256: Hex32 }),
  'bar.deal_linked': z.strictObject({ role: LawyerSlot, link_sha256: Hex32, verification_sha256: Hex32 }),
  'attorney.credential.issued': z.strictObject({
    ops_account: XrplAddress,
    verification_sha256: Hex32,
    create_tx_hash: XrplHash,
    accept_tx_hash: XrplHash,
    expiration: RippleTime,
  }),
  'wallet.locked': z.strictObject({
    tx_hashes: z.array(XrplHash).min(1).max(16),
    domain: z.string().regex(/^01[0-9A-F]{128}$/),
  }),
  'lock.verified': z.strictObject({ ledger: LedgerAnchor, findings: z.array(Finding).max(512) }),
  'lawyer.approved': z.strictObject({ role: LawyerSlot, message_hash: Hex32 }),
  'passport.verified': z.strictObject({ side: Side, attestation: EnvelopeBytesB64 }), // embedded byte for byte
  'release.gate.passed': z.strictObject({ gate: ReleaseGateRecord }),
  'release.performed': z.strictObject({ finish_tx_hash: XrplHash, ledger_index: LedgerIndex, gate_leaf_hash: Hex32 }),
  'frost.dkg.completed': z.strictObject({
    session_id: Hex32, // the DKG session; inside the transcript the holder signatures cover
    slot: Slot,
    group_pub: XrplEd25519PublicKey,
    slot_policy: Hex32,
    roles: z.tuple([HolderRole, HolderRole, HolderRole]),
    transcript_hash: Hex32,
    holder_sigs: z.tuple([KeySig, KeySig, KeySig]), // every holder over the transcript hash
    verifying_shares: z.tuple([VerifyingShare, VerifyingShare, VerifyingShare]),
    test_sigs: z.tuple([Ed25519SigHex, Ed25519SigHex, Ed25519SigHex]), // pairs (1,2), (1,3), (2,3)
  }),
  'frost.signed': z.strictObject({
    slot: Slot,
    message_hash: Hex32,
    signer_key_ids: z.tuple([KeyId, KeyId]),
    signature: Ed25519SigHex,
  }),
  'frost.refreshed': z.strictObject({
    slot: Slot,
    group_pub: XrplEd25519PublicKey,
    epoch: z.int().min(1),
    old_verifying_shares: z.tuple([VerifyingShare, VerifyingShare, VerifyingShare]),
    new_verifying_shares: z.tuple([VerifyingShare, VerifyingShare, VerifyingShare]),
    deletion_sigs: z.array(KeySig).max(3), // complete only when every remaining holder signed (P1.15-18)
  }),
  'identity.onboarded': z.strictObject({ side: Side, attestation: EnvelopeBytesB64 }), // IdentityOnboarded envelope
  'pq.bound': z.strictObject({ binding: PqBinding }),
  'exit.signed': z.strictObject({
    purpose: ExitPurpose,
    request_id: z.uuid({ version: 'v7' }),
    exit_slot: SequenceNumber, // Sequence or TicketSequence of slot S (DESIGN 7.5)
    destination: Payout,
  }),
  'exit.validated': z.strictObject({
    purpose: ExitPurpose,
    tx_hash: XrplHash,
    destination: Payout,
    delivered_drops: Drops, // from meta.delivered_amount
  }),
  'dispute.opened': z.strictObject({ notice_sha256: Hex32 }),
  'award.recorded': z.strictObject({ award_sha256: Hex32, outcome: ExitPurpose }),
  'escrow.cancelled': z.strictObject({ tx_hash: XrplHash }),
  'wallet.closed': z.strictObject({ tx_hash: XrplHash, destination: XrplAddress }),
  // The coordinator's genesis event of a deal (task 3.2; the identity policy is read from it).
  'deal.created': z.strictObject({ identity_policy: IdentityPolicy, network: Network, amount_drops: Drops }),
  // An enrollment key's hash enters the log before the key is usable (DESIGN 6.3).
  'enrollment.pinned': z.strictObject({ key_id: KeyId, slot: Slot, holder_role: HolderRole, key_sha256: Hex32 }),
  // Two watched XRPL servers report different hashes for one validated ledger (task 3.5).
  'ledger.disagreement': z.strictObject({
    ledger_index: LedgerIndex,
    hashes: z
      .record(z.string().max(256), XrplHash) // server name -> ledger hash
      .refine((h) => Object.keys(h).length >= 2 && Object.keys(h).length <= 8, 'two to eight servers'),
  }),
  'frost.share.released': FrostDecision,
  'frost.refused': FrostDecision,
  // Recovery of a slot (DESIGN 6.4 recovery rules); `ready_at` is the start plus the 72-hour delay, by ledger time.
  'frost.recovery.requested': z.strictObject({ ...Recovery, new_key_id: KeyId, ready_at: z.int().min(0) }),
  'frost.recovery.cancelled': z.strictObject(Recovery),
  'frost.recovery.authorized': z.strictObject(Recovery),
  // The recovery pair signed after the delay (I-E6): which holder roles signed.
  'frost.recovery.signed': z.strictObject({ ...Recovery, holder_roles: z.tuple([HolderRole, HolderRole]) }),
  // OD-28: the old lawyer B hands the release code to the new lawyer B in an X-Wing box (kind
  // `release-code-handover`); the box is an attachment and only its hash is logged.
  'release_code.handed_over': z.strictObject({ from_key_id: KeyId, to_key_id: KeyId, box_sha256: Hex32 }),
  'shipment.signed': ShipmentSigned,
  'receipt.signed': ReceiptSigned,
  'checkpoint.anchored': z.strictObject({
    tree_size: z.int().min(1),
    root: Hex32,
    anchor_tx_hash: XrplHash,
    anchor_ledger: LedgerIndex,
  }),
} as const;

/** Every event kind of DESIGN 8.1. */
export const EventKind = z.enum(Object.keys(EVENT_DATA) as [keyof typeof EVENT_DATA, ...(keyof typeof EVENT_DATA)[]]);
export type EventKind = z.infer<typeof EventKind>;

const PredicateBase = {
  event_id: z.uuid({ version: 'v7' }),
  deal_id: z.uuid({ version: 'v7' }),
  seq: z.int().min(0), // gap-free per deal
  actor: z.strictObject({ role: ActorRole, key_id: KeyId }),
  occurred_at: z.iso.datetime({ offset: true }), // RFC 3339, as claimed by the signer
  prev_hash: Hex32, // sha256 of the previous envelope in this deal; zeros for seq 0
  payload_commitment: Hex32, // HMAC-SHA256(dealKey, sha256(off-ledger payload))
  ledger: z.strictObject({ tx_hash: XrplHash, ledger_index: LedgerIndex, validated: z.literal(true) }).optional(),
  trace_id: z
    .string()
    .regex(/^[0-9a-f]{32}$/)
    .optional(), // W3C trace-id; join key only, never on the ledger
  sig_algs: SigAlgs,
};

type Kind = keyof typeof EVENT_DATA;
const predicateFor = <K extends Kind>(kind: K) =>
  z.strictObject({ ...PredicateBase, kind: z.literal(kind), data: EVENT_DATA[kind] });

type PredicateSchema = { [K in Kind]: ReturnType<typeof predicateFor<K>> }[Kind];
export const EventPredicate = z.discriminatedUnion(
  'kind',
  EventKind.options.map(predicateFor) as unknown as [PredicateSchema, ...PredicateSchema[]],
);

/** The in-toto Statement v1 inside every event envelope (DESIGN 8.1). */
export const LegxEvent = z.strictObject({
  _type: z.literal('https://in-toto.io/Statement/v1'),
  subject: z.tuple([
    z.strictObject({
      name: z.string().regex(/^deal:[0-9a-f-]{36}$/),
      digest: z.strictObject({ sha256: Hex32 }), // the contract root
    }),
  ]),
  predicateType: z.literal('https://legx.dev/event/v1'),
  predicate: EventPredicate,
});
export type LegxEvent = z.infer<typeof LegxEvent>;
