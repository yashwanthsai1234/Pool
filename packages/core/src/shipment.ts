// OD-37: the shipment (seller, slot B) and the delivery receipt (buyer, slot A) that the release gate requires.
// Both are FROST Ed25519 slot signatures over tagged tupleHash messages bound to the deal and its seal.
// Source: build/SHIP_RECEIPT.md sections 1 to 4; build/DECISIONS.md OD-37
import { ReceiptCondition, ReceiptSigned, ShipmentSigned } from '@legx/contracts/events';
import { ManifestItem } from '@legx/contracts/records';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import canonicalize from 'canonicalize';
import { mth, tupleHash } from './dealcore.ts';
import { u32, verifyEd25519Strict } from './frost.ts';

export const SHIPMENT_TAG = 'legx/shipment/v1';
export const RECEIPT_TAG = 'legx/receipt/v1';
/** A shipment's ledger index is at most this many ledgers old when the coordinator accepts it. */
export const SHIP_LEDGER_MAX_AGE = 20;
/** Receipt conditions in rcptMsg order: the uint8 is the index (0 ok, 1 damaged, 2 missing). */
export const CONDITIONS = ReceiptCondition.options;
export type Condition = (typeof CONDITIONS)[number];

/**
 * The RFC 8785 (JCS) bytes of one manifest item, after the strict item schema (no extra key, integers in range).
 * The library refuses lone surrogates (RFC 8785 3.2.2.2).
 * Source: https://www.rfc-editor.org/rfc/rfc8785.html#section-3.2
 */
export function jcsItem(item: ManifestItem): Uint8Array {
  return utf8ToBytes(canonicalize(ManifestItem.parse(item)) as string);
}

/**
 * The RFC 9162 Merkle tree hash over the items' JCS bytes, in list order. Throws on an empty or invalid manifest.
 * Source: https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1.1 ; build/SHIP_RECEIPT.md 1
 */
export function manifestRoot(items: readonly ManifestItem[]): Uint8Array {
  if (items.length === 0) throw new Error('empty manifest');
  return mth(items.map(jcsItem));
}

const bytes32 = (b: Uint8Array, what: string) => {
  if (b.length !== 32) throw new Error(`${what} must be 32 bytes`);
  return b;
};
const uint32 = (n: number) => {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error('ledger index must be a uint32');
  return u32(n);
};

export interface ShipmentFields {
  readonly dealId: string;
  readonly dealSeal: Uint8Array;
  readonly manifestRoot: Uint8Array;
  readonly carrier: string;
  readonly trackingId: string;
  readonly ledgerIndex: number;
}
/** The tupleHash parts of shipMsg, as the slot allow-list checks them (frostRules). */
export const shipParts = (f: ShipmentFields): Uint8Array[] => [
  utf8ToBytes(f.dealId),
  bytes32(f.dealSeal, 'dealSeal'),
  bytes32(f.manifestRoot, 'manifestRoot'),
  utf8ToBytes(f.carrier),
  utf8ToBytes(f.trackingId),
  uint32(f.ledgerIndex),
];
/** shipMsg = tupleHash("legx/shipment/v1", [dealId, dealSeal, manifestRoot, carrier, trackingId, u32 ledger]). */
export const shipMsg = (f: ShipmentFields): Uint8Array => tupleHash(SHIPMENT_TAG, shipParts(f));
/** shipmentHash = SHA-256(shipMsg): what the receipt binds to. */
export const shipmentHash = (f: ShipmentFields): Uint8Array => sha256(shipMsg(f));

export interface ReceiptFields {
  readonly dealId: string;
  readonly dealSeal: Uint8Array;
  readonly shipmentHash: Uint8Array;
  readonly manifestRoot: Uint8Array;
  readonly condition: Condition;
  readonly ledgerIndex: number;
}
export function rcptParts(f: ReceiptFields): Uint8Array[] {
  const c = CONDITIONS.indexOf(f.condition);
  if (c < 0) throw new Error('unknown condition');
  return [
    utf8ToBytes(f.dealId),
    bytes32(f.dealSeal, 'dealSeal'),
    bytes32(f.shipmentHash, 'shipmentHash'),
    bytes32(f.manifestRoot, 'manifestRoot'),
    Uint8Array.of(c),
    uint32(f.ledgerIndex),
  ];
}
/** rcptMsg = tupleHash("legx/receipt/v1", [dealId, dealSeal, shipmentHash, manifestRoot, u8 condition, u32 ledger]). */
export const rcptMsg = (f: ReceiptFields): Uint8Array => tupleHash(RECEIPT_TAG, rcptParts(f));

export type ShipmentError =
  | 'MALFORMED'
  | 'MSG_HASH_MISMATCH'
  | 'BAD_SIGNATURE'
  | 'LEDGER_AFTER_GATE'
  | 'LEDGER_TOO_OLD';
export type ReceiptError =
  | Exclude<ShipmentError, 'LEDGER_TOO_OLD'>
  | 'SHIPMENT_MISMATCH'
  | 'MANIFEST_MISMATCH'
  | 'LEDGER_BEFORE_SHIPMENT';
export type ShipmentResult =
  | { readonly ok: true; readonly hash: Uint8Array; readonly manifestRoot: Uint8Array; readonly ledgerIndex: number }
  | { readonly ok: false; readonly code: ShipmentError };
export type ReceiptResult =
  | { readonly ok: true; readonly condition: Condition; readonly ledgerIndex: number }
  | { readonly ok: false; readonly code: ReceiptError };

export interface DealContext {
  readonly dealId: string;
  readonly dealSeal: Uint8Array;
  /** The sealed 33-byte slot key: xPubB for a shipment, xPubA for a receipt. */
  readonly slotPub: Uint8Array;
  /** The validated ledger the check runs at (the gate's ledger, or the coordinator's latest validated index). */
  readonly atLedger: number;
}

/** Checks the message hash and the strict slot signature over a rebuilt message (shared by both verifiers). */
function signedBy(msg: Uint8Array, msgHashHex: string, sigHex: string, slotPub: Uint8Array) {
  if (bytesToHex(sha256(msg)) !== msgHashHex) return 'MSG_HASH_MISMATCH' as const;
  return verifyEd25519Strict(hexToBytes(sigHex), msg, slotPub) ? undefined : ('BAD_SIGNATURE' as const);
}

/**
 * A `shipment.signed` event's data: shipMsg rebuilt from the fields and the deal, signed by the sealed slot B key, at
 * a ledger not later than `atLedger` (and, with `maxAge`, at most that many ledgers older). Never throws.
 * Source: build/SHIP_RECEIPT.md 2, 4 (SHIPMENT_SIGNED_OK)
 */
export function verifyShipment(data: unknown, ctx: DealContext & { readonly maxAge?: number }): ShipmentResult {
  const p = ShipmentSigned.safeParse(data);
  if (!p.success) return { ok: false, code: 'MALFORMED' };
  const d = p.data;
  try {
    const f = {
      dealId: ctx.dealId,
      dealSeal: ctx.dealSeal,
      manifestRoot: hexToBytes(d.manifest_root),
      carrier: d.carrier,
      trackingId: d.tracking_id,
      ledgerIndex: d.ledger_index,
    };
    const msg = shipMsg(f);
    const bad = signedBy(msg, d.ship_msg_hash, d.slot_sig, ctx.slotPub);
    if (bad) return { ok: false, code: bad };
    if (d.ledger_index > ctx.atLedger) return { ok: false, code: 'LEDGER_AFTER_GATE' };
    if (ctx.maxAge !== undefined && ctx.atLedger - d.ledger_index > ctx.maxAge)
      return { ok: false, code: 'LEDGER_TOO_OLD' };
    return { ok: true, hash: sha256(msg), manifestRoot: f.manifestRoot, ledgerIndex: d.ledger_index };
  } catch {
    return { ok: false, code: 'MALFORMED' };
  }
}

/**
 * A `receipt.signed` event's data: rcptMsg rebuilt from the fields and the deal, signed by the sealed slot A key,
 * naming this shipment's hash and manifest root, at a ledger between the shipment's and `atLedger`. The condition is
 * returned, not judged: the gate requires `ok`, the UI offers the dispute path otherwise. Never throws.
 * Source: build/SHIP_RECEIPT.md 3, 4 (RECEIPT_SIGNED_OK)
 */
export function verifyReceipt(
  data: unknown,
  ctx: DealContext & {
    readonly shipment: { readonly hash: Uint8Array; readonly manifestRoot: Uint8Array; readonly ledgerIndex: number };
  },
): ReceiptResult {
  const p = ReceiptSigned.safeParse(data);
  if (!p.success) return { ok: false, code: 'MALFORMED' };
  const d = p.data;
  try {
    const msg = rcptMsg({
      dealId: ctx.dealId,
      dealSeal: ctx.dealSeal,
      shipmentHash: hexToBytes(d.shipment_hash),
      manifestRoot: hexToBytes(d.manifest_root),
      condition: d.condition,
      ledgerIndex: d.ledger_index,
    });
    const bad = signedBy(msg, d.rcpt_msg_hash, d.slot_sig, ctx.slotPub);
    if (bad) return { ok: false, code: bad };
    if (d.shipment_hash !== bytesToHex(ctx.shipment.hash)) return { ok: false, code: 'SHIPMENT_MISMATCH' };
    if (d.manifest_root !== bytesToHex(ctx.shipment.manifestRoot)) return { ok: false, code: 'MANIFEST_MISMATCH' };
    if (d.ledger_index < ctx.shipment.ledgerIndex) return { ok: false, code: 'LEDGER_BEFORE_SHIPMENT' };
    if (d.ledger_index > ctx.atLedger) return { ok: false, code: 'LEDGER_AFTER_GATE' };
    return { ok: true, condition: d.condition, ledgerIndex: d.ledger_index };
  } catch {
    return { ok: false, code: 'MALFORMED' };
  }
}
