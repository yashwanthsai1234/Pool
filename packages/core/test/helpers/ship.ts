// OD-37 test data: a signed shipment (slot B) and a receipt bound to it (slot A), for the gate worlds.
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  type Condition,
  manifestRoot,
  RECEIPT_TAG,
  rcptMsg,
  rcptParts,
  SHIPMENT_TAG,
  type ShipmentFields,
  shipMsg,
  shipmentHash,
  shipParts,
} from '../../src/shipment.ts';

export const MANIFEST = [
  { sku: 'BOLT-M8', description: 'Steel bolts, M8, zinc', qty: 200, weight_g: 9 },
  { sku: 'CUP-01', description: 'Café cups', qty: 12, weight_g: 300 },
];
/** Signs a tagged message; `parts` lets a FROST slot run its allow-list on the preimage. */
type Sign = (msg: Uint8Array, tag: string, parts: Uint8Array[]) => Uint8Array;
type Json = Record<string, unknown>;

/** Builders for `shipment.signed` and `receipt.signed` data; `over` replaces signed inputs before signing. */
export function shipBuilders(dealId: string, dealSeal: Uint8Array, gateLedger: number) {
  const shipFields = (over: Partial<ShipmentFields> = {}): ShipmentFields => ({
    dealId,
    dealSeal,
    manifestRoot: manifestRoot(MANIFEST),
    carrier: 'DHL Express',
    trackingId: 'JD014600006281230704',
    ledgerIndex: gateLedger - 10,
    ...over,
  });
  const shipmentData = (sign: Sign, over: Partial<ShipmentFields> = {}): Json => {
    const f = shipFields(over);
    const msg = shipMsg(f);
    const sig = sign(msg, SHIPMENT_TAG, shipParts(f));
    return {
      manifest_root: bytesToHex(f.manifestRoot),
      carrier: f.carrier,
      tracking_id: f.trackingId,
      ledger_index: f.ledgerIndex,
      ship_msg_hash: bytesToHex(shipmentHash(f)),
      slot_sig: bytesToHex(sig),
    };
  };
  const receiptData = (
    sign: Sign,
    over: { condition?: Condition; ledgerIndex?: number; shipment?: Partial<ShipmentFields>; root?: Uint8Array } = {},
  ): Json => {
    const s = shipFields(over.shipment);
    const f = {
      dealId,
      dealSeal,
      shipmentHash: shipmentHash(s),
      manifestRoot: over.root ?? s.manifestRoot,
      condition: over.condition ?? 'ok',
      ledgerIndex: over.ledgerIndex ?? gateLedger - 5,
    };
    const msg = rcptMsg(f);
    const sig = sign(msg, RECEIPT_TAG, rcptParts(f));
    return {
      shipment_hash: bytesToHex(f.shipmentHash),
      manifest_root: bytesToHex(f.manifestRoot),
      condition: f.condition,
      ledger_index: f.ledgerIndex,
      rcpt_msg_hash: bytesToHex(sha256(msg)),
      slot_sig: bytesToHex(sig),
    };
  };
  return { shipFields, shipmentData, receiptData };
}
