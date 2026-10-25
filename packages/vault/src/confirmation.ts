// What the user is shown before the vault signs a shipment or a receipt (OD-37, build/SHIP_RECEIPT.md 2 and 3). The text is
// decoded here from the exact tupleHash parts the vault is about to sign, never taken from the page.

import type { SignRequest } from '@legx/core/frostRules';
import { bytesToHex } from '@noble/hashes/utils.js';

export type Confirmation = {
  kind: 'shipment' | 'receipt';
  manifestRoot: string;
  /** Shipment only. */
  carrier?: string;
  trackingId?: string;
  /** Receipt only. */
  condition?: 'ok' | 'damaged' | 'missing';
};

const CONDITIONS = ['ok', 'damaged', 'missing'] as const;
const utf8 = (b: Uint8Array | undefined) => new TextDecoder().decode(b);

/** The confirmation for a tagged request that needs one, or undefined for every other request. */
export function confirmationFor(req: SignRequest): Confirmation | undefined {
  if (req.kind !== 'tagged') return undefined;
  const p = req.parts;
  if (req.tag === 'legx/shipment/v1')
    return {
      kind: 'shipment',
      manifestRoot: bytesToHex(p[2] ?? new Uint8Array()),
      carrier: utf8(p[3]),
      trackingId: utf8(p[4]),
    };
  if (req.tag === 'legx/receipt/v1')
    return {
      kind: 'receipt',
      manifestRoot: bytesToHex(p[3] ?? new Uint8Array()),
      condition: CONDITIONS[p[4]?.[0] ?? 0] ?? 'missing',
    };
  return undefined;
}
