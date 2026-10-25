// Fee math in drops. Mirrors rippled: base * (33 + floor(fulfillmentBytes/16)) + base * signers.
export function escrowFinishFee(baseDrops: number, fulfillmentBytes: number, signers: number): number {
  return baseDrops * (33 + Math.floor(fulfillmentBytes / 16)) + baseDrops * signers;
}
export function multisigFee(baseDrops: number, signers: number): number { return baseDrops * (1 + signers); }
// Ripple epoch helpers. CancelAfter is compared with the parent ledger close time, not wall clock.
export const RIPPLE_EPOCH = 946684800;
export const toRipple = (unix: number) => unix - RIPPLE_EPOCH;
export const fromRipple = (r: number) => r + RIPPLE_EPOCH;
