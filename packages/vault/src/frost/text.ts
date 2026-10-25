// What the FROST screens show and the delay countdown: no dependencies, so a route chunk that shows them does not pull
// in the signing code (xrpl and its WASM stay out of the phone route, P4.1-06). The logic stays in the other modules.
import type { RotationStep } from '@legx/core/frostRules';

/** Shown on every refresh screen (DESIGN 6.4). */
export const HYGIENE_NOTE =
  'A refresh is hygiene, not revocation: old shares still work together until every holder has deleted them. If a share was stolen, rotate the key instead.';

/** Who is told about a recovery (DESIGN 6.4), as the screen says it. */
export const NOTIFIED = ['your old device', 'Lawyer A', 'Lawyer B'] as const;

/** The recovery status the coordinator returns (contracts `RecoveryStatus`). `readyAt` is in Ripple seconds. */
export type RecoveryStatus = {
  recoveryId: string;
  dealId: string;
  slot: string;
  state: 'waiting' | 'ready' | 'cancelled' | 'done';
  readyAt: number;
};

/** Ripple epoch (2000-01-01T00:00:00Z) in Unix milliseconds. */
export const RIPPLE_EPOCH_MS = 946_684_800_000;
export const rippleToMs = (t: number): number => t * 1000 + RIPPLE_EPOCH_MS;

/** The delay left, by ledger time, as the screen shows it ("71 h 59 min"); zero once the delay is over. */
export function remaining(status: RecoveryStatus, ledgerNowMs: number): { ms: number; text: string } {
  const ms = Math.max(0, rippleToMs(status.readyAt) - ledgerNowMs);
  const min = Math.ceil(ms / 60_000);
  return { ms, text: `${Math.floor(min / 60)} h ${String(min % 60).padStart(2, '0')} min` };
}

/** The rotation steps as the screen names them (core's `rotationPlan` decides which apply). */
export const STEP_TITLE: Record<RotationStep, string> = {
  repair: 'Repair the lost share',
  refresh: 'Refresh all shares',
  'new-dkg': 'Make a new slot key (new DKG)',
  'signer-list-set-4-of-4': 'Replace the key on the ledger (4-of-4 SignerListSet)',
  'new-seal': 'Seal the deal again with the new key',
  'new-contract-signatures': 'Sign the contract again',
  'new-nft': 'Issue the new contract NFT',
};
