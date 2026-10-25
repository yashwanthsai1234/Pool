// Who holds share 2, which modes fit which role, the single-device label, and the rule that a client's share
// never goes to the client's own lawyer (DESIGN 6.4; IMPLEMENTATION 4.2 "Think hard"; OD-17 role names).
import type { Role as PartyRole } from '@legx/contracts/values';
import type { Role as HolderRole, SlotName } from '@legx/core/frost';
import { VaultError } from './errors.ts';

export type { PartyRole };

/** Where share 2 lives, seen from the slot's primary device (the phone or the lawyer's console). */
export type Share2Mode =
  | 'security-key' // a FIDO2 security key with PRF unlocks share 2 for one signature
  | 'single-device' // a passkey on the same phone unlocks it: labeled, no theft protection
  | 'recovery-code' // the authenticator has no PRF: a recovery code the client keeps off the phone unlocks it
  | 'second-device' // the client's second device holds share 2 and signs its own share after an approval
  | 'firm-hsm'; // a lawyer slot: the firm's HSM service holds share 2 and signs after the lawyer's approval

/** Shown on the share screen, in the DKG summary and in the deal record (P4.2-15). */
export const SINGLE_DEVICE_LABEL = 'Single-device mode: no protection if this phone is stolen';
/** Shown on the share screen (P4.2-10). */
export const NEVER_TO_LAWYER = 'Never give a share to your own lawyer';

export const SLOT_OF: Readonly<Record<PartyRole, SlotName>> = { alice: 'A', bob: 'B', lawyerA: 'LA', lawyerB: 'LB' };

const CLIENT_MODES: readonly Share2Mode[] = ['security-key', 'single-device', 'recovery-code', 'second-device'];
const isClientRole = (role: PartyRole): boolean => role === 'alice' || role === 'bob';

/** Client roles take the client modes; lawyer roles take only `firm-hsm`. */
export function checkModeForRole(role: PartyRole, mode: Share2Mode): void {
  if (CLIENT_MODES.includes(mode) !== isClientRole(role)) throw new VaultError('ROLE_REFUSED');
}

/** The holder roles for `slotPolicy` (task 1.15): the mode is part of the slot's recorded setup (P4.2-15). */
export function holderRoles(mode: Share2Mode): HolderRole[] {
  if (mode === 'firm-hsm') return ['console', 'firm-hsm', 'partner'];
  if (mode === 'single-device') return ['phone', 'passkey-same-device', 'recovery-agent'];
  return ['phone', 'second-authenticator', 'recovery-agent'];
}

/** The only holders a client share may be sent to (task 4.7 DKG and repair). A lawyer role is not in the type. */
export type ClientShareRecipient = 'phone' | 'second-authenticator' | 'passkey-same-device' | 'recovery-agent';
const CLIENT_RECIPIENTS: readonly string[] = ['phone', 'second-authenticator', 'passkey-same-device', 'recovery-agent'];

/** Run-time half of P4.2-10: refuses any recipient outside the client's own holders (for example `console`). */
export function assertShareRecipient(to: ClientShareRecipient): void {
  if (!CLIENT_RECIPIENTS.includes(to)) throw new VaultError('ROLE_REFUSED');
}
