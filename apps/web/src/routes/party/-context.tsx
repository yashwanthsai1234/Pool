// What the party app needs from outside: the signed API client, the key vault (task 4.2), the coordinator's validated
// ledger relay, and the lawyer's presence request. The `-` prefix keeps this file out of the route tree.
// Source: https://tanstack.com/router/latest/docs/framework/react/routing/file-naming-conventions (routeFileIgnorePrefix)
import type { Role } from '@legx/contracts/values';
import type { ChainEntry, EnvelopeCheck } from '@legx/core/evidence';
import type { Vault } from '@legx/vault';
import { createContext, type ReactNode, useContext } from 'react';
import type { ApiClient } from '../../lib/api.ts';

/** The lawyer's request to prove presence (DESIGN 6.15), as the coordinator relays it. All hex is lowercase. */
export type PresenceRequest = {
  method: 'zkpassport' | 'nfc-chip';
  lawyerNonce: string;
  ledgerHash: string;
  ledgerIndex: number;
};

export type PartyServices = {
  dealId: string;
  role: Extract<Role, 'alice' | 'bob'>;
  api: ApiClient;
  vault: Pick<Vault, 'signMultisig' | 'signFrost'>;
  /** The coordinator's validated `account_info` relay (flags only). */
  accountInfo: (address: string) => Promise<{ flags: number } | undefined>;
  /** Checks one stored envelope's signatures against the pinned keys of the deal. */
  checkEnvelope: EnvelopeCheck;
  /** The validated ledger index of a transaction hash, from the phone's own view of the ledger. */
  ledgerIndexOf: (txHash: string) => number | undefined;
  /** Loads what `checkEnvelope` and `ledgerIndexOf` need for these records (the pinned keys, the ledger). Optional in tests. */
  prepareEnvelopes?: (entries: ChainEntry[]) => Promise<void>;
  presenceRequest: () => Promise<PresenceRequest>;
  /** Sends the presence signature to the lawyer (an evidence event, task 3.4). */
  submitPresence: (p: { signature: string; ledgerIndex: number }) => Promise<void>;
  /** Alice only: makes the shell key on the phone and returns its address (the secret never leaves the vault). Absent when the host cannot. */
  createShellKey?: () => Promise<string>;
  /** Alice only: signs steps 5a to 5g of the lock with the shell key in the frame. Absent when the host cannot. */
  runLockSetup?: (
    onStep: (s: { id: string; status: 'running' | 'done' | 'failed'; detail?: string }) => void,
  ) => Promise<void>;
  /** Absent when the host cannot accept the badge: the screen then says your lawyer does it. */
  acceptBadge?: () => Promise<void>;
};

const Ctx = createContext<PartyServices | undefined>(undefined);
export const PartyProvider = ({ value, children }: { value: PartyServices; children: ReactNode }) => (
  <Ctx.Provider value={value}>{children}</Ctx.Provider>
);
export const useParty = (): PartyServices | undefined => useContext(Ctx);
export const usePartyStrict = (): PartyServices => {
  const s = useContext(Ctx);
  if (!s) throw new Error('PartyProvider missing');
  return s;
};
