// Each lawyer half has its own vault namespace (P4.4-09): its own IndexedDB and its own role in every entry name, so
// lawyer A's half can neither see nor use lawyer B's shares on the same laptop.
// Source: IMPLEMENTATION 4.4 "Think" (separate vault namespaces); packages/vault (createVault, one IndexedDB per partition)
import { createVault, type Vault, type VaultDeps } from '@legx/vault';
import type { Role } from './ports.ts';

export const LAWYER_VAULT_DB: Readonly<Record<Role, string>> = {
  LA: 'legx-vault-lawyer-a',
  LB: 'legx-vault-lawyer-b',
};

export const lawyerVault = (role: Role, deps: Omit<VaultDeps, 'role' | 'dbName'>): Vault =>
  createVault({ ...deps, role: role === 'LA' ? 'lawyerA' : 'lawyerB', dbName: LAWYER_VAULT_DB[role] });

/** The operations account keys of each half (non-extractable WebCrypto keys, one per deal): this origin's own database. */
export const LAWYER_OPS_DB: Readonly<Record<Role, string>> = {
  LA: 'legx-ops-lawyer-a',
  LB: 'legx-ops-lawyer-b',
};
