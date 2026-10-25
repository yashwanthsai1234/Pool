// @legx/vault: the browser key vault for FROST slot shares (DESIGN 6.4, IMPLEMENTATION 4.2).

export type { CeremonyHost } from './ceremony.ts';
export { VAULT_CSP } from './csp.ts';
export { enrollmentKeys, type PqHalf } from './enrollment.ts';
export { type VaultCode, VaultError } from './errors.ts';
export { type EnrollResult, type FrameHost, type SignApiInput, vaultFrameHost } from './frame-host.ts';
export { apiRequestSigner } from './pq/apiRequest.ts';
export { type ObserverKey, observerSigner } from './pq/observer.ts';
export { type AuthenticatorKind, type PrfCredential, type PrfSource, webauthnPrf } from './prf.ts';
export { connectCoSigner, connectVault, isVaultMessage, serveCoSigner, serveVault } from './protocol.ts';
export {
  assertShareRecipient,
  type ClientShareRecipient,
  holderRoles,
  NEVER_TO_LAWYER,
  type Share2Mode,
  SINGLE_DEVICE_LABEL,
} from './rules.ts';
export type { ShellInfo } from './shell.ts';
export {
  type CoSignerPort,
  createVault,
  type EntrySummary,
  type Share2Input,
  type StorageContext,
  type Vault,
  type VaultDeps,
} from './vault.ts';
