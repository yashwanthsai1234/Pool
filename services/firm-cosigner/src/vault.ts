// The HSM's share store (DESIGN 6.4 "Signing rules": a server holder keeps its share encrypted and its nonces never
// leave it). It is the recovery agent's `ShareVault` (one implementation, I-26) over the `firm_cosigner_share` table,
// as holder 2. The wrapping key is not an operator-supplied secret: it is derived from the HSM's own `SignerPort`,
// whose private key never leaves the HSM, by signing a fixed label with Ed25519 (deterministic, RFC 8032) and running
// HKDF over the signature. Whoever can use the HSM key can unwrap; a copy of the database alone cannot.
// Source: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6 (Ed25519 signatures are deterministic)
// Source: https://www.rfc-editor.org/rfc/rfc5869 (HKDF)
import type { SignerPort } from '@legx/contracts/ports';
import { utf8ToBytes } from '@legx/core/dealcore';
import type { Database } from '@legx/db';
import { ShareVault, type VaultSpec } from '@legx/recovery-agent/vault';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

/** The HSM is always holder 2 of a lawyer slot (canonical order: console, firm HSM, partner). */
export const HSM_INDEX = 2;
const WRAP_LABEL = 'legx/firm-cosigner/vault-wrap/v1';
const FIRM_VAULT: VaultSpec = {
  table: 'firm_cosigner_share',
  holderIndex: HSM_INDEX,
  label: 'legx/firm-cosigner/share/v1',
};

export async function wrapKeyFrom(signer: SignerPort): Promise<Uint8Array> {
  const sig = await signer.signHybrid(utf8ToBytes(WRAP_LABEL), 'legx/dsse/v1');
  return hkdf(sha256, sig.ed25519, undefined, utf8ToBytes(WRAP_LABEL), 32);
}

export class FirmShareVault extends ShareVault {
  constructor(db: Database, wrapKey: Uint8Array) {
    super(db, wrapKey, FIRM_VAULT);
  }
}
