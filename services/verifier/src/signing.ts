// Hybrid envelopes for the verifier's two records (DESIGN 6.16, 6.13). Signing goes only through SignerPort, so the
// service never holds a key. Both signatures cover the same PAE bytes; a half signature cannot be produced.
import type { SignerPort } from '@legx/contracts/ports';
import { ATTEST_PAYLOAD_TYPE } from '@legx/contracts/records';
import type { BarTrust } from '@legx/core/bar';
import type { Envelope } from '@legx/core/evidence';
import { type RegisteredKey, signHybrid, verifyHybrid } from '@legx/core/hybridEnvelope';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

export interface SignedRecord {
  readonly envelope: Envelope;
  /** The exact stored DSSE bytes. Every hash in the system is taken over these, never over a re-serialization. */
  readonly bytes: Uint8Array;
  readonly sha256: string;
  readonly keyIds: { readonly ed25519: string; readonly mlDsa65: string };
}

/** Signs an attestation payload (BarVerification or BarDealLink, already schema-checked by the caller). */
export async function signAttestation(signer: SignerPort, payload: object): Promise<SignedRecord> {
  const envelope = await signHybrid(ATTEST_PAYLOAD_TYPE, utf8ToBytes(JSON.stringify(payload)), signer);
  const bytes = utf8ToBytes(JSON.stringify(envelope));
  const { keyIds } = await signer.publicKeys();
  return { envelope, bytes, sha256: bytesToHex(sha256(bytes)), keyIds };
}

/** What the gate will trust: this signer's two public keys. Used for the self-check after every signature. */
export async function verifierTrust(signer: SignerPort): Promise<BarTrust> {
  const keys = await signer.publicKeys();
  const pair = `service:${keys.keyIds.ed25519}`;
  const entries = new Map<string, RegisteredKey>([
    [keys.keyIds.ed25519, { alg: 'ed25519', publicKey: keys.ed25519, validFrom: 0, logged: true, pair }],
    [keys.keyIds.mlDsa65, { alg: 'ml-dsa-65', publicKey: keys.mlDsa65, validFrom: 0, logged: true, pair }],
  ]);
  return {
    verifierKeyIds: keys.keyIds,
    verify: (env) => verifyHybrid(env, (id) => entries.get(id), 0),
  };
}
