// A holder's enrollment keys as the relay code signs with them (DESIGN 6.3): the vault's non-extractable WebCrypto
// Ed25519 key (task 4.2) plus the ML-DSA-65 half (task 4.9, through `PqHalf`), both over the same relay bytes.
import type { Role } from '@legx/core/frost';
import type { enrollmentKeys, PqHalf } from '../enrollment.ts';
import { type HolderInfo, type PartyKeys, RELAY_CONTEXT } from './wire.ts';

/** This device's keys for one deal, and the `HolderInfo` the other holders pin. */
export async function vaultPartyKeys(input: {
  enrollment: ReturnType<typeof enrollmentKeys>;
  dealId: string;
  keyId: string;
  pq: PqHalf;
  identifier: string;
  role: Role;
  deviceId: string;
  label: string;
}): Promise<{ keys: PartyKeys; info: HolderInfo }> {
  const raw = await input.enrollment.create(input.dealId);
  const edPub = new Uint8Array(33);
  edPub[0] = 0xed;
  edPub.set(raw, 1);
  return {
    keys: {
      keyId: input.keyId,
      signEd: (msg) => input.enrollment.sign(input.dealId, msg),
      signPq: (msg) => input.pq.sign(msg, RELAY_CONTEXT),
    },
    info: {
      identifier: input.identifier,
      keyId: input.keyId,
      role: input.role,
      edPub,
      pqPub: input.pq.publicKey,
      deviceId: input.deviceId,
      label: input.label,
    },
  };
}
