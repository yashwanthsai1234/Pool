// The key naming convention for hybrid pairs. An `enrollment_key` row holds both public keys under one pair id, but a
// DSSE signature names one key. So a signature's `keyid` is `<pairId>#ed25519` or `<pairId>#ml-dsa-65` (DQ-3.2-1).

import type { Role, Slot } from '@legx/contracts/values';
import type { RegisteredKey } from '@legx/core/hybridEnvelope';
import type { EnrollmentKeyRow } from '@legx/db/repos/identity';

export const ED_SUFFIX = '#ed25519';
export const PQ_SUFFIX = '#ml-dsa-65';

/** The pair id of a signature key id, or undefined when it has neither suffix. */
export function pairIdOf(keyId: string, half: 'ed25519' | 'ml-dsa-65'): string | undefined {
  const suffix = half === 'ed25519' ? ED_SUFFIX : PQ_SUFFIX;
  return keyId.endsWith(suffix) && keyId.length > suffix.length ? keyId.slice(0, -suffix.length) : undefined;
}

/** The deal role a slot's holders act as. */
export const ROLE_OF_SLOT: Readonly<Record<Slot, Role>> = { A: 'alice', LA: 'lawyerA', B: 'bob', LB: 'lawyerB' };
export const SLOT_OF_ROLE: Readonly<Record<Role, Slot>> = { alice: 'A', lawyerA: 'LA', bob: 'B', lawyerB: 'LB' };

const b64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));
const hex = (s: string) => new Uint8Array(Buffer.from(s, 'hex'));

/** A `KeyRegistry` (core) over the deal's `enrollment_key` rows. Every row in the table was logged before use (3.1). */
export function registryOf(rows: readonly EnrollmentKeyRow[]) {
  const reg = new Map<string, RegisteredKey>();
  for (const r of rows) {
    const common = {
      validFrom: r.valid_from,
      ...(r.valid_to === undefined ? {} : { validTo: r.valid_to }),
      logged: true,
      pair: r.key_id,
    };
    reg.set(r.key_id + ED_SUFFIX, { ...common, alg: 'ed25519', publicKey: hex(r.ed25519_pub) });
    reg.set(r.key_id + PQ_SUFFIX, { ...common, alg: 'ml-dsa-65', publicKey: b64(r.mldsa65_pub) });
  }
  return (keyId: string) => reg.get(keyId);
}
