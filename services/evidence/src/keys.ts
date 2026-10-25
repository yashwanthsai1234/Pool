// The key registry the hybrid verifier needs, built from the append-only `enrollment_key` rows of one deal plus the
// service's own keys (DESIGN 6.3, 8.1). A row is one holder key with both public keys under one `key_id`: the Ed25519
// half is named `key_id#ed25519` and the ML-DSA-65 half `key_id#ml-dsa-65`, the same convention as the coordinator (DQ-3.2-1,
// I-3.7-e), so a DSSE signature's `keyid` finds its key and a client signs the same ids on every route.

import type { HybridPublicKeys } from '@legx/contracts/ports';
import { ED_SUFFIX, PQ_SUFFIX } from '@legx/coordinator/keys';
import type { KeyRegistry, RegisteredKey } from '@legx/core/hybridEnvelope';
import type { EnrollmentKeyRow } from '@legx/db/repos/identity';

/** Rows only exist if the key's hash was logged first (`evidence_event_id` NOT NULL), so every key is `logged`. */
export function registryFromRows(
  rows: readonly EnrollmentKeyRow[],
  service?: { readonly keys: HybridPublicKeys; readonly validFrom: number },
): KeyRegistry {
  const map = new Map<string, RegisteredKey>();
  const window = (r: { key_id: string; valid_from: number; valid_to?: number }) => ({
    pair: r.key_id,
    validFrom: r.valid_from,
    ...(r.valid_to === undefined ? {} : { validTo: r.valid_to }),
    logged: true,
  });
  for (const r of rows) {
    map.set(r.key_id + ED_SUFFIX, {
      alg: 'ed25519',
      publicKey: Uint8Array.from(Buffer.from(r.ed25519_pub, 'hex')),
      ...window(r),
    });
    map.set(r.key_id + PQ_SUFFIX, {
      alg: 'ml-dsa-65',
      publicKey: Uint8Array.from(Buffer.from(r.mldsa65_pub, 'base64')),
      ...window(r),
    });
  }
  if (service) {
    const w = { validFrom: service.validFrom, logged: true, pair: `service:${service.keys.keyIds.ed25519}` };
    map.set(service.keys.keyIds.ed25519, { alg: 'ed25519', publicKey: service.keys.ed25519, ...w });
    map.set(service.keys.keyIds.mlDsa65, { alg: 'ml-dsa-65', publicKey: service.keys.mlDsa65, ...w });
  }
  return (keyId) => map.get(keyId);
}
