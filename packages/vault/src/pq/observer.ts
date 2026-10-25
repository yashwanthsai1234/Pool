// The projector's observer key (OD-31, DESIGN 6.3): a hybrid enrollment key made at demo seeding, pinned like any
// holder key, allowed only to subscribe to the live feed and call read routes. This signer produces API-request
// signatures and nothing else: no other ML-DSA context is accepted, so the key can never sign evidence or money.
// The seeding writes both private keys as PKCS#8 DER hex; both are seed-only forms, so the last 32 bytes are the seed.
// Source: RFC 8410 section 7 (Ed25519 PKCS#8: 48 bytes); RFC 9881 (ML-DSA PKCS#8 seed-only form: 54 bytes);
//         build/DECISIONS.md OD-31
import type { KeyId } from '@legx/contracts/values';
import { mldsaSign } from '@legx/core/pq';
import { ed25519 } from '@noble/curves/ed25519.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { VaultError } from '../errors.ts';
import type { HybridRaw } from './keys.ts';

export interface ObserverKey {
  /** The pair id the coordinator registered: its halves are `<keyId>#ed25519` and `<keyId>#ml-dsa-65`. */
  keyId: string;
  ed25519Pkcs8: string;
  mlDsa65Pkcs8: string;
}

const ED_PREFIX = '302e020100300506032b657004220420';
const PQ_PREFIX = '3034020100300b060960864801650304031204228020';

function seedOf(pkcs8Hex: string, prefix: string, total: number): Uint8Array {
  if (!/^[0-9a-f]+$/i.test(pkcs8Hex) || pkcs8Hex.length !== total * 2 || !pkcs8Hex.toLowerCase().startsWith(prefix))
    throw new VaultError('INPUT_INVALID');
  return hexToBytes(pkcs8Hex.slice(-64));
}

export function observerSigner(key: ObserverKey): HybridRaw {
  const edSeed = seedOf(key.ed25519Pkcs8, ED_PREFIX, 48);
  const pqSecret = ml_dsa65.keygen(seedOf(key.mlDsa65Pkcs8, PQ_PREFIX, 54)).secretKey;
  const keyIds = {
    ed25519: `${key.keyId}#ed25519` as KeyId,
    mlDsa65: `${key.keyId}#ml-dsa-65` as KeyId,
  };
  return async (msg, ctx) => {
    if (ctx !== 'legx/api-request/v1') throw new VaultError('INPUT_INVALID');
    return {
      ed25519: ed25519.sign(msg, edSeed),
      mlDsa65: mldsaSign('ml-dsa-65', pqSecret, msg, ctx as never),
      keyIds,
    };
  };
}
