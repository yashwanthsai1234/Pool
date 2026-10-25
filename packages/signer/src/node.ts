// Signers on Node 24's built-in Ed25519 and ML-DSA. Every ML-DSA call passes its context explicitly: Node defaults
// to the empty context, so a forgotten option would sign something any other use accepts (DESIGN 6.13).
// Source: https://nodejs.org/docs/latest-v24.x/api/crypto.html#cryptosignalgorithm-data-key-callback (`context` option)
// Source: https://csrc.nist.gov/pubs/fips/204/final

import { createPublicKey, generateKeyPairSync, type KeyObject, sign } from 'node:crypto';
import type {
  CheckpointSignature,
  CheckpointSignerPort,
  HybridSignature,
  MlDsaContext,
  SignerPort,
} from '@legx/contracts/ports';
import type { KeyId } from '@legx/contracts/values';

const ED25519_SPKI_PREFIX_LENGTH = 12; // 302a300506032b6570032100
const MLDSA_SPKI_PREFIX_LENGTH = 22; // 308207b2300b0609608648016503040312038207a100 (ML-DSA-65); 44 differs only in lengths

/** The empty context of the C2SP 0x06 cosignature (mirrors `C2SP_0X06_CONTEXT` in `@legx/core/pq`). */
const EMPTY_CONTEXT = Buffer.alloc(0);

const rawPublic = (key: KeyObject, prefixLength: number): Uint8Array => {
  const der = createPublicKey(key).export({ format: 'der', type: 'spki' });
  return new Uint8Array(der.subarray(prefixLength));
};

const mldsa = (privateKey: KeyObject, msg: Uint8Array, context: Buffer): Uint8Array =>
  new Uint8Array(sign(null, msg, { key: privateKey, context }));

export interface NodeSignerKeys {
  readonly ed25519: { readonly keyId: KeyId; readonly privateKey: KeyObject };
  readonly mlDsa65: { readonly keyId: KeyId; readonly privateKey: KeyObject };
}

export interface NodeCheckpointKeys {
  readonly ed25519: { readonly keyId: KeyId; readonly privateKey: KeyObject };
  readonly mlDsa44: { readonly keyId: KeyId; readonly privateKey: KeyObject };
}

/** Hybrid `SignerPort` over Node's own crypto: Ed25519 plus ML-DSA-65 under the context the caller names. */
export function nodeSigner(keys: NodeSignerKeys): SignerPort {
  const keyIds = { ed25519: keys.ed25519.keyId, mlDsa65: keys.mlDsa65.keyId };
  return {
    async signHybrid(msg: Uint8Array, ctx: MlDsaContext): Promise<HybridSignature> {
      return {
        ed25519: new Uint8Array(sign(null, msg, keys.ed25519.privateKey)),
        mlDsa65: mldsa(keys.mlDsa65.privateKey, msg, Buffer.from(ctx, 'utf8')),
        keyIds,
      };
    },
    async publicKeys() {
      return {
        ed25519: rawPublic(keys.ed25519.privateKey, ED25519_SPKI_PREFIX_LENGTH),
        mlDsa65: rawPublic(keys.mlDsa65.privateKey, MLDSA_SPKI_PREFIX_LENGTH),
        keyIds,
      };
    },
  };
}

/** The log's checkpoint signer: Ed25519 over the note body, ML-DSA-44 over the CosignedSubtree, empty context. */
export function nodeCheckpointSigner(keys: NodeCheckpointKeys): CheckpointSignerPort {
  const keyIds = { ed25519: keys.ed25519.keyId, mlDsa44: keys.mlDsa44.keyId };
  return {
    async signCheckpoint(input): Promise<CheckpointSignature> {
      return {
        ed25519: new Uint8Array(sign(null, input.noteBody, keys.ed25519.privateKey)),
        mlDsa44: mldsa(keys.mlDsa44.privateKey, input.cosignedSubtree, EMPTY_CONTEXT),
        keyIds,
      };
    },
    async publicKeys() {
      return {
        ed25519: rawPublic(keys.ed25519.privateKey, ED25519_SPKI_PREFIX_LENGTH),
        mlDsa44: rawPublic(keys.mlDsa44.privateKey, MLDSA_SPKI_PREFIX_LENGTH),
        keyIds,
      };
    },
  };
}

/** Fresh random keys: for tests and for the first start of the demo profile. */
export function generateNodeSignerKeys(ed25519Id: KeyId, mlDsa65Id: KeyId): NodeSignerKeys {
  return {
    ed25519: { keyId: ed25519Id, privateKey: generateKeyPairSync('ed25519').privateKey },
    mlDsa65: { keyId: mlDsa65Id, privateKey: generateKeyPairSync('ml-dsa-65').privateKey },
  };
}

export function generateNodeCheckpointKeys(ed25519Id: KeyId, mlDsa44Id: KeyId): NodeCheckpointKeys {
  return {
    ed25519: { keyId: ed25519Id, privateKey: generateKeyPairSync('ed25519').privateKey },
    mlDsa44: { keyId: mlDsa44Id, privateKey: generateKeyPairSync('ml-dsa-44').privateKey },
  };
}
