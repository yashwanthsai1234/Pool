// KmsSigner: service keys in AWS KMS. Ed25519 is `ECC_NIST_EDWARDS25519` (ED25519_SHA_512, RAW message); ML-DSA-65 is
// `ML_DSA_65` (ML_DSA_SHAKE_256) signed with EXTERNAL_MU: we compute mu ourselves (`muFor`, FIPS 204) so the result is an
// ordinary signature over the PAE bytes under our context string, whatever the message size.
// Source: https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html (MessageType, 4096-byte RAW limit)
// Source: https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html
// Source: https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html (ED25519_SHA_512 needs RAW)
import {
  GetPublicKeyCommand,
  type GetPublicKeyCommandOutput,
  SignCommand,
  type SignCommandOutput,
} from '@aws-sdk/client-kms';
import type { HybridPublicKeys, HybridSignature, MlDsaContext, SignerPort } from '@legx/contracts/ports';
import type { KeyId } from '@legx/contracts/values';
import { mldsaVerify, muFor } from '@legx/core/pq';
import { ed25519 } from '@noble/curves/ed25519.js';

/** KMS signs at most 4096 bytes in RAW mode; ED25519_SHA_512 has no EXTERNAL_MU, so larger messages cannot be signed. */
export const KMS_RAW_LIMIT = 4096;

/** The two calls we make; `KMSClient` satisfies it and tests pass an emulator. */
export interface KmsClientLike {
  send(command: GetPublicKeyCommand): Promise<GetPublicKeyCommandOutput>;
  send(command: SignCommand): Promise<SignCommandOutput>;
}

export interface KmsSignerConfig {
  readonly client: KmsClientLike;
  /** KMS key ID or ARN of the ECC_NIST_EDWARDS25519 key and of the ML_DSA_65 key. */
  readonly kmsKeys: { readonly ed25519: string; readonly mlDsa65: string };
  /** Our key IDs, as registered in `enrollment_key`. */
  readonly keyIds: { readonly ed25519: KeyId; readonly mlDsa65: KeyId };
}

// SubjectPublicKeyInfo headers: RFC 8410 (Ed25519, OID 1.3.101.112) and RFC 9881 (ML-DSA-65, OID 2.16.840.1.101.3.4.3.18).
// Source: https://www.rfc-editor.org/rfc/rfc8410#section-4 and https://www.rfc-editor.org/rfc/rfc9881
const ED25519_SPKI_PREFIX = Uint8Array.from(Buffer.from('302a300506032b6570032100', 'hex'));
const MLDSA65_SPKI_PREFIX = Uint8Array.from(Buffer.from('308207b2300b0609608648016503040312038207a100', 'hex'));

function stripSpki(spki: Uint8Array | undefined, prefix: Uint8Array, keyLength: number, what: string): Uint8Array {
  const ok = spki !== undefined && spki.length === prefix.length + keyLength && prefix.every((b, i) => spki[i] === b);
  if (!ok) throw new Error(`KMS returned an unexpected ${what} public key encoding`);
  return spki.slice(prefix.length);
}

export function kmsSigner(config: KmsSignerConfig): SignerPort {
  const { client, kmsKeys, keyIds } = config;
  let cached: Promise<HybridPublicKeys> | undefined;

  const fetchKeys = async (): Promise<HybridPublicKeys> => {
    const [ed, pq] = await Promise.all([
      client.send(new GetPublicKeyCommand({ KeyId: kmsKeys.ed25519 })),
      client.send(new GetPublicKeyCommand({ KeyId: kmsKeys.mlDsa65 })),
    ]);
    return {
      ed25519: stripSpki(ed.PublicKey, ED25519_SPKI_PREFIX, 32, 'Ed25519'),
      mlDsa65: stripSpki(pq.PublicKey, MLDSA65_SPKI_PREFIX, 1952, 'ML-DSA-65'),
      keyIds,
    };
  };
  // Public keys never change for a KMS key: fetch once, but retry after a failed fetch.
  const publicKeys = (): Promise<HybridPublicKeys> => {
    cached ??= fetchKeys().catch((e: unknown) => {
      cached = undefined;
      throw e;
    });
    return cached;
  };

  return {
    publicKeys,
    async signHybrid(msg: Uint8Array, ctx: MlDsaContext): Promise<HybridSignature> {
      if (msg.length > KMS_RAW_LIMIT) {
        throw new Error(
          `KMS Ed25519 signs at most ${KMS_RAW_LIMIT} bytes (no EXTERNAL_MU for Ed25519); got ${msg.length}`,
        );
      }
      const pub = await publicKeys();
      const [ed, pq] = await Promise.all([
        client.send(
          new SignCommand({
            KeyId: kmsKeys.ed25519,
            Message: msg,
            MessageType: 'RAW',
            SigningAlgorithm: 'ED25519_SHA_512',
          }),
        ),
        client.send(
          new SignCommand({
            KeyId: kmsKeys.mlDsa65,
            Message: muFor(pub.mlDsa65, ctx, msg),
            MessageType: 'EXTERNAL_MU',
            SigningAlgorithm: 'ML_DSA_SHAKE_256',
          }),
        ),
      ]);
      const edSig = ed.Signature;
      const pqSig = pq.Signature;
      // Never trust a signature we did not check: a wrong mu or a wrong key would otherwise surface much later.
      if (!edSig || !ed25519.verify(edSig, msg, pub.ed25519, { zip215: false })) {
        throw new Error('KMS returned an Ed25519 signature that does not verify');
      }
      if (!pqSig || !mldsaVerify('ml-dsa-65', pub.mlDsa65, msg, pqSig, ctx)) {
        throw new Error('KMS returned an ML-DSA-65 signature that does not verify under the given context');
      }
      return { ed25519: edSig, mlDsa65: pqSig, keyIds };
    },
  };
}
