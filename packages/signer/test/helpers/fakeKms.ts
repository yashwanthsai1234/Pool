// A KMS emulator for the two calls KmsSigner makes, built from the AWS documentation (see SOURCES.md): it enforces the
// rules that matter (ED25519_SHA_512 needs RAW and at most 4096 bytes; ML_DSA_SHAKE_256 with EXTERNAL_MU needs exactly
// 64 bytes) and signs with noble (ML-DSA external mu) and node:crypto (Ed25519). It is NOT a recording of real KMS.

import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import type {
  GetPublicKeyCommand,
  GetPublicKeyCommandOutput,
  SignCommand,
  SignCommandOutput,
} from '@aws-sdk/client-kms';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import type { KmsClientLike } from '../../src/kms.ts';

export interface FakeKms extends KmsClientLike {
  readonly calls: { readonly type: 'GetPublicKey' | 'Sign'; readonly input: Record<string, unknown> }[];
  /** Makes the next ML-DSA signature wrong, to prove the signer checks what KMS returns. */
  corruptNextMlDsa(): void;
}

export const FAKE_ED_KEY = 'alias/fake-ed25519';
export const FAKE_PQ_KEY = 'alias/fake-mldsa65';

export function createFakeKms(): FakeKms {
  const ed = generateKeyPairSync('ed25519');
  const pq = ml_dsa65.keygen();
  const calls: FakeKms['calls'][number][] = [];
  let corrupt = false;
  const reject = (m: string): never => {
    throw Object.assign(new Error(m), { name: 'ValidationException' });
  };
  const spkiMl = Buffer.concat([Buffer.from('308207b2300b0609608648016503040312038207a100', 'hex'), pq.publicKey]);

  async function send(
    command: GetPublicKeyCommand | SignCommand,
  ): Promise<GetPublicKeyCommandOutput | SignCommandOutput> {
    const input = command.input as unknown as Record<string, unknown>;
    const name = command.constructor.name;
    if (name === 'GetPublicKeyCommand') {
      calls.push({ type: 'GetPublicKey', input });
      if (input.KeyId === FAKE_ED_KEY) {
        return { PublicKey: ed.publicKey.export({ format: 'der', type: 'spki' }), $metadata: {} };
      }
      if (input.KeyId === FAKE_PQ_KEY) return { PublicKey: new Uint8Array(spkiMl), $metadata: {} };
      return reject('NotFoundException');
    }
    calls.push({ type: 'Sign', input });
    const msg = input.Message as Uint8Array;
    if (input.KeyId === FAKE_ED_KEY) {
      if (input.SigningAlgorithm !== 'ED25519_SHA_512' || input.MessageType !== 'RAW') {
        reject('ED25519_SHA_512 requires MessageType RAW');
      }
      if (msg.length > 4096) reject('RAW messages are limited to 4096 bytes');
      return { Signature: new Uint8Array(nodeSign(null, msg, ed.privateKey)), $metadata: {} };
    }
    if (input.SigningAlgorithm !== 'ML_DSA_SHAKE_256') reject('unsupported signing algorithm');
    if (input.MessageType !== 'EXTERNAL_MU') reject('this emulator only models EXTERNAL_MU for ML-DSA');
    if (msg.length !== 64) reject('EXTERNAL_MU must be exactly 64 bytes');
    const sig = ml_dsa65.internal.sign(msg, pq.secretKey, { externalMu: true });
    if (corrupt) {
      corrupt = false;
      sig[0] = (sig[0] ?? 0) ^ 1;
    }
    return { Signature: sig, $metadata: {} };
  }
  return {
    send: send as KmsClientLike['send'],
    calls,
    corruptNextMlDsa: () => {
      corrupt = true;
    },
  };
}
