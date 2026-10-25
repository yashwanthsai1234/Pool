// E2E-P1 helper: a WebAuthn assertion as an authenticator makes it (ES256, user verified), for the holders that need a
// user-verified approval before they sign (DESIGN 6.4).
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import type { Approval, ApproverKey } from '../../src/frostRules.ts';

const key = p256.utils.randomSecretKey();
export const APPROVER: ApproverKey = { p256Pub: p256.getPublicKey(key), rpId: 'legx.example' };

export function assertion(msgHash: Uint8Array): Approval {
  const authenticatorData = new Uint8Array([...sha256(utf8ToBytes(APPROVER.rpId)), 0x05, 0, 0, 0, 1]);
  const clientDataJSON = utf8ToBytes(
    JSON.stringify({
      type: 'webauthn.get',
      challenge: Buffer.from(msgHash).toString('base64url'),
      origin: 'https://legx.example',
    }),
  );
  const signature = p256.sign(new Uint8Array([...authenticatorData, ...sha256(clientDataJSON)]), key, {
    format: 'der',
  });
  return { authenticatorData, clientDataJSON, signature };
}
