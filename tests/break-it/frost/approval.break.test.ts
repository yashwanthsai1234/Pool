// Break-it (task 5.7): the user-verified approval that gates the firm HSM and the second authenticator (DESIGN 6.4).
import { describe, expect, it } from 'vitest';
import { p256 } from '../../../packages/core/node_modules/@noble/curves/nist.js';
import { sha256 } from '../../../packages/core/node_modules/@noble/hashes/sha2.js';
import { utf8ToBytes } from '../../../packages/core/node_modules/@noble/hashes/utils.js';
import { base64urlnopad } from '../../../packages/core/node_modules/@scure/base/index.js';
import { approvalCheck } from '../../../packages/core/src/frostRules.ts';

const RP_ID = 'legx.app';
const secret = p256.utils.randomSecretKey();
const approver = { p256Pub: p256.getPublicKey(secret, false), rpId: RP_ID };
const msgHash = sha256(utf8ToBytes('EscrowFinish multisign bytes'));

function assertion(client: Record<string, unknown>) {
  const authenticatorData = new Uint8Array([...sha256(utf8ToBytes(RP_ID)), 0x05, 0, 0, 0, 1]); // UP | UV, counter 1
  const clientDataJSON = utf8ToBytes(
    JSON.stringify({ type: 'webauthn.get', challenge: base64urlnopad.encode(msgHash), ...client }),
  );
  const signature = p256.sign(new Uint8Array([...authenticatorData, ...sha256(clientDataJSON)]), secret, {
    format: 'der',
  });
  return { authenticatorData, clientDataJSON, signature };
}

describe('I-S-F3 approvalCheck does not check the WebAuthn origin', () => {
  it('control: the vault origin is accepted', () => {
    expect(approvalCheck(assertion({ origin: 'https://vault.legx.app' }), msgHash, approver)).toEqual({ ok: true });
  });
  // Source: https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion step 13 ("Verify that the value of C.origin is
  // an origin expected by the Relying Party") and step 14 (topOrigin when crossOrigin is true)
  it('refuses an assertion made on another origin, or cross-origin from a framing page', () => {
    expect(approvalCheck(assertion({ origin: 'https://evil.example' }), msgHash, approver).ok).toBe(false);
    expect(
      approvalCheck(
        assertion({ origin: 'https://vault.legx.app', crossOrigin: true, topOrigin: 'https://evil.example' }),
        msgHash,
        approver,
      ).ok,
    ).toBe(false);
  });
});
