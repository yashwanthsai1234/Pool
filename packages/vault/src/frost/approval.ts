// The human's approval of one message (DESIGN 6.4 "A second holder never signs on its own say-so"): a user-verified
// WebAuthn assertion whose challenge is SHA-256 of the exact message. The firm HSM (task 3.10) checks it with core's
// `approvalCheck` before it releases a signature share (P4.7-21). The credential is the lawyer's registered ES256
// credential; the vault never sees a private key.
// Source: https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion
// Source: https://simplewebauthn.dev/docs/packages/browser#startauthentication
import type { WebAuthnApproval } from '@legx/contracts/frost';
import type { Approval } from '@legx/core/frostRules';
import { fromBase64Strict, toBase64 } from '@legx/core/pq';
import { base64URLStringToBuffer, bufferToBase64URLString, startAuthentication } from '@simplewebauthn/browser';
import type { z } from 'zod';
import { bs } from '../aead.ts';
import { VaultError } from '../errors.ts';
import { hex } from './wire.ts';

export type ApprovalWire = z.infer<typeof WebAuthnApproval>;
/** Asks the human to approve `msgHash` (32 bytes); throws `APPROVAL_REFUSED` when they cancel or the prompt fails. */
export type RequestApproval = (msgHash: Uint8Array) => Promise<ApprovalWire>;

const b64url = (b: ArrayBuffer | Uint8Array): string =>
  bufferToBase64URLString((b instanceof Uint8Array ? b.slice() : new Uint8Array(b)).buffer);
const fromUrl = (s: string): Uint8Array => new Uint8Array(base64URLStringToBuffer(s));

/**
 * `requestApproval(hash)` over `navigator.credentials.get` with user verification required. Without `credential` the browser
 * offers the lawyer's discoverable credentials for `rpId` (the console does not store a credential id; the HSM checks the
 * assertion against the lawyer's registered key).
 */
export function webauthnApproval(rpId: string, credential?: { id: string; transports: string[] }): RequestApproval {
  return async (msgHash) => {
    if (msgHash.length !== 32) throw new VaultError('INPUT_INVALID');
    try {
      const a = await startAuthentication({
        optionsJSON: {
          challenge: b64url(bs(msgHash)),
          rpId,
          ...(credential
            ? {
                allowCredentials: [
                  {
                    id: credential.id,
                    type: 'public-key' as const,
                    transports: credential.transports as AuthenticatorTransport[],
                  },
                ],
              }
            : {}),
          userVerification: 'required',
        },
      });
      return {
        credential_id: toBase64(fromUrl(a.rawId)),
        authenticator_data: toBase64(fromUrl(a.response.authenticatorData)),
        client_data_json: toBase64(fromUrl(a.response.clientDataJSON)),
        signature: toBase64(fromUrl(a.response.signature)),
        message_hash: hex(msgHash),
      } as ApprovalWire;
    } catch {
      throw new VaultError('APPROVAL_REFUSED');
    }
  };
}

/** The wire approval as core's `approvalCheck` takes it. */
export function approvalBytes(a: ApprovalWire): Approval {
  const d = (s: string) => fromBase64Strict(s) ?? new Uint8Array();
  return {
    authenticatorData: d(a.authenticator_data),
    clientDataJSON: d(a.client_data_json),
    signature: d(a.signature),
  };
}
