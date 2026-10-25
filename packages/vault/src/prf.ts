// WebAuthn PRF for share 2 (DESIGN 6.4): a FIDO2 security key with PRF ("security-key", cross-platform), or a
// passkey on the same phone ("single-device", platform; labeled, it loses the theft protection).
// The vault needs no server here: the PRF output itself proves the authenticator, because only it opens the
// AES-GCM ciphertext. User verification is required on every evaluation.
// Source: https://w3c.github.io/webauthn/#prf-extension
// Source: https://simplewebauthn.dev/docs/packages/browser (v14: `startRegistration`, `startAuthentication`;
//   `extensions` pass through unchanged, `clientExtensionResults` come back unchanged)
import { bufferToBase64URLString, startAuthentication, startRegistration } from '@simplewebauthn/browser';
import { bs } from './aead.ts';
import { VaultError } from './errors.ts';

export type AuthenticatorKind = 'security-key' | 'same-phone';
/** A credential and its transports. Chrome routes a request by the transport hint, so the vault keeps it. */
export type PrfCredential = { id: string; transports: string[] };

/** The vault's view of the authenticator that unlocks share 2. Tests may pass their own. */
export interface PrfSource {
  /** Creates a credential. `prf` is false when the authenticator or browser has no PRF: offer the recovery file. */
  register(
    kind: AuthenticatorKind,
    user: { id: Uint8Array; name: string },
  ): Promise<{ credential: PrfCredential; prf: boolean }>;
  /** PRF(input) with user verification. The caller zeroes the result. Throws `PASSKEY_REQUIRED` on any failure. */
  evaluate(credential: PrfCredential, input: Uint8Array): Promise<Uint8Array>;
}

const challenge = (): string => bufferToBase64URLString(crypto.getRandomValues(new Uint8Array(32)).buffer);

/** The real PRF source over `navigator.credentials`, through @simplewebauthn/browser 14.0.0. */
export function webauthnPrf(rp: { id: string; name: string }): PrfSource {
  return {
    async register(kind, user) {
      const r = await startRegistration({
        optionsJSON: {
          challenge: challenge(),
          rp,
          user: { id: bufferToBase64URLString(user.id.slice().buffer), name: user.name, displayName: user.name },
          pubKeyCredParams: [
            { type: 'public-key', alg: -8 },
            { type: 'public-key', alg: -7 },
          ],
          authenticatorSelection: {
            authenticatorAttachment: kind === 'security-key' ? 'cross-platform' : 'platform',
            residentKey: 'discouraged',
            userVerification: 'required',
          },
          extensions: { prf: {} },
        },
      });
      const transports = r.response.transports ?? [];
      return { credential: { id: r.id, transports }, prf: r.clientExtensionResults.prf?.enabled === true };
    },

    async evaluate(credential, input) {
      let first: unknown;
      try {
        const a = await startAuthentication({
          optionsJSON: {
            challenge: challenge(),
            rpId: rp.id,
            allowCredentials: [
              { id: credential.id, type: 'public-key', transports: credential.transports as AuthenticatorTransport[] },
            ],
            userVerification: 'required',
            extensions: { prf: { eval: { first: bs(input) } } },
          },
        });
        first = a.clientExtensionResults.prf?.results?.first;
      } catch {
        throw new VaultError('PASSKEY_REQUIRED');
      }
      if (!(first instanceof ArrayBuffer) || first.byteLength !== 32) throw new VaultError('PASSKEY_REQUIRED');
      return new Uint8Array(first);
    },
  };
}
