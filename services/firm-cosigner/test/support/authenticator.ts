// A fixture WebAuthn authenticator: a P-256 key that signs assertions the way a platform authenticator does
// (authenticatorData || SHA-256(clientDataJSON), DER ECDSA). Every flag and field a test needs to break is a parameter.
// Source: https://www.w3.org/TR/webauthn-3/#sctn-op-get-assertion
import { randomBytes } from 'node:crypto';
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import type { WireApproval } from '../../src/approval.ts';

export const RP_ID = 'firm.example';
export const ORIGIN = 'https://firm.example';
const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');

export interface AssertOpts {
  readonly uv?: boolean;
  readonly up?: boolean;
  readonly counter?: number;
  /** The hash the user is shown (default: the hash asked for). */
  readonly challengeHash?: Uint8Array;
  readonly rpId?: string;
  readonly origin?: string;
  /** The hash claimed in the wire field (default: the hash asked for). */
  readonly claimedHash?: Uint8Array;
}

export class FixtureAuthenticator {
  readonly credentialId = new Uint8Array(randomBytes(32));
  readonly #secret = p256.utils.randomSecretKey();
  #counter = 0;

  /** The COSE_Key (ES256) a server stores for this credential. */
  cosePublicKey(): Uint8Array {
    const pub = p256.getPublicKey(this.#secret, false); // 04 || x || y
    return isoCBOR.encode(
      new Map<number, number | Uint8Array>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, pub.slice(1, 33)],
        [-3, pub.slice(33, 65)],
      ]),
    );
  }

  assert(msgHash: Uint8Array, o: AssertOpts = {}): WireApproval {
    const flags = (o.up === false ? 0 : 0x01) | (o.uv === false ? 0 : 0x04);
    const counter = o.counter ?? this.#counter + 1;
    this.#counter = Math.max(this.#counter, counter);
    const authData = new Uint8Array(37);
    authData.set(sha256(new TextEncoder().encode(o.rpId ?? RP_ID)), 0);
    authData[32] = flags;
    new DataView(authData.buffer).setUint32(33, counter);
    const clientData = new TextEncoder().encode(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: Buffer.from(o.challengeHash ?? msgHash).toString('base64url'),
        origin: o.origin ?? ORIGIN,
        crossOrigin: false,
      }),
    );
    const signature = p256.sign(new Uint8Array([...authData, ...sha256(clientData)]), this.#secret, { format: 'der' });
    return {
      credential_id: b64(this.credentialId),
      authenticator_data: b64(authData),
      client_data_json: b64(clientData),
      signature: b64(signature),
      message_hash: Buffer.from(o.claimedHash ?? msgHash).toString('hex'),
    } as unknown as WireApproval;
  }
}
