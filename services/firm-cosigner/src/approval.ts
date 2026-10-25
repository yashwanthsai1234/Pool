// The lawyer's approval (DESIGN 6.4 "Signing rules": the firm HSM signs only with a user-verified WebAuthn approval by
// the lawyer over the same message hash). The assertion is checked by @simplewebauthn/server 14.x with the message hash
// as the challenge and user verification required. The service adds what the library cannot know:
//  - the credential must be the lawyer's registered one for this (deal, slot),
//  - an assertion is used once (the challenge is the message hash, so a replay of the same assertion is the risk), and
//  - the signature counter moves forward in the same step that consumes the assertion.
// Source: https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion
// Source: https://simplewebauthn.dev/docs/packages/server (verifyAuthenticationResponse)
import { kyselyOf } from '@legx/coordinator/frost/store';
import { bytesToHex, tupleHash } from '@legx/core/dealcore';
import type { Database } from '@legx/db';
import type { SignBegin } from '@legx/recovery-agent/holder';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { type Kysely, sql } from 'kysely';

export type ApprovalCode =
  | 'APPROVAL_MISSING'
  | 'APPROVAL_HASH_MISMATCH'
  | 'APPROVAL_NOT_UV'
  | 'APPROVAL_CREDENTIAL_UNKNOWN'
  | 'APPROVAL_INVALID'
  | 'APPROVAL_REUSED';

export class ApprovalError extends Error {
  readonly code: ApprovalCode;
  constructor(code: ApprovalCode, detail = '') {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'ApprovalError';
    this.code = code;
  }
}

/** The approval as it travels in `sign.begin` (contracts `WebAuthnApproval`); standard or URL-safe base64 both decode. */
export type WireApproval = NonNullable<SignBegin['approval']>;

const b64url = (s: string): string => Buffer.from(s, 'base64').toString('base64url');

export interface ApprovalConfig {
  readonly rpId: string;
  readonly origin: string;
}

export class LawyerApprovals {
  readonly #k: Kysely<unknown>;
  readonly #cfg: ApprovalConfig;
  constructor(db: Database, cfg: ApprovalConfig) {
    this.#k = kyselyOf(db);
    this.#cfg = cfg;
  }

  /** Registers the lawyer's WebAuthn credential (COSE public key, as @simplewebauthn/server stores it). */
  async register(dealId: string, slot: string, credentialId: string, publicKey: Uint8Array): Promise<void> {
    await sql`insert into firm_cosigner_credential (deal_id, slot, credential_id, public_key)
      values (${dealId}, ${slot}, ${b64url(credentialId)}, ${publicKey}) on conflict do nothing`.execute(this.#k);
  }

  /** Throws `ApprovalError` unless this is a fresh, user-verified assertion by the lawyer over `msgHash`. */
  async verify(dealId: string, slot: string, msgHash: Uint8Array, a: WireApproval | undefined): Promise<string> {
    if (!a) throw new ApprovalError('APPROVAL_MISSING');
    if (a.message_hash.toLowerCase() !== bytesToHex(msgHash)) throw new ApprovalError('APPROVAL_HASH_MISMATCH');
    const id = b64url(a.credential_id);
    const row = (
      await sql<{ public_key: Uint8Array; counter: string }>`select public_key, counter from firm_cosigner_credential
        where deal_id = ${dealId} and slot = ${slot} and credential_id = ${id}`.execute(this.#k)
    ).rows[0];
    if (!row) throw new ApprovalError('APPROVAL_CREDENTIAL_UNKNOWN');
    let counter: number;
    try {
      const v = await verifyAuthenticationResponse({
        response: {
          id,
          rawId: id,
          type: 'public-key',
          clientExtensionResults: {},
          response: {
            authenticatorData: b64url(a.authenticator_data),
            clientDataJSON: b64url(a.client_data_json),
            signature: b64url(a.signature),
          },
        },
        expectedChallenge: Buffer.from(msgHash).toString('base64url'),
        expectedOrigin: this.#cfg.origin,
        expectedRPID: this.#cfg.rpId,
        credential: { id, publicKey: new Uint8Array(row.public_key), counter: Number(row.counter) },
        requireUserVerification: true,
      });
      if (!v.verified) throw new ApprovalError('APPROVAL_INVALID');
      if (!v.authenticationInfo.userVerified) throw new ApprovalError('APPROVAL_NOT_UV');
      counter = v.authenticationInfo.newCounter;
    } catch (e) {
      if (e instanceof ApprovalError) throw e;
      const m = e instanceof Error ? e.message : '';
      if (/counter/i.test(m)) throw new ApprovalError('APPROVAL_REUSED', 'the signature counter did not advance');
      if (/challenge/i.test(m)) throw new ApprovalError('APPROVAL_HASH_MISMATCH');
      if (/verification/i.test(m)) throw new ApprovalError('APPROVAL_NOT_UV');
      throw new ApprovalError('APPROVAL_INVALID', m);
    }
    // One step: the assertion is recorded as used (a second use hits the primary key), then the counter advances.
    const used = bytesToHex(
      tupleHash(
        'legx/firm-cosigner/approval/v1',
        [a.authenticator_data, a.client_data_json, a.signature].map((x) => Buffer.from(x, 'base64')),
      ),
    );
    const fresh = await sql`insert into firm_cosigner_approval_use (approval_id) values (${used})
      on conflict do nothing returning approval_id`.execute(this.#k);
    if (fresh.rows.length === 0) throw new ApprovalError('APPROVAL_REUSED');
    await sql`update firm_cosigner_credential set counter = greatest(counter, ${counter}) where deal_id = ${dealId}
      and slot = ${slot} and credential_id = ${id}`.execute(this.#k);
    return id;
  }
}
