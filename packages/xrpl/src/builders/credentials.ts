// Steps 0a, 0b, 5e, 5f: credentials (XLS-70). DESIGN 7.3 and 6.16.
// Source: https://xrpl.org/docs/references/protocol/transactions/types/credentialcreate
// Source: https://xrpl.org/docs/references/protocol/transactions/types/credentialaccept
// Source: https://xrpl.org/docs/references/protocol/transactions/types/credentialdelete
import { sha256 } from '@legx/core/dealcore';
import type { CredentialAccept, CredentialCreate, CredentialDelete } from 'xrpl';
import { addr, type BuildCtx, baseFee, bytes32, DAY, hexOfText, hexUp, seq } from './common.ts';

const ATTORNEY = hexOfText('LEGX_ATTORNEY');
const partyType = (side: 'A' | 'B') => {
  if (side !== 'A' && side !== 'B') throw new Error('side must be A or B');
  return hexOfText(`LEGX_PARTY_${side}`);
};

export const ATTORNEY_VALID_DAYS = 90;

/** 0a: the verifier issuer grants a lawyer's operations account the LEGX_ATTORNEY credential, valid 90 days. */
export function build0a(
  i: { issuer: string; subject: string; barVerificationSha256: Uint8Array; closeTime: number },
  ctx: BuildCtx,
): CredentialCreate {
  return {
    TransactionType: 'CredentialCreate',
    Account: addr(i.issuer),
    Subject: addr(i.subject),
    CredentialType: ATTORNEY,
    URI: hexOfText(`legx:bar:v1:${hexUp(bytes32('barVerificationSha256', i.barVerificationSha256))}`),
    Expiration: seq(i.closeTime + ATTORNEY_VALID_DAYS * DAY),
    Fee: String(baseFee(ctx)),
  };
}

/** 0b: the lawyer's operations account accepts it. */
export function build0b(i: { subject: string; issuer: string }, ctx: BuildCtx): CredentialAccept {
  return {
    TransactionType: 'CredentialAccept',
    Account: addr(i.subject),
    Issuer: addr(i.issuer),
    CredentialType: ATTORNEY,
    Fee: String(baseFee(ctx)),
  };
}

/** The verifier issuer deletes the lawyer's LEGX_ATTORNEY credential (renewal after the age limit, or revocation). */
export function build0c(i: { issuer: string; subject: string }, ctx: BuildCtx): CredentialDelete {
  return {
    TransactionType: 'CredentialDelete',
    Account: addr(i.issuer),
    Subject: addr(i.subject),
    Issuer: addr(i.issuer),
    CredentialType: ATTORNEY,
    Fee: String(baseFee(ctx)),
  };
}

/** 5e: the deal wallet binds a client with LEGX_PARTY_A or LEGX_PARTY_B; the URI names the 64-byte binding signature. */
export function build5e(
  i: { shell: string; subject: string; side: 'A' | 'B'; bindingSig: Uint8Array },
  ctx: BuildCtx,
): CredentialCreate {
  if (i.bindingSig.length !== 64) throw new Error('bindingSig must be 64 bytes');
  return {
    TransactionType: 'CredentialCreate',
    Account: addr(i.shell),
    Subject: addr(i.subject),
    CredentialType: partyType(i.side),
    URI: hexOfText(`legx:bind:v1:${hexUp(sha256(i.bindingSig))}`),
    Fee: String(baseFee(ctx)),
  };
}

/** 5f: the client accepts it. */
export function build5f(i: { subject: string; shell: string; side: 'A' | 'B' }, ctx: BuildCtx): CredentialAccept {
  return {
    TransactionType: 'CredentialAccept',
    Account: addr(i.subject),
    Issuer: addr(i.shell),
    CredentialType: partyType(i.side),
    Fee: String(baseFee(ctx)),
  };
}
