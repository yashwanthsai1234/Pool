// Ledger side of onboarding: the credential as the ledger shows it.
// Every read comes from one validated ledger through LedgerPort.snapshot (account_info plus account_objects).
// Source: https://xrpl.org/docs/references/protocol/ledger-data/ledger-entry-types/credential
import type { LedgerHeader, LedgerPort, XrplJson } from '@legx/contracts/ports';
import { XrplHash } from '@legx/contracts/values';
import { hexOfText } from '@legx/xrpl/builders/common';
import { rippledCode } from '@legx/xrpl/read';
import { VerifierError } from './errors.ts';

export const ATTORNEY_TYPE_HEX = hexOfText('LEGX_ATTORNEY');
/** lsfAccepted. Source: the credential entry page above. */
export const LSF_ACCEPTED = 0x00010000;

export interface CredentialView {
  readonly index: string;
  readonly uri: string | undefined;
  readonly accepted: boolean;
  readonly expiration: number | undefined;
  readonly previousTxnId: string;
}

export interface OpsState {
  readonly ledger: LedgerHeader;
  readonly credential: CredentialView | undefined;
}

/** The operations account and its LEGX_ATTORNEY credential from `issuer`, both at one validated ledger. */
export async function readOpsState(ledger: LedgerPort, ops: string, issuer: string): Promise<OpsState> {
  let snap: Awaited<ReturnType<LedgerPort['snapshot']>>;
  try {
    snap = await ledger.snapshot([ops as never]);
  } catch (e) {
    if (rippledCode(e) === 'actNotFound') {
      throw new VerifierError('OPS_ACCOUNT_MISSING', `${ops} does not exist on the ledger (fund it first)`);
    }
    throw e;
  }
  const mine = snap.accounts[ops]?.objects.find(
    (o) =>
      o.LedgerEntryType === 'Credential' &&
      o.Issuer === issuer &&
      o.Subject === ops &&
      o.CredentialType === ATTORNEY_TYPE_HEX,
  );
  return { ledger: snap.ledger, credential: mine && viewOf(mine) };
}

function viewOf(o: XrplJson): CredentialView {
  const flags = typeof o.Flags === 'number' ? o.Flags : 0;
  return {
    index: String(o.index),
    uri: typeof o.URI === 'string' ? o.URI : undefined,
    accepted: (flags & LSF_ACCEPTED) !== 0,
    expiration: typeof o.Expiration === 'number' ? o.Expiration : undefined,
    previousTxnId: String(o.PreviousTxnID),
  };
}

/**
 * The create and accept transaction hashes of an accepted credential, from the ledger alone. The entry's
 * PreviousTxnID is the accept; that transaction's metadata shows the entry as a ModifiedNode whose own
 * PreviousTxnID is the create. So a crash after the accept loses nothing.
 * Source: https://xrpl.org/docs/references/protocol/transactions/metadata
 */
export async function credentialHashes(
  ledger: LedgerPort,
  c: CredentialView,
): Promise<{ createTxHash: string; acceptTxHash: string }> {
  const accept = await ledger.tx(XrplHash.parse(c.previousTxnId));
  const nodes = (accept?.meta.AffectedNodes ?? []) as readonly Record<string, XrplJson>[];
  for (const n of nodes) {
    const m = n.ModifiedNode;
    if (m?.LedgerEntryType === 'Credential' && m.LedgerIndex === c.index && typeof m.PreviousTxnID === 'string') {
      return { createTxHash: m.PreviousTxnID, acceptTxHash: c.previousTxnId };
    }
  }
  throw new VerifierError('LEDGER_REJECTED', `cannot find the create transaction of credential ${c.index}`);
}
