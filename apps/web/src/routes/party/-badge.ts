// Step 5f (OD-33, DESIGN 5.2): the client accepts its party badge. The client's account is the slot account, so the
// acceptance is a `CredentialAccept` single-signed by the client's FROST pair inside the vault frame. The page builds the
// transaction only from the deal it recomputed the seal of, and the frame's allow-list checks it again against its own seal.
// Source: https://xrpl.org/docs/references/protocol/transactions/types/credentialaccept
import { bytesToHex } from '@legx/core/dealcore';
import type { ApiClient } from '../../lib/api.ts';
import { fetchSealedDeal } from '../../lib/seal.ts';

/** Ledgers the transaction stays valid for, and the base fee of the demo ledgers (DESIGN 5.2 table: 10 drops). */
const VALID_FOR_LEDGERS = 20;
const FEE_DROPS = '10';

export async function acceptBadgeTx(d: {
  api: ApiClient;
  vault: { signSingle(dealId: string, tx: Record<string, unknown>): Promise<string> };
  dealId: string;
  role: 'alice' | 'bob';
  validatedIndex: () => Promise<number>;
}): Promise<string> {
  const side = d.role === 'alice' ? 'A' : 'B';
  const sealed = await fetchSealedDeal(d.api, d.dealId);
  if (sealed.state === 'incomplete') throw new Error('DEAL_NOT_SEALED');
  if (sealed.state === 'seal-mismatch') throw new Error('SEAL_MISMATCH');
  const pub = (side === 'A' ? sealed.publicData.xPubA : sealed.publicData.xPubB).toUpperCase();
  const { deriveAddress } = await import('xrpl');
  const account = deriveAddress(pub);
  const [info, index] = await Promise.all([d.api.ledger.accountInfo({ address: account }), d.validatedIndex()]);
  if (!info.exists) throw new Error('ACCOUNT_NOT_FUNDED');
  const tx = {
    TransactionType: 'CredentialAccept',
    Account: account,
    Issuer: sealed.publicData.walletAddress,
    CredentialType: bytesToHex(new TextEncoder().encode(`LEGX_PARTY_${side}`)).toUpperCase(),
    Fee: FEE_DROPS,
    Sequence: info.sequence,
    LastLedgerSequence: index + VALID_FOR_LEDGERS,
    SigningPubKey: pub,
  };
  const blob = await d.vault.signSingle(d.dealId, tx);
  const res = await d.api.ledger.submit({ txBlob: blob });
  if (res.status !== 'validated' || !res.result.startsWith('tes'))
    throw new Error(`LEDGER_REFUSED ${res.status === 'expired' ? 'expired' : res.result}`);
  return res.hash;
}
