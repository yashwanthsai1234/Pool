// OD-33: step 5f. The client's account is the slot account, so the vault signs `CredentialAccept` single-signed with the FROST
// pair, and only the sealed one: this slot's account, issued by the sealed deal wallet, the sealed type, no other fields.
import { slotAddress, slotPubkey } from '@legx/core/frost';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { decode, encodeForSigning, type Transaction } from 'xrpl';
import { createVault } from '../src/vault.ts';
import { copy, dealId, fakePrf, freshDb, makeSlot, sealedDeal } from './helpers.ts';

async function setup() {
  const { pub, shares } = makeSlot();
  const id = dealId();
  const deal = sealedDeal(pub, 'A');
  const prf = fakePrf();
  const vault = createVault({ role: 'alice', dbName: freshDb(), prf: prf.source, deals: async () => deal });
  await vault.storeShares({
    dealId: id,
    pub,
    share1: copy(shares[0]),
    share2: { mode: 'security-key', credential: { id: 'c', transports: [] }, share: copy(shares[1]) },
  });
  const slotHex = bytesToHex(slotPubkey(pub)).toUpperCase();
  const accept = {
    TransactionType: 'CredentialAccept',
    Account: slotAddress(pub),
    Issuer: deal.walletAddress,
    CredentialType: bytesToHex(new TextEncoder().encode('LEGX_PARTY_A')).toUpperCase(),
    Fee: '12',
    Sequence: 1,
    LastLedgerSequence: 100,
    SigningPubKey: slotHex,
  };
  return { vault, id, deal, pub, accept, slotHex };
}

describe('OD-33 signSingle', () => {
  it('signs the sealed CredentialAccept: the blob verifies strictly under the slot key', async () => {
    const s = await setup();
    const blob = await s.vault.signSingle(s.id, s.accept);
    const signed = decode(blob) as unknown as Record<string, string>;
    expect(signed.TransactionType).toBe('CredentialAccept');
    const msg = hexToBytes(encodeForSigning(s.accept as unknown as Transaction));
    expect(
      ed25519.verify(hexToBytes(signed.TxnSignature as string), msg, slotPubkey(s.pub).slice(1), { zip215: false }),
    ).toBe(true);
  });

  it.each([
    ['another issuer', (s: Awaited<ReturnType<typeof setup>>) => ({ ...s.accept, Issuer: s.deal.payoutA.account })],
    ['another type', (s: Awaited<ReturnType<typeof setup>>) => ({ ...s.accept, CredentialType: '41' })],
    ['another account', (s: Awaited<ReturnType<typeof setup>>) => ({ ...s.accept, Account: s.deal.payoutB.account })],
    ['an extra field', (s: Awaited<ReturnType<typeof setup>>) => ({ ...s.accept, Memos: [] })],
    ['a payment', (s: Awaited<ReturnType<typeof setup>>) => ({ ...s.accept, TransactionType: 'Payment' })],
    ['a fee over the sealed maximum', (s: Awaited<ReturnType<typeof setup>>) => ({ ...s.accept, Fee: '99999' })],
  ])('refuses %s', async (_n, make) => {
    const s = await setup();
    await expect(s.vault.signSingle(s.id, make(s))).rejects.toMatchObject({ code: 'MESSAGE_REFUSED' });
  });
});
