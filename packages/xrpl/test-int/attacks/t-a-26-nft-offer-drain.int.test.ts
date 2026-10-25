// T-A-26 (IMPLEMENTATION 2.6; DESIGN 6.9, T-A-19): the NFT buy-offer drain on a real ledger. While the setup key is live
// (after step 2 and before 5g) it creates a BUY offer owned by the shell for an NFT an accomplice holds. After the lock
// nobody can sign for the shell, yet the accomplice can accept the offer at any time: the shell pays the offer's price
// without a signature. The lock checker must block (UNEXPECTED_OWNED_NFTOKENOFFER) and the release gate must refuse
// (LOCK_OK) BEFORE the escrow is released, so no funds arrive. A second test then releases anyway, against the gate, and
// shows the drain is real: that is why the check is the only defence.
// Run with the offer made right after funding (step 3) and with the offer made as the last lock step (after 5f).
// Source: https://xrpl.org/docs/references/protocol/transactions/types/nftokencreateoffer ; DESIGN 6.9
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type Deal, newDeal, type Stage } from '../deal.ts';
import { type Chain, openChain } from '../roles.ts';
import { outcome, stranger } from './util.ts';

const TRANSFERABLE = 8;
const PRICE = '30000000';
let c: Chain;
beforeAll(async () => {
  c = await openChain();
});
afterAll(async () => {
  await c.close();
});

/** The accomplice mints an NFT; the shell (setup key) offers to BUY it. Returns what the accomplice needs to accept. */
async function plant(d: Deal) {
  const accomplice = await stranger(c);
  const mint = await c.send(accomplice, {
    TransactionType: 'NFTokenMint',
    Account: accomplice.classicAddress,
    NFTokenTaxon: 0,
    Flags: TRANSFERABLE,
  });
  const nftokenId = String(mint.meta.nftoken_id);
  await d.setup({
    TransactionType: 'NFTokenCreateOffer',
    Account: d.wallet,
    Owner: accomplice.classicAddress,
    NFTokenID: nftokenId,
    Amount: PRICE,
  });
  const offers = await d.objects('nft_offer');
  return { accomplice, nftokenId, offerIndex: String(offers[0]?.index), offers };
}

describe('T-A-26 the NFT buy-offer drain', () => {
  it.each<Stage>(['funded', 'credentials'])(
    'the offer is made after stage %s: the checker and the gate block before funds arrive',
    async (phase) => {
      const d = await newDeal(c, phase);
      expect(await d.objects('nft_offer')).toEqual([]); // setup state
      const { offers } = await plant(d);
      expect(offers).toHaveLength(1);
      expect(offers[0]).toMatchObject({ Owner: d.wallet, Amount: PRICE });

      expect(await d.lockFlagged()).toEqual(['UNEXPECTED_OWNED_NFTOKENOFFER']);
      const g = await d.gate();
      expect(g.failing).toEqual(['LOCK_OK']); // the gate does not pass, so no EscrowFinish is built
      // no funds arrived: the quarantine escrow is still pending and the shell holds only its own funding
      expect(await d.balance(d.wallet)).toBeLessThan(100_000_000n);
    },
  );

  it('released anyway (against the gate), the accomplice drains the shell with no signature of the four', async () => {
    const d = await newDeal(c, 'credentials');
    const { accomplice, offerIndex } = await plant(d);
    expect(await d.lockFlagged()).toEqual(['UNEXPECTED_OWNED_NFTOKENOFFER']); // setup state: the checker did flag it
    const finish = await c.attempt(d.lawyerB.ops, d.finishTx());
    expect(outcome(finish)).toBe('validated:tesSUCCESS'); // the ledger itself does not know the gate
    const funded = await d.balance(d.wallet);
    const take = await c.attempt(accomplice, {
      TransactionType: 'NFTokenAcceptOffer',
      Account: accomplice.classicAddress,
      NFTokenBuyOffer: offerIndex,
    });
    expect(outcome(take)).toBe('validated:tesSUCCESS');
    expect(funded - (await d.balance(d.wallet))).toBe(BigInt(PRICE));
  });
});
