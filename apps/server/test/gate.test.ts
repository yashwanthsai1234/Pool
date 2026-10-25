// I-3.7-g: the composed gate is the core gate over the stored deal, and it fails closed.
// Source: DESIGN 6.17 (a gate that cannot read its input does not pass)
import type { LedgerPort } from '@legx/contracts/ports';
import { openPglite } from '@legx/db/pglite';
import { generateNodeSignerKeys, nodeSigner } from '@legx/signer';
import { describe, expect, it } from 'vitest';
import { realGate } from '../src/gate.ts';

const gateFor = async () => {
  const db = openPglite();
  await db.migrate();
  const deal = await db.repos.deals.insert({
    state: 'DRAFT',
    network: 'standalone',
    contract_root: '11'.repeat(32),
    payout_a: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
    payout_b: 'rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn',
    amount_drops: '1000000',
  });
  const gate = realGate({
    db,
    profile: 'demo',
    verifierSigner: nodeSigner(generateNodeSignerKeys('v-ed' as never, 'v-pq' as never)),
    verifierIssuer: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
  });
  return { gate, dealId: deal.deal_id };
};
const input = (dealId: string) => ({ dealId, publicData: {} as never, claim: {} as never, ledger: {} as LedgerPort });

describe('realGate', () => {
  it('refuses a deal that is not minted, naming why', async () => {
    const { gate, dealId } = await gateFor();
    const r = await gate.run(input(dealId));
    expect(r).toEqual({ ok: false, failed: ['INPUT_UNAVAILABLE:deal is not minted'] });
  });
  it('refuses a deal that does not exist', async () => {
    const { gate } = await gateFor();
    const r = await gate.run(input('01a17239-b43f-771d-8332-b1f8a9d02056'));
    expect(r.ok).toBe(false);
  });
});
