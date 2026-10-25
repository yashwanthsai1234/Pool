// T-I-05 (IMPLEMENTATION 2.6; DESIGN 5.4, 6.4): lawyer key rotation after a share is known to be stolen, on a locked deal.
// A new DKG for the lawyer slot, new contract signatures, a new signed-contract NFT, a 4-of-4 SignerListSet signed by the old
// four, then Domain set again to 01 + root + the single new deal seal (signed by the new four), new records. The checker
// passes with DOMAIN_IS_SEAL, the gate passes, and the new group key signs the release and an exit. Run for slot LB and LA.
// Source: DESIGN 6.4 ("rotate the slot key on the ledger"), 6.6, 6.9 DOMAIN_IS_SEAL
import { domain } from '@legx/core/dealcore';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { newDeal } from '../deal.ts';
import { type Chain, openChain, up } from '../roles.ts';

let c: Chain;
beforeAll(async () => {
  c = await openChain();
});
afterAll(async () => {
  await c.close();
});

describe('T-I-05 lawyer key rotation', () => {
  it.each(['LB', 'LA'] as const)('slot %s is rotated on the ledger and the deal still completes', async (role) => {
    const d = await newDeal(c, 'locked');
    expect(await d.lockOk()).toBe(true); // setup state
    const field = async (name: string) =>
      (await c.client.request({ command: 'account_info', account: d.wallet, ledger_index: 'validated' })).result
        .account_data[name as 'Domain'];
    const oldDomain = await field('Domain');
    const oldSeal = d.seal;
    const oldMint = d.minted.hash;
    const oldSigners = (await d.objects('signer_list'))[0] as { SignerEntries: { SignerEntry: { Account: string } }[] };
    expect(oldSigners.SignerEntries).toHaveLength(4);

    const { old, fresh } = await d.swapLawyer(role);

    // the keys changed and nothing else about the lawyer did
    expect(fresh.slot.pubHex).not.toBe(old.slot.pubHex);
    expect(fresh.ops.classicAddress).toBe(old.ops.classicAddress);
    expect(d.minted.hash).not.toBe(oldMint);
    expect(d.seal).not.toEqual(oldSeal);
    // on the ledger: the new signer list, and Domain = 01 + root + the single new seal
    const list = (await d.objects('signer_list')) as {
      SignerEntries: { SignerEntry: { Account: string } }[];
      SignerQuorum: number;
    }[];
    expect(list).toHaveLength(1);
    const accounts = list[0]?.SignerEntries.map((e) => e.SignerEntry.Account) ?? [];
    expect(accounts).toContain(fresh.slot.address);
    expect(accounts).not.toContain(old.slot.address);
    expect(list[0]?.SignerQuorum).toBe(4);
    const now = String(await field('Domain'));
    expect(now).not.toBe(oldDomain);
    expect(now).toBe(up(domain(d.root, d.seal)));
    expect(now).toHaveLength(130);
    expect(now.startsWith('01')).toBe(true);

    // the checker passes, with DOMAIN_IS_SEAL named
    const findings = await d.lockCheck();
    expect(findings.find((f) => f.code === 'DOMAIN_IS_SEAL')).toMatchObject({ ok: true });
    expect(findings.find((f) => f.code === 'SIGNERS_MATCH_KEYS')).toMatchObject({ ok: true });
    expect(await d.lockOk()).toBe(true);
    // the gate passes with the new records, and the new group key signs the release and the exit
    expect((await d.gate()).failing).toEqual([]);
    await d.release();
    const exit = await d.exit('bob');
    expect(exit.receiverAfter - exit.receiverBefore).toBe(50_000_000n);
  });
});
