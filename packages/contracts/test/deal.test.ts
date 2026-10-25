import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { PublicDealData, SEAL_FIELD_ORDER } from '../src/deal.ts';
import { PassportAttestation } from '../src/records.ts';

const golden = (name: string) => JSON.parse(readFileSync(new URL(`../examples/${name}.json`, import.meta.url), 'utf8'));
const [deal] = golden('PublicDealData');
const [zkAttestation] = golden('PassportAttestation');

const issuePaths = (r: { error?: { issues: { path: PropertyKey[] }[] } }) =>
  r.error?.issues.map((i) => i.path.join('.'));

describe('P1.2-09 PublicDealData and PassportAttestation.method', () => {
  it('has exactly the 29 seal fields of DESIGN 6.6, in seal order', () => {
    expect(SEAL_FIELD_ORDER).toEqual([
      'contractRoot',
      'signedContractSeal',
      'walletAddress',
      'xPubA',
      'xPubB',
      'commitmentA',
      'commitmentB',
      'idMethodA',
      'idMethodB',
      'identityPolicy',
      'lawyerPubA',
      'lawyerPubB',
      'lawyerCommitmentA',
      'lawyerCommitmentB',
      'lawyerOpsA',
      'lawyerOpsB',
      'releaserAccount',
      'slotPolicyA',
      'slotPolicyLA',
      'slotPolicyB',
      'slotPolicyLB',
      'pqKeyHashA',
      'pqKeyHashLA',
      'pqKeyHashB',
      'pqKeyHashLB',
      'signerAccounts',
      'quorum',
      'payoutA',
      'payoutB',
    ]);
    expect(PublicDealData.safeParse(deal).success).toBe(true);
  });

  it('rejects a 30th key', () => {
    const r = PublicDealData.safeParse({ ...deal, amountDrops: '1' });
    expect(r.error?.issues[0]?.code).toBe('unrecognized_keys');
  });

  it('rejects a missing key', () => {
    const { payoutB: _, ...rest } = deal;
    expect(issuePaths(PublicDealData.safeParse(rest))).toContain('payoutB');
  });

  it('rejects releaserAccount != lawyerOpsB (DESIGN 6.6: dealSeal throws)', () => {
    expect(issuePaths(PublicDealData.safeParse({ ...deal, releaserAccount: deal.lawyerOpsA }))).toEqual([
      'releaserAccount',
    ]);
  });

  it('rejects duplicate signer accounts and a quorum other than 4', () => {
    const dup = [deal.signerAccounts[0], ...deal.signerAccounts.slice(0, 3)];
    expect(issuePaths(PublicDealData.safeParse({ ...deal, signerAccounts: dup }))).toEqual(['signerAccounts']);
    expect(issuePaths(PublicDealData.safeParse({ ...deal, quorum: 3 }))).toEqual(['quorum']);
  });

  it('rejects a wrong hex length and a bad address, naming the field', () => {
    expect(issuePaths(PublicDealData.safeParse({ ...deal, contractRoot: `${deal.contractRoot}00` }))).toEqual([
      'contractRoot',
    ]);
    const badAddr = `${deal.walletAddress.slice(0, -1)}${deal.walletAddress.endsWith('Q') ? 'R' : 'Q'}`;
    expect(issuePaths(PublicDealData.safeParse({ ...deal, walletAddress: badAddr }))).toEqual(['walletAddress']);
  });

  it('PassportAttestation.method accepts only "zkpassport" and "nfc-chip"', () => {
    expect(PassportAttestation.safeParse(zkAttestation).success).toBe(true);
    const r = PassportAttestation.safeParse({ ...zkAttestation, method: 'self' });
    expect(issuePaths(r)).toEqual(['method']);
  });

  it('a zkpassport attestation with chip checks is rejected (one checks shape per method)', () => {
    const [, chip] = golden('PassportAttestation');
    expect(PassportAttestation.safeParse({ ...zkAttestation, checks: chip.checks }).success).toBe(false);
  });
});
