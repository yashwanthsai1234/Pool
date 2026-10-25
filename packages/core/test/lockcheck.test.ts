// Task 1.11: lock checker with the seal rules (DESIGN 6.9, 6.6; IMPLEMENTATION 1.11 and Appendix B).
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import type { PublicDealData } from '@legx/contracts/deal';
import { Finding as FindingSchema, LOCK_CODES } from '@legx/contracts/records';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import * as xrpl from 'xrpl';
import { dealSeal, domain } from '../src/dealcore.ts';
import { allOk, blocking, checkLock, type Expected, type Finding, lsf } from '../src/lockcheck.ts';

const h32 = (n: number) => bytesToHex(new Uint8Array(32).fill(n)).toUpperCase();
const pub = (n: number) => `ED${h32(n)}`;
const addr = (n: number) => xrpl.encodeAccountID(new Uint8Array(20).fill(n));

const WALLET = addr(0x10);
const OPS_A = addr(0x11);
const OPS_B = addr(0x12);
const ALICE = addr(0x31);
const BOB = addr(0x32);
const STRANGER = addr(0x40);
const KEYS = [pub(3), pub(7), pub(4), pub(8)]; // xPubA, lawyerPubA, xPubB, lawyerPubB
const SIGNERS = KEYS.map((k) => xrpl.deriveAddress(k));

const DEAL = {
  contractRoot: h32(1),
  signedContractSeal: h32(2),
  walletAddress: WALLET,
  xPubA: KEYS[0],
  xPubB: KEYS[2],
  commitmentA: h32(5),
  commitmentB: h32(6),
  idMethodA: 'zkpassport',
  idMethodB: 'nfc-chip',
  identityPolicy: 'zk-or-chip',
  lawyerPubA: KEYS[1],
  lawyerPubB: KEYS[3],
  lawyerCommitmentA: h32(9),
  lawyerCommitmentB: h32(10),
  lawyerOpsA: OPS_A,
  lawyerOpsB: OPS_B,
  releaserAccount: OPS_B,
  slotPolicyA: h32(11),
  slotPolicyLA: h32(12),
  slotPolicyB: h32(13),
  slotPolicyLB: h32(14),
  pqKeyHashA: h32(15),
  pqKeyHashLA: h32(16),
  pqKeyHashB: h32(17),
  pqKeyHashLB: h32(18),
  signerAccounts: SIGNERS,
  quorum: 4,
  payoutA: `${ALICE}:7`,
  payoutB: BOB,
} as unknown as PublicDealData;

// The Domain the lock step writes: 01 || contractRoot || dealSeal, uppercase hex as rippled returns it (DESIGN 6.6).
const DOMAIN = bytesToHex(domain(hexToBytes(DEAL.contractRoot), dealSeal(DEAL))).toUpperCase();
const CONDITION = `A0258020${'CC'.repeat(32)}810120`;
const ALL_FLAGS =
  lsf.DisableMaster |
  lsf.DepositAuth |
  lsf.DisallowIncomingNFTokenOffer |
  lsf.DisallowIncomingCheck |
  lsf.DisallowIncomingPayChan |
  lsf.DisallowIncomingTrustline;

// biome-ignore lint/suspicious/noExplicitAny: ledger JSON as rippled returns it, mutated freely by the attack rows
type Obj = Record<string, any>;
type World = { acct: Obj; objs: Obj[]; exp: Expected };

const good = (): World => ({
  acct: { Account: WALLET, Flags: ALL_FLAGS, Domain: DOMAIN, OwnerCount: 2 },
  objs: [
    {
      LedgerEntryType: 'SignerList',
      SignerQuorum: 4,
      SignerEntries: SIGNERS.map((Account) => ({ SignerEntry: { Account, SignerWeight: 1 } })),
      index: 'S1',
    },
    { LedgerEntryType: 'DepositPreauth', Account: WALLET, Authorize: OPS_B, index: 'P1' },
    { LedgerEntryType: 'Credential', Issuer: WALLET, Subject: ALICE, Flags: lsf.CredentialAccepted, index: 'C1' },
    { LedgerEntryType: 'Credential', Issuer: WALLET, Subject: BOB, Flags: lsf.CredentialAccepted, index: 'C2' },
    {
      LedgerEntryType: 'Escrow',
      Account: ALICE,
      Destination: WALLET,
      Sequence: 7,
      Amount: '5000000000',
      Condition: CONDITION,
      CancelAfter: 2000,
      index: 'E1',
    },
  ],
  exp: {
    deal: structuredClone(DEAL),
    releaserAccount: OPS_B,
    credentialSubjects: [ALICE, BOB],
    escrow: { owner: ALICE, sequence: 7, amountDrops: '5000000000', conditionHex: CONDITION, minCancelAfter: 1000 },
  },
});
const run = (g: World) => checkLock(g.acct, g.objs, g.exp);
const blockCodes = (g: World) => blocking(run(g)).map((x) => x.code);
const at = (g: World, i: number): Obj => {
  const o = g.objs.at(i);
  if (!o) throw new Error(`no object ${i}`);
  return o;
};
const owned = (g: World, o: Obj) => {
  g.objs.push(o);
  g.acct.OwnerCount++;
};

describe('P1.11-01 starting-code checker tests, Domain in the 01 form', () => {
  it('T-U-09 passes a correctly locked wallet', () => {
    const r = run(good());
    expect(blocking(r)).toEqual([]);
    expect(allOk(r)).toBe(true);
  });

  it.each<[string, (g: World) => void, string]>([
    [
      'T-A-01 setup key left on',
      (g) => {
        g.acct.Flags &= ~lsf.DisableMaster;
      },
      'MASTER_DISABLED',
    ],
    [
      'T-A-02 regular key planted',
      (g) => {
        g.acct.RegularKey = STRANGER;
      },
      'NO_REGULARKEY',
    ],
    [
      'T-A-03 delegate planted',
      (g) => owned(g, { LedgerEntryType: 'Delegate', Account: WALLET, Authorize: STRANGER }),
      'UNEXPECTED_OWNED_DELEGATE',
    ],
    [
      'T-A-04 ticket left on the wallet',
      (g) => owned(g, { LedgerEntryType: 'Ticket', Account: WALLET, TicketSequence: 9 }),
      'TICKET_ALLOWED',
    ],
    [
      'T-A-05 one signer swapped',
      (g) => {
        at(g, 0).SignerEntries[1].SignerEntry.Account = STRANGER;
      },
      'SIGNERS_MATCH_KEYS',
    ],
    [
      'T-A-06 quorum lowered to 2',
      (g) => {
        at(g, 0).SignerQuorum = 2;
      },
      'QUORUM_MATCH',
    ],
    [
      'T-A-08 escrow condition differs',
      (g) => {
        at(g, 4).Condition = `A0258020${'DD'.repeat(32)}810120`;
      },
      'ESCROW_AMOUNT_AND_CONDITION',
    ],
    [
      'T-A-09 escrow amount short',
      (g) => {
        at(g, 4).Amount = '4999999999';
      },
      'ESCROW_AMOUNT_AND_CONDITION',
    ],
    [
      'T-A-10 CancelAfter too soon',
      (g) => {
        at(g, 4).CancelAfter = 999;
      },
      'CANCEL_AFTER_MARGIN',
    ],
    [
      'T-A-16 Domain seal changed by one byte',
      (g) => {
        g.acct.Domain = `${DOMAIN.slice(0, -2)}${DOMAIN.endsWith('00') ? '01' : '00'}`;
      },
      'DOMAIN_IS_SEAL',
    ],
    [
      'T-A-19 NFT buy offer owned by the wallet',
      (g) => owned(g, { LedgerEntryType: 'NFTokenOffer', Owner: WALLET, Amount: '5000000000', Destination: ALICE }),
      'UNEXPECTED_OWNED_NFTOKENOFFER',
    ],
    [
      'T-A-20 Alice pre-approved as a depositor',
      (g) => owned(g, { LedgerEntryType: 'DepositPreauth', Account: WALLET, Authorize: ALICE }),
      'PREAUTH_ONLY_RELEASER',
    ],
    [
      'T-A-21 authorized NFT minter set',
      (g) => {
        g.acct.NFTokenMinter = STRANGER;
      },
      'NO_NFTOKENMINTER',
    ],
    [
      'T-A-23 incoming checks still allowed',
      (g) => {
        g.acct.Flags &= ~lsf.DisallowIncomingCheck;
      },
      'DISALLOW_CHECK',
    ],
    [
      'T-A-24 OwnerCount higher than the objects seen',
      (g) => {
        g.acct.OwnerCount = 3;
      },
      'OWNER_COUNT_MATCHES',
    ],
    [
      'T-A-25 credential not accepted',
      (g) => {
        at(g, 2).Flags = 0;
        g.acct.OwnerCount++;
      },
      'CREDENTIAL_ACCEPTED',
    ],
    [
      'T-A-28a DepositPreauth for an account that is not the sealed releaser',
      (g) => {
        at(g, 1).Authorize = OPS_A;
      },
      'PREAUTH_ONLY_RELEASER',
    ],
  ])('%s', (_name, mutate, code) => {
    const g = good();
    mutate(g);
    expect(blockCodes(g)).toContain(code);
  });

  it('T-A-22 a stranger escrow to the wallet is a warning only; the release is not blocked', () => {
    const g = good();
    g.objs.push({
      LedgerEntryType: 'Escrow',
      Account: STRANGER,
      Destination: WALLET,
      Amount: '1',
      CancelAfter: 5,
      index: 'X',
    });
    const r = run(g);
    expect(allOk(r)).toBe(true);
    expect(r).toContainEqual({ ok: true, level: 'warn', code: 'FOREIGN_INCOMING_ESCROW', detail: 'X' });
  });
});

describe('the other DESIGN 6.9 rules', () => {
  it.each<[string, (g: World) => void, string]>([
    [
      'DepositAuth off',
      (g) => {
        g.acct.Flags &= ~lsf.DepositAuth;
      },
      'DEPOSIT_AUTH_ON',
    ],
    [
      'incoming NFT offers allowed',
      (g) => {
        g.acct.Flags &= ~lsf.DisallowIncomingNFTokenOffer;
      },
      'DISALLOW_NFT_OFFER',
    ],
    [
      'incoming channels allowed',
      (g) => {
        g.acct.Flags &= ~lsf.DisallowIncomingPayChan;
      },
      'DISALLOW_PAYCHAN',
    ],
    [
      'incoming trust lines allowed',
      (g) => {
        g.acct.Flags &= ~lsf.DisallowIncomingTrustline;
      },
      'DISALLOW_TRUSTLINE',
    ],
    [
      'no Flags field at all',
      (g) => {
        delete g.acct.Flags;
      },
      'MASTER_DISABLED',
    ],
    [
      'MintedNFTokens set',
      (g) => {
        g.acct.MintedNFTokens = 1;
      },
      'NO_MINTEDNFTOKENS',
    ],
    [
      'AMMID set',
      (g) => {
        g.acct.AMMID = h32(1);
      },
      'NO_AMMID',
    ],
    [
      'VaultID set',
      (g) => {
        g.acct.VaultID = h32(1);
      },
      'NO_VAULTID',
    ],
    [
      'LoanBrokerID set',
      (g) => {
        g.acct.LoanBrokerID = h32(1);
      },
      'NO_LOANBROKERID',
    ],
    [
      'Sponsor set',
      (g) => {
        g.acct.Sponsor = STRANGER;
      },
      'NO_SPONSOR',
    ],
    [
      'SponsoringOwnerCount set',
      (g) => {
        g.acct.SponsoringOwnerCount = 1;
      },
      'NO_SPONSORINGOWNERCOUNT',
    ],
    [
      'SponsoringAccountCount set',
      (g) => {
        g.acct.SponsoringAccountCount = 1;
      },
      'NO_SPONSORINGACCOUNTCOUNT',
    ],
    [
      'no signer list',
      (g) => {
        g.objs.shift();
        g.acct.OwnerCount--;
      },
      'ONE_SIGNER_LIST',
    ],
    ['two signer lists', (g) => owned(g, structuredClone(at(g, 0))), 'ONE_SIGNER_LIST'],
    [
      'a signer weight of 2',
      (g) => {
        at(g, 0).SignerEntries[0].SignerEntry.SignerWeight = 2;
      },
      'SIGNERS_MATCH_KEYS',
    ],
    [
      'quorum below the total weight',
      (g) => {
        at(g, 0).SignerEntries.push({ SignerEntry: { Account: STRANGER, SignerWeight: 1 } });
      },
      'QUORUM_NEEDS_EVERY_SIGNER',
    ],
    [
      'no DepositPreauth',
      (g) => {
        g.objs.splice(1, 1);
        g.acct.OwnerCount--;
      },
      'ONE_PREAUTH',
    ],
    [
      'a second DepositPreauth for the releaser',
      (g) => owned(g, { LedgerEntryType: 'DepositPreauth', Account: WALLET, Authorize: OPS_B }),
      'ONE_PREAUTH',
    ],
    [
      'the releaser preauth carries credential rules',
      (g) => {
        at(g, 1).AuthorizeCredentials = [{ Credential: { Issuer: STRANGER, CredentialType: '01' } }];
      },
      'PREAUTH_ONLY_RELEASER',
    ],
    [
      'a credential issued to a stranger',
      (g) => {
        at(g, 3).Subject = STRANGER;
      },
      'CREDENTIAL_SUBJECT_EXPECTED',
    ],
    [
      'the escrow is gone',
      (g) => {
        g.objs.pop();
      },
      'QUARANTINE_PRESENT',
    ],
    [
      'the escrow has a FinishAfter',
      (g) => {
        at(g, 4).FinishAfter = 1500;
      },
      'NO_FINISH_DELAY_TRAP',
    ],
    [
      'the escrow has no CancelAfter',
      (g) => {
        delete at(g, 4).CancelAfter;
      },
      'CANCEL_AFTER_MARGIN',
    ],
    [
      'the escrow has no condition',
      (g) => {
        delete at(g, 4).Condition;
      },
      'ESCROW_AMOUNT_AND_CONDITION',
    ],
    [
      'OwnerCount lower than the objects seen',
      (g) => {
        g.acct.OwnerCount = 1;
      },
      'OWNER_COUNT_MATCHES',
    ],
    [
      'an Offer owned by the wallet',
      (g) => owned(g, { LedgerEntryType: 'Offer', Account: WALLET }),
      'UNEXPECTED_OWNED_OFFER',
    ],
  ])('%s', (_name, mutate, code) => {
    const g = good();
    mutate(g);
    expect(blockCodes(g)).toContain(code);
  });

  it('CANCEL_AFTER_MARGIN holds exactly at the margin', () => {
    const g = good();
    at(g, 4).CancelAfter = g.exp.escrow.minCancelAfter;
    expect(allOk(run(g))).toBe(true);
  });

  it('the hex case of the escrow condition does not matter', () => {
    const g = good();
    at(g, 4).Condition = CONDITION.toLowerCase();
    expect(allOk(run(g))).toBe(true);
  });

  it('TICKET_ALLOWED after funding: only the recorded exit-slot ticket passes', () => {
    const g = good();
    owned(g, { LedgerEntryType: 'Ticket', Account: WALLET, TicketSequence: 9 });
    g.exp.allowedTicketSequences = [9];
    expect(allOk(run(g))).toBe(true);
    at(g, -1).TicketSequence = 10;
    expect(blockCodes(g)).toEqual(['TICKET_ALLOWED']);
  });

  it('objects other accounts own that point at the wallet are INCOMING_<TYPE> warnings', () => {
    const g = good();
    g.objs.push({ LedgerEntryType: 'Check', Account: STRANGER, Destination: WALLET, index: 'K' });
    g.objs.push({ LedgerEntryType: 'PayChannel', Account: STRANGER, Destination: WALLET, index: 'L' });
    const r = run(g);
    expect(allOk(r)).toBe(true);
    expect(r.filter((x) => x.level === 'warn').map((x) => x.code)).toEqual(['INCOMING_CHECK', 'INCOMING_PAYCHANNEL']);
  });

  it('an accepted credential is not counted as owned; a pending one is', () => {
    const g = good();
    at(g, 2).Flags = 0;
    expect(blockCodes(g)).toEqual(['CREDENTIAL_ACCEPTED', 'OWNER_COUNT_MATCHES']);
  });
});

describe('DOMAIN_IS_SEAL (P1.11-03, P1.11-04, T-A-16)', () => {
  const domainFails = (value: unknown) => {
    const g = good();
    g.acct.Domain = value;
    return blockCodes(g);
  };

  it('P1.11-02 a good wallet emits DOMAIN_IS_SEAL and RELEASER_IS_OPS_B as passing', () => {
    const r = run(good());
    for (const code of ['DOMAIN_IS_SEAL', 'RELEASER_IS_OPS_B'])
      expect(r).toContainEqual({ ok: true, level: 'block', code, detail: undefined });
    expect(blocking(r)).toEqual([]);
  });

  it('P1.11-03 Domain that does not start with 01', () => {
    expect(domainFails(`00${DOMAIN.slice(2)}`)).toEqual(['DOMAIN_IS_SEAL']);
    expect(domainFails(`02${DOMAIN.slice(2)}`)).toEqual(['DOMAIN_IS_SEAL']);
  });

  it('P1.11-03 Domain that is not 01 || contractRoot || dealSeal', () => {
    const seal = DOMAIN.slice(66);
    const root = DOMAIN.slice(2, 66);
    expect(domainFails(`01${seal}${root}`)).toEqual(['DOMAIN_IS_SEAL']); // halves swapped
    expect(domainFails(`01${h32(0x99)}${seal}`)).toEqual(['DOMAIN_IS_SEAL']); // another contract root
    expect(domainFails(`01${root}${h32(0x99)}`)).toEqual(['DOMAIN_IS_SEAL']); // another seal
  });

  it('P1.11-03 the seal is recomputed from the sealed deal, so any sealed field change trips it', () => {
    for (const change of [
      { payoutB: `${BOB}:1` },
      { lawyerOpsA: STRANGER },
      { identityPolicy: 'chip', idMethodA: 'nfc-chip' },
      { walletAddress: STRANGER },
    ]) {
      const g = good();
      g.exp.deal = { ...g.exp.deal, ...change } as PublicDealData;
      expect(blockCodes(g), JSON.stringify(change)).toEqual(['DOMAIN_IS_SEAL']);
    }
  });

  it('P1.11-03 a deal the seal refuses fails closed instead of throwing', () => {
    for (const change of [{ contractRoot: 'ZZ' }, { quorum: 2 ** 32 }, { payoutA: `${ALICE}:01` }]) {
      const g = good();
      g.exp.deal = { ...g.exp.deal, ...change } as unknown as PublicDealData;
      expect(blockCodes(g), JSON.stringify(change)).toEqual(['DOMAIN_IS_SEAL']);
    }
  });

  it('P1.11-04 Domain of 64 or 66 bytes', () => {
    expect(domainFails(DOMAIN.slice(0, -2))).toEqual(['DOMAIN_IS_SEAL']);
    expect(domainFails(`${DOMAIN}00`)).toEqual(['DOMAIN_IS_SEAL']);
  });

  it('hostile Domain values fail closed without throwing', () => {
    for (const v of [undefined, '', 42, null, {}, `${DOMAIN}0`, `${DOMAIN.slice(0, -2)}GG`, ` ${DOMAIN.slice(1)}`])
      expect(domainFails(v), String(v)).toEqual(['DOMAIN_IS_SEAL']);
  });

  it('the hex case of Domain does not matter (the bytes do)', () => {
    expect(domainFails(DOMAIN.toLowerCase())).toEqual([]);
  });
});

describe('RELEASER_IS_OPS_B (P1.11-05)', () => {
  it('fails when the expected releaser is not the sealed lawyerOpsB', () => {
    const g = good();
    g.exp.releaserAccount = OPS_A;
    expect(blockCodes(g)).toEqual(['RELEASER_IS_OPS_B']);
  });

  it('fails when the sealed releaserAccount is not the sealed lawyerOpsB (the seal also refuses it)', () => {
    const g = good();
    g.exp.deal = { ...g.exp.deal, releaserAccount: OPS_A } as PublicDealData;
    at(g, 1).Authorize = OPS_A;
    g.exp.releaserAccount = OPS_A;
    expect(blockCodes(g)).toEqual(['DOMAIN_IS_SEAL', 'RELEASER_IS_OPS_B']);
  });

  it('is always checked, even for an empty wallet', () => {
    const r = checkLock({ Account: WALLET }, [], good().exp);
    expect(r.filter((x) => x.code === 'RELEASER_IS_OPS_B')).toEqual([
      { ok: true, level: 'block', code: 'RELEASER_IS_OPS_B', detail: undefined },
    ]);
  });
});

describe('signer keys come from the sealed deal', () => {
  it('a wallet whose signer list matches keys outside the seal fails', () => {
    const g = good();
    g.exp.deal = { ...g.exp.deal, lawyerPubB: pub(0x55) } as PublicDealData;
    expect(blockCodes(g)).toEqual(['DOMAIN_IS_SEAL', 'SIGNERS_MATCH_KEYS']);
  });

  it('an undecodable sealed key fails SIGNERS_MATCH_KEYS instead of throwing', () => {
    const g = good();
    g.exp.deal = { ...g.exp.deal, xPubA: 'EDZZ' } as PublicDealData;
    expect(blockCodes(g)).toEqual(['DOMAIN_IS_SEAL', 'SIGNERS_MATCH_KEYS']);
  });
});

describe('DQ-11 Oracle objects name their owner in Owner (fixed)', () => {
  it('an Oracle owned by the wallet blocks', () => {
    const g = good();
    owned(g, { LedgerEntryType: 'Oracle', Owner: WALLET, index: 'O' });
    expect(blockCodes(g)).toEqual(['UNEXPECTED_OWNED_ORACLE']);
  });

  it("another account's Oracle is a warning, read from Owner", () => {
    const g = good();
    g.objs.push({ LedgerEntryType: 'Oracle', Owner: STRANGER, index: 'O' });
    const r = run(g);
    expect(allOk(r)).toBe(true);
    expect(r).toContainEqual({ ok: true, level: 'warn', code: 'INCOMING_ORACLE', detail: 'O' });
  });
});

// Every LEDGER_ENTRY in rippled develop at commit ef5064e (2026-10-20, "feat: Remove XChainBridge feature (#8255)"),
// in macro order, with the field that names the owner there (undefined: the entry has no owner field).
// Source: https://github.com/XRPLF/rippled/blob/ef5064eeb9e0ce467fae4694d58609de84109131/include/xrpl/protocol/detail/ledger_entries.macro
// (snapshot: build/tmp/1.11/ledger_entries.macro@ef5064e)
const MACRO_TYPES: readonly (readonly [string, string | undefined])[] = [
  ['NFTokenOffer', 'Owner'],
  ['Check', 'Account'],
  ['DID', 'Account'],
  ['NegativeUNL', undefined],
  ['NFTokenPage', undefined],
  ['SignerList', 'Owner'],
  ['Ticket', 'Account'],
  ['AccountRoot', 'Account'],
  ['DirectoryNode', 'Owner'],
  ['Amendments', undefined],
  ['LedgerHashes', undefined],
  ['Offer', 'Account'],
  ['DepositPreauth', 'Account'],
  ['RippleState', undefined],
  ['FeeSettings', undefined],
  ['Escrow', 'Account'],
  ['PayChannel', 'Account'],
  ['AMM', 'Account'],
  ['MPTokenIssuance', 'Issuer'],
  ['MPToken', 'Account'],
  ['Oracle', 'Owner'],
  ['Credential', 'Issuer'],
  ['PermissionedDomain', 'Owner'],
  ['Delegate', 'Account'],
  ['Vault', 'Owner'],
  ['LoanBroker', 'Owner'],
  ['Loan', 'Borrower'],
  ['Sponsorship', 'Owner'],
  ['TransactionProposal', 'Owner'],
];
// Removed from develop by #8255 but still in the xrpl.js 5.3.0 codec (and possibly in old ledgers): covered too.
// Source: https://github.com/XRPLF/rippled/blob/ef5064eeb9e0ce467fae4694d58609de84109131~1/include/xrpl/protocol/detail/ledger_entries.macro
const REMOVED_TYPES: readonly (readonly [string, string])[] = [
  ['Bridge', 'Account'],
  ['XChainOwnedClaimID', 'Account'],
  ['XChainOwnedCreateAccountClaimID', 'Account'],
];
// DESIGN 6.9: the wallet may own a signer list, the releaser's DepositPreauth, the credentials it issues and (after
// funding) the exit ticket. Each has its own rule, so an extra one still blocks under that rule.
const ALLOW_LISTED = new Set(['SignerList', 'DepositPreauth', 'Credential', 'Ticket']);

describe('every ledger entry type, owned by the wallet, blocks unless allow-listed', () => {
  it('the table matches the xrpl.js 5.3.0 codec list (second source), apart from the known differences', () => {
    const req = createRequire(createRequire(import.meta.url).resolve('xrpl'));
    const defs = JSON.parse(readFileSync(req.resolve('ripple-binary-codec/dist/enums/definitions.json'), 'utf8'));
    const codec = Object.keys(defs.LEDGER_ENTRY_TYPES)
      .filter((t) => t !== 'Invalid')
      .sort();
    const ours = [...MACRO_TYPES, ...REMOVED_TYPES].map(([t]) => t);
    expect(ours.filter((t) => !codec.includes(t))).toEqual(['TransactionProposal']); // newer than xrpl.js 5.3.0
    expect(codec.filter((t) => !ours.includes(t))).toEqual([]);
    expect(MACRO_TYPES).toHaveLength(29);
  });

  it.each([...MACRO_TYPES, ...REMOVED_TYPES])('%s owned via %s', (type, ownerField) => {
    const g = good();
    owned(g, { LedgerEntryType: type, ...(ownerField ? { [ownerField]: WALLET } : {}), index: 'N' });
    const codes = blockCodes(g);
    const unexpected = `UNEXPECTED_OWNED_${type.toUpperCase()}`;
    if (ALLOW_LISTED.has(type)) {
      expect(codes).not.toContain(unexpected);
      expect(codes.length).toBeGreaterThan(0);
    } else expect(codes).toEqual([unexpected]);
  });
});

const sorted = (f: Finding[]) => f.map((x) => JSON.stringify(x)).sort();
const extraPool: Obj[] = [
  { LedgerEntryType: 'Escrow', Account: STRANGER, Destination: WALLET, Amount: '1', index: 'Y1' },
  { LedgerEntryType: 'Check', Account: STRANGER, Destination: WALLET, index: 'Y2' },
  { LedgerEntryType: 'Ticket', Account: WALLET, TicketSequence: 3, index: 'Y3' },
  { LedgerEntryType: 'Credential', Issuer: WALLET, Subject: STRANGER, Flags: 0, index: 'Y4' },
  { LedgerEntryType: 'DepositPreauth', Account: WALLET, Authorize: ALICE, index: 'Y5' },
  // A second escrow from Alice with the same amount and condition, but a FinishAfter trap.
  { ...good().objs[4], FinishAfter: 1, Sequence: 8, index: 'Y6' },
  { ...good().objs[4], CancelAfter: 1, Sequence: 9, index: 'Y7' },
];

describe('properties', () => {
  it('P1.11-06 any random extra object type owned by the wallet blocks (fail closed)', () => {
    const anyType = fc.oneof(fc.constantFrom(...MACRO_TYPES.map(([t]) => t)), fc.string({ maxLength: 80 }));
    fc.assert(
      fc.property(anyType, fc.boolean(), (type, counted) => {
        const g = good();
        g.objs.push({ LedgerEntryType: type, Account: WALLET, Owner: WALLET, Issuer: WALLET, Borrower: WALLET });
        if (counted) g.acct.OwnerCount++;
        expect(allOk(run(g))).toBe(false);
      }),
      { numRuns: 500 },
    );
  });

  it('P1.11-07 shuffling the objects gives the same findings', () => {
    const worlds = fc.subarray(extraPool).chain((extra) => {
      const objs = [...good().objs, ...extra];
      return fc.tuple(fc.constant(objs), fc.shuffledSubarray(objs, { minLength: objs.length }));
    });
    fc.assert(
      fc.property(worlds, ([objs, shuffled]) => {
        const g = good();
        g.acct.OwnerCount = 2 + objs.length - 5;
        expect(sorted(run({ ...g, objs: shuffled }))).toEqual(sorted(run({ ...g, objs })));
      }),
      { numRuns: 300 },
    );
  });

  it('a second matching escrow with a trap blocks whatever its position', () => {
    for (const trap of extraPool.slice(5)) {
      const g = good();
      g.objs.splice(4, 0, trap);
      const ga = good();
      ga.objs.push(trap);
      expect(blockCodes(g)).toEqual(blockCodes(ga));
      expect(allOk(run(g))).toBe(false);
    }
  });

  it('every finding fits the frozen contracts Finding schema, even for hostile types and a 32-entry signer list', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 200 }), (type) => {
        const g = good();
        owned(g, { LedgerEntryType: type, Account: WALLET });
        g.objs.push({ LedgerEntryType: type, Account: STRANGER, index: 'W' });
        at(g, 0).SignerEntries = Array.from({ length: 32 }, (_, i) => ({
          SignerEntry: { Account: addr(0x60 + i), SignerWeight: 1 },
        }));
        for (const f of run(g)) expect(FindingSchema.safeParse(f).success, JSON.stringify(f)).toBe(true);
      }),
      { numRuns: 300 },
    );
  });

  it('the good wallet emits every fixed code of DESIGN 6.9 except the per-ticket rule and the warning', () => {
    const codes = run(good()).map((x) => x.code);
    expect(LOCK_CODES.filter((c) => !codes.includes(c))).toEqual(['TICKET_ALLOWED', 'FOREIGN_INCOMING_ESCROW']);
  });
});

describe('design questions (IMPLEMENTATION Appendix B): today the checker follows DESIGN 6.9 as written', () => {
  it('DQ-1 (current behavior) after funding the escrow is gone, so QUARANTINE_PRESENT and ESCROW_AMOUNT_AND_CONDITION fail', () => {
    const g = good();
    g.objs.pop();
    expect(blockCodes(g)).toEqual(['QUARANTINE_PRESENT', 'ESCROW_AMOUNT_AND_CONDITION']);
  });
  it("DQ-1 phase 'funded': after the EscrowFinish validated, exactly the four escrow rules are skipped", () => {
    const g = good();
    g.objs.pop();
    const funded = (x: World) => checkLock(x.acct, x.objs, { ...x.exp, phase: 'funded' });
    expect(blocking(funded(g))).toEqual([]);
    const codes = (f: { code: string }[]) => f.map((x) => x.code);
    const escrowRules = [
      'QUARANTINE_PRESENT',
      'ESCROW_AMOUNT_AND_CONDITION',
      'NO_FINISH_DELAY_TRAP',
      'CANCEL_AFTER_MARGIN',
    ];
    expect(codes(run(good())).filter((c) => !codes(funded(good())).includes(c))).toEqual(escrowRules);
    const keyed = good();
    keyed.acct.RegularKey = 'rX';
    expect(codes(blocking(funded(keyed)))).toEqual(['NO_REGULARKEY']);
  });

  it('DQ-2 (current behavior) with no credentials at all, the credential rules pass', () => {
    const g = good();
    g.objs.splice(2, 2);
    expect(allOk(run(g))).toBe(true);
  });
  it.todo('DQ-2 require exactly one accepted credential for each expected subject');

  it('DQ-4 (current behavior) a Sponsorship that only names the wallet is counted as owned and blocks', () => {
    const g = good();
    owned(g, { LedgerEntryType: 'Sponsorship', Owner: STRANGER, Sponsee: WALLET });
    expect(blockCodes(g)).toEqual(['UNEXPECTED_OWNED_SPONSORSHIP']);
  });
  it.todo('DQ-4 decide ownership per type from the right field; objects that only point at the wallet are warnings');

  it('DQ-5 (current behavior) the escrow is matched by owner, amount and condition, not by its sequence', () => {
    const g = good();
    at(g, 4).Sequence = 99;
    expect(allOk(run(g))).toBe(true);
  });
  it.todo('DQ-5 match the quarantine escrow by owner plus sequence');

  it('DQ-12 (current behavior) a DID owned by the wallet blocks, even one holding the seal', () => {
    const g = good();
    owned(g, { LedgerEntryType: 'DID', Account: WALLET, Data: DOMAIN });
    expect(blockCodes(g)).toEqual(['UNEXPECTED_OWNED_DID']);
  });
  it.todo('DQ-12 remove the DID seal option from DESIGN 7.1, or allow exactly one DID holding the seal');

  it('DQ-13 (current behavior) an unknown AccountRoot authority field passes (the field check is a block-list)', () => {
    const g = good();
    g.acct.FutureAuthority = STRANGER;
    expect(allOk(run(g))).toBe(true);
  });
  it.todo('DQ-13 allow-list the AccountRoot fields');
});
