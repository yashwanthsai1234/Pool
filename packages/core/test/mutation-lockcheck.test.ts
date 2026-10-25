// Task 5.4: tests added to kill surviving StrykerJS mutants in lockcheck.ts. Equivalent mutants are explained inline.
import type { PublicDealData } from '@legx/contracts/deal';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import * as xrpl from 'xrpl';
import { dealSeal, domain } from '../src/dealcore.ts';
import { blocking, checkLock, type Expected, lsf } from '../src/lockcheck.ts';

const h32 = (n: number) => bytesToHex(new Uint8Array(32).fill(n)).toUpperCase();
const addr = (n: number) => xrpl.encodeAccountID(new Uint8Array(20).fill(n));
const WALLET = addr(0x10);
const OPS_B = addr(0x12);
const ALICE = addr(0x31);
const BOB = addr(0x32);
const OTHER = addr(0x40);
const KEYS = [3, 7, 4, 8].map((n) => `ED${h32(n)}`);
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
  lawyerOpsA: addr(0x11),
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
const DOMAIN = bytesToHex(domain(hexToBytes(DEAL.contractRoot), dealSeal(DEAL))).toUpperCase();
const COND = `A0258020${'CC'.repeat(32)}810120`;
const FLAGS =
  lsf.DisableMaster |
  lsf.DepositAuth |
  lsf.DisallowIncomingNFTokenOffer |
  lsf.DisallowIncomingCheck |
  lsf.DisallowIncomingPayChan |
  lsf.DisallowIncomingTrustline;

// biome-ignore lint/suspicious/noExplicitAny: ledger JSON
type Obj = Record<string, any>;
const world = (extra: Obj[] = [], ownedExtra = 0) => ({
  acct: { Account: WALLET, Flags: FLAGS, Domain: DOMAIN, OwnerCount: 2 + ownedExtra } as Obj,
  objs: [
    {
      LedgerEntryType: 'SignerList',
      SignerQuorum: 4,
      SignerEntries: SIGNERS.map((Account) => ({ SignerEntry: { Account, SignerWeight: 1 } })),
      index: 'S1',
    },
    { LedgerEntryType: 'DepositPreauth', Account: WALLET, Authorize: OPS_B, index: 'P1' },
    {
      LedgerEntryType: 'Escrow',
      Account: ALICE,
      Destination: WALLET,
      Amount: '5000000000',
      Condition: COND,
      CancelAfter: 2000,
      index: 'E1',
    },
    ...extra,
  ] as Obj[],
  exp: {
    deal: structuredClone(DEAL),
    releaserAccount: OPS_B,
    credentialSubjects: [ALICE, BOB],
    escrow: { owner: ALICE, sequence: 7, amountDrops: '5000000000', conditionHex: COND, minCancelAfter: 1000 },
  } as Expected,
});
const run = (w: ReturnType<typeof world>) => checkLock(w.acct, w.objs, w.exp);
const codes = (w: ReturnType<typeof world>) => blocking(run(w)).map((f) => f.code);

describe('ownerOf and typeCode (5.4 lockcheck)', () => {
  // Every type that names its owner in Account, with the owner elsewhere: an incoming warning, never a block.
  it.each(['Escrow', 'Check', 'PayChannel', 'Offer', 'DepositPreauth', 'Ticket', 'DID', 'Delegate'])(
    '%s owned by another account is only an INCOMING warning',
    (t) => {
      const w = world([{ LedgerEntryType: t, Account: OTHER, Destination: OTHER, index: 'X' }]);
      const r = run(w);
      expect(blocking(r)).toEqual([]);
      expect(r).toContainEqual({ ok: true, level: 'warn', code: `INCOMING_${t.toUpperCase()}`, detail: 'X' });
    },
  );
  it.each(['Escrow', 'Check', 'PayChannel', 'Offer', 'DID', 'Delegate'])('%s owned by the wallet blocks', (t) => {
    const w = world([{ LedgerEntryType: t, Account: WALLET, Destination: OTHER, index: 'X' }], 1);
    expect(codes(w)).toContain(`UNEXPECTED_OWNED_${t.toUpperCase()}`);
  });
  it.each(['NFTokenOffer', 'Oracle'])('%s names its owner in Owner', (t) => {
    const other = world([{ LedgerEntryType: t, Owner: OTHER, Account: WALLET, index: 'X' }]);
    expect(blocking(run(other))).toEqual([]);
    const mine = world([{ LedgerEntryType: t, Owner: WALLET, Account: OTHER, index: 'X' }], 1);
    expect(codes(mine)).toEqual([`UNEXPECTED_OWNED_${t.toUpperCase()}`]);
  });
  it('a Credential is owned by the subject once accepted, by the issuer before', () => {
    const accepted = { LedgerEntryType: 'Credential', Issuer: OTHER, Subject: WALLET, Flags: lsf.CredentialAccepted };
    expect(codes(world([accepted], 1))).toEqual(['UNEXPECTED_OWNED_CREDENTIAL']);
    const pendingElsewhere = { LedgerEntryType: 'Credential', Issuer: OTHER, Subject: WALLET, Flags: 0 };
    expect(codes(world([pendingElsewhere]))).toEqual([]);
    const acceptedElsewhere = { LedgerEntryType: 'Credential', Issuer: WALLET, Subject: OTHER, Flags: 0 };
    expect(codes(world([acceptedElsewhere], 1))).toContain('CREDENTIAL_ACCEPTED');
  });
  it('unknown and unowned-by-type objects count as owned and fail closed', () => {
    for (const t of ['RippleState', 'NFTokenPage', 'Brand_New']) {
      const w = world([{ LedgerEntryType: t, index: 'X' }], 1);
      expect(codes(w)).toEqual([`UNEXPECTED_OWNED_${t.toUpperCase()}`]);
    }
  });
  it('typeCode upper-cases and replaces characters outside A-Z0-9_', () => {
    const w = world([{ LedgerEntryType: 'foo-Bar.9', index: 'X' }], 1);
    expect(codes(w)).toEqual(['UNEXPECTED_OWNED_FOO_BAR_9']);
  });
  it('typeCode caps the length at 64 and never yields an empty code', () => {
    const long = world([{ LedgerEntryType: 'a'.repeat(100), index: 'X' }], 1);
    expect(codes(long)).toEqual([`UNEXPECTED_OWNED_${'A'.repeat(64)}`.slice(0, 'UNEXPECTED_OWNED_'.length + 64)]);
    const none = world([{ index: 'X' }], 1);
    expect(codes(none)).toEqual(['UNEXPECTED_OWNED_UNDEFINED']);
  });
});

describe('domainIsSeal (5.4 lockcheck)', () => {
  const finding = (domainValue: unknown) => {
    const w = world();
    w.acct.Domain = domainValue;
    return run(w).find((f) => f.code === 'DOMAIN_IS_SEAL');
  };
  it('accepts exactly the 65-byte seal, in either hex case', () => {
    expect(finding(DOMAIN)?.ok).toBe(true);
    expect(finding(DOMAIN.toLowerCase())?.ok).toBe(true);
  });
  it('rejects anything else with ok === false', () => {
    for (const bad of [undefined, 5, `${DOMAIN}00`, `00${DOMAIN}`, DOMAIN.slice(2), `${DOMAIN.slice(0, -1)}G`, '']) {
      expect(finding(bad)?.ok).toBe(false);
    }
  });
  it('a deal the seal refuses fails the rule without throwing', () => {
    const w = world();
    w.exp.deal = { ...DEAL, contractRoot: 'zz' } as unknown as PublicDealData;
    expect(run(w).find((f) => f.code === 'DOMAIN_IS_SEAL')?.ok).toBe(false);
  });
  // Equivalent mutants: dropping the first `^`/`$` anchor or turning || into && cannot change the result, because a
  // string of the wrong shape then fails the byte comparison against the recomputed Domain anyway.
});

describe('signer list and counts (5.4 lockcheck)', () => {
  it('an undecodable sealed key derives the empty address, which must match literally', () => {
    const w = world();
    w.exp.deal = { ...DEAL, xPubA: 'not-a-key' } as unknown as PublicDealData;
    (w.objs[0] as Obj).SignerEntries[0].SignerEntry.Account = '';
    expect(codes(w)).not.toContain('SIGNERS_MATCH_KEYS');
  });
  it('SIGNERS_MATCH_KEYS detail lists the ledger signers; quorum details are exact', () => {
    const w = world();
    (w.objs[0] as Obj).SignerEntries[0].SignerEntry.SignerWeight = 2;
    (w.objs[0] as Obj).SignerQuorum = 5;
    const r = run(w);
    expect(r.find((f) => f.code === 'SIGNERS_MATCH_KEYS')?.detail).toContain(`${SIGNERS[0]}:2`);
    expect(r.find((f) => f.code === 'QUORUM_MATCH')?.detail).toBe('5');
    const q = r.find((f) => f.code === 'QUORUM_NEEDS_EVERY_SIGNER');
    expect(q?.ok).toBe(true);
    (w.objs[0] as Obj).SignerQuorum = 4;
    expect(run(w).find((f) => f.code === 'QUORUM_NEEDS_EVERY_SIGNER')?.detail).toBe('4/5');
  });
  it('NO_<field> passes for 0 and fails for any other value, with the value as detail', () => {
    const w = world();
    w.acct.MintedNFTokens = 0;
    expect(codes(w)).toEqual([]);
    w.acct.MintedNFTokens = 1;
    w.acct.AMMID = 'X';
    const r = blocking(run(w));
    expect(r.map((f) => [f.code, f.detail])).toEqual([
      ['NO_MINTEDNFTOKENS', '1'],
      ['NO_AMMID', 'X'],
    ]);
  });
  it('RELEASER_IS_OPS_B needs both the expected and the sealed releaser to be ops B', () => {
    const a = world();
    a.exp.releaserAccount = OTHER;
    expect(blocking(run(a))).toEqual([
      { ok: false, level: 'block', code: 'RELEASER_IS_OPS_B', detail: `${OTHER} ${OPS_B}` },
    ]);
    const b = world();
    b.exp.deal = { ...DEAL, releaserAccount: OTHER } as unknown as PublicDealData;
    expect(codes(b)).toContain('RELEASER_IS_OPS_B');
    const c = world();
    expect(run(c).find((f) => f.code === 'RELEASER_IS_OPS_B')?.detail).toBeUndefined();
  });
  it('OWNER_COUNT_MATCHES reports both counts, and a pending credential counts once', () => {
    const w = world();
    w.acct.OwnerCount = 9;
    expect(blocking(run(w))[0]?.detail).toBe('9 vs 2');
    const p = world([{ LedgerEntryType: 'Credential', Issuer: WALLET, Subject: ALICE, Flags: 0 }], 1);
    expect(codes(p)).toEqual(['CREDENTIAL_ACCEPTED']);
    const q = world([{ LedgerEntryType: 'Credential', Issuer: WALLET, Subject: ALICE, Flags: 0 }], 0);
    expect(codes(q)).toEqual(['CREDENTIAL_ACCEPTED', 'OWNER_COUNT_MATCHES']);
  });
  it('a foreign incoming escrow only warns; one from the quarantine owner is not foreign', () => {
    const foreign = world([
      { LedgerEntryType: 'Escrow', Account: OTHER, Destination: WALLET, Amount: '1', index: 'F' },
    ]);
    expect(blocking(run(foreign))).toEqual([]);
    expect(run(foreign)).toContainEqual({ ok: true, level: 'warn', code: 'FOREIGN_INCOMING_ESCROW', detail: 'F' });
    // The wallet's own escrow to itself is an owned object, not an incoming one.
    const self = world([{ LedgerEntryType: 'Escrow', Account: WALLET, Destination: WALLET, index: 'S' }], 1);
    expect(codes(self)).toEqual(['UNEXPECTED_OWNED_ESCROW']);
    // An escrow to someone else, owned by someone else, is not ours either.
    const unrelated = world([{ LedgerEntryType: 'Escrow', Account: OTHER, Destination: BOB, index: 'U' }]);
    expect(run(unrelated).find((f) => f.code === 'INCOMING_ESCROW')?.detail).toBe('U');
  });
  it('credentials issued by someone else, preauths and tickets of someone else are not ours', () => {
    const w = world([
      { LedgerEntryType: 'Credential', Issuer: OTHER, Subject: OTHER, Flags: lsf.CredentialAccepted, index: 'C' },
      { LedgerEntryType: 'DepositPreauth', Account: OTHER, Authorize: ALICE, index: 'D' },
      { LedgerEntryType: 'Ticket', Account: OTHER, TicketSequence: 1, index: 'T' },
    ]);
    expect(codes(w)).toEqual([]);
  });
  it('ticket allow-list and preauth details', () => {
    const w = world([{ LedgerEntryType: 'Ticket', Account: WALLET, TicketSequence: 9, index: 'T' }], 1);
    w.exp.allowedTicketSequences = [9];
    expect(codes(w)).toEqual([]);
    w.exp.allowedTicketSequences = [1, 2];
    expect(blocking(run(w))[0]).toMatchObject({ code: 'TICKET_ALLOWED', detail: '9' });
    const noList = world([{ LedgerEntryType: 'Ticket', Account: WALLET, TicketSequence: 9 }], 1);
    expect(codes(noList)).toEqual(['TICKET_ALLOWED']);
    const pre = world([{ LedgerEntryType: 'DepositPreauth', Account: WALLET, Authorize: OPS_B }], 1);
    expect(codes(pre)).toEqual(['ONE_PREAUTH']);
    const cred = world();
    (cred.objs[1] as Obj).AuthorizeCredentials = [{}];
    expect(codes(cred)).toEqual(['PREAUTH_ONLY_RELEASER']);
  });
  it('credential subjects are checked against the expected list', () => {
    const w = world([{ LedgerEntryType: 'Credential', Issuer: WALLET, Subject: OTHER, Flags: lsf.CredentialAccepted }]);
    expect(blocking(run(w))[0]).toMatchObject({ code: 'CREDENTIAL_SUBJECT_EXPECTED', detail: OTHER });
  });
});

describe('quarantine escrow (5.4 lockcheck)', () => {
  it('QUARANTINE_PRESENT counts escrows by owner and destination only', () => {
    const w = world();
    w.objs = w.objs.filter((o) => o.LedgerEntryType !== 'Escrow');
    expect(blocking(run(w)).map((f) => [f.code, f.detail])).toEqual([
      ['QUARANTINE_PRESENT', '0'],
      ['ESCROW_AMOUNT_AND_CONDITION', undefined],
    ]);
    const wrongOwner = world();
    (wrongOwner.objs[2] as Obj).Account = OTHER;
    expect(codes(wrongOwner)).toEqual(['QUARANTINE_PRESENT', 'ESCROW_AMOUNT_AND_CONDITION']);
    const wrongDest = world();
    (wrongDest.objs[2] as Obj).Destination = OTHER;
    expect(codes(wrongDest)).toContain('QUARANTINE_PRESENT');
  });
  it('the condition compares case-insensitively and the amount exactly', () => {
    const w = world();
    (w.objs[2] as Obj).Condition = COND.toLowerCase();
    expect(codes(w)).toEqual([]);
    (w.objs[2] as Obj).Condition = undefined;
    expect(codes(w)).toEqual(['ESCROW_AMOUNT_AND_CONDITION']);
  });
  it('every matching escrow must pass the timing rules, in any order', () => {
    const second = { ...world().objs[2], CancelAfter: 5, index: 'E2' } as Obj;
    const a = world([second]);
    const r = blocking(run(a));
    expect(r.map((f) => [f.code, f.detail])).toEqual([['CANCEL_AFTER_MARGIN', '2000,5']]);
    const b = world([{ ...second, CancelAfter: 3000 }]);
    b.objs.reverse();
    expect(codes(b)).toEqual([]);
    const trap = world([{ ...second, CancelAfter: 3000, FinishAfter: 1 }]);
    expect(codes(trap)).toEqual(['NO_FINISH_DELAY_TRAP']);
    const missing = world();
    (missing.objs[2] as Obj).CancelAfter = undefined;
    expect(codes(missing)).toEqual(['CANCEL_AFTER_MARGIN']);
    const exact = world();
    (exact.objs[2] as Obj).CancelAfter = 1000;
    expect(codes(exact)).toEqual([]);
  });
});

describe('blocking (5.4 lockcheck)', () => {
  it('ignores warnings and passing blocks', () => {
    const r = [
      { ok: true, level: 'block' as const, code: 'A' },
      { ok: true, level: 'warn' as const, code: 'B' },
      { ok: false, level: 'warn' as const, code: 'C' },
      { ok: false, level: 'block' as const, code: 'D' },
    ];
    expect(blocking(r).map((f) => f.code)).toEqual(['D']);
  });
});
