// Pure check of the deal wallet's on-ledger state, read from a VALIDATED ledger (every account_objects page).
// Allow-list design: anything not explicitly expected fails closed.
// Source: DESIGN.md 6.9 "Lock checker"; flags and fields: https://xrpl.org/docs/references/protocol/ledger-data/ledger-entry-types/accountroot
import type { PublicDealData } from '@legx/contracts/deal';
import type { Finding } from '@legx/contracts/records';
import { deriveAddress } from 'xrpl';
import { bytesToHex, dealSeal, domain, hexToBytes } from './dealcore.ts';

export type { Finding };

export const lsf = {
  DisableMaster: 0x00100000,
  DepositAuth: 0x01000000,
  DisallowIncomingNFTokenOffer: 0x04000000,
  DisallowIncomingCheck: 0x08000000,
  DisallowIncomingPayChan: 0x10000000,
  DisallowIncomingTrustline: 0x20000000,
  CredentialAccepted: 0x00010000,
} as const;

export interface Expected {
  deal: PublicDealData; // the sealed public data: the four signer keys, lawyerOpsA/B, releaserAccount, the Domain inputs
  releaserAccount: string; // the account expected to submit the finish (lawyer B's funded operations account)
  credentialSubjects: string[]; // Alice's and Bob's accounts
  escrow: {
    owner: string;
    sequence: number /* OfferSequence for EscrowFinish */;
    amountDrops: string;
    conditionHex: string;
    minCancelAfter: number; // the validated close_time + 86,400 at check time
  };
  allowedTicketSequences?: number[]; // after funding only (exit slot)
  /**
   * `funded`: the EscrowFinish validated, so the quarantine escrow is gone and its four rules (QUARANTINE_PRESENT,
   * ESCROW_AMOUNT_AND_CONDITION, NO_FINISH_DELAY_TRAP, CANCEL_AFTER_MARGIN) are skipped. Default `pre-funding`.
   * Temporary rule linked to DQ-1 (IMPLEMENTATION 3.5 "Think hard", Appendix B; build/ISSUES.md I-3.5-a).
   */
  phase?: 'pre-funding' | 'funded';
}

// biome-ignore lint/suspicious/noExplicitAny: account_info / account_objects JSON exactly as rippled returns it
type LedgerJson = Record<string, any>;

const QUORUM = 4; // DESIGN 6.9 QUORUM_MATCH: "quorum is 4"
const DETAIL_MAX = 1024; // contracts Finding.detail limit

// Who owns (pays the reserve for) an object, from the deal wallet's point of view. Owner fields per type:
// Source: https://github.com/XRPLF/rippled/blob/develop/include/xrpl/protocol/detail/ledger_entries.macro
function ownerOf(o: LedgerJson): string | undefined {
  switch (o.LedgerEntryType) {
    case 'Escrow':
    case 'Check':
    case 'PayChannel':
    case 'Offer':
    case 'DepositPreauth':
    case 'Ticket':
    case 'DID':
    case 'Delegate':
      return o.Account;
    case 'NFTokenOffer':
    case 'Oracle': // DQ-11: Oracle names its owner in Owner, not Account
      return o.Owner;
    case 'Credential':
      return o.Flags & lsf.CredentialAccepted ? o.Subject : o.Issuer;
    default:
      return undefined; // SignerList, NFTokenPage, RippleState, unknown types: treated as owned
  }
}

// `UNEXPECTED_OWNED_<TYPE>` / `INCOMING_<TYPE>`: TYPE upper-cased and kept to the contracts code alphabet.
const typeCode = (t: unknown) =>
  String(t)
    .toUpperCase()
    .replace(/[^A-Z0-9_]/g, '_')
    .slice(0, 64) || '_';

// DOMAIN_IS_SEAL: Domain is 65 bytes and equals 01 || contractRoot || dealSeal, recomputed locally. A deal the
// seal refuses fails the rule. Source: DESIGN 6.6 and 6.9
function domainIsSeal(domainHex: unknown, deal: PublicDealData): boolean {
  if (typeof domainHex !== 'string' || !/^[0-9A-Fa-f]{130}$/.test(domainHex)) return false;
  try {
    return domainHex.toUpperCase() === bytesToHex(domain(hexToBytes(deal.contractRoot), dealSeal(deal))).toUpperCase();
  } catch {
    return false;
  }
}

// Classic address of a sealed XRPL public key; an undecodable key gives no address. Source: DESIGN 6.9 SIGNERS_MATCH_KEYS
function addressOf(pubKey: string): string {
  try {
    return deriveAddress(pubKey);
  } catch {
    return '';
  }
}

// Source: DESIGN 6.9 (the table, in order)
export function checkLock(acct: LedgerJson, objects: LedgerJson[], exp: Expected): Finding[] {
  const f: Finding[] = [];
  const add = (ok: boolean, level: Finding['level'], code: string, detail?: string) =>
    f.push({ ok, level, code, detail: detail?.slice(0, DETAIL_MAX) });
  const block = (ok: boolean, code: string, detail?: string) => add(ok, 'block', code, detail);
  const warn = (code: string, detail?: string) => add(true, 'warn', code, detail);
  const me = acct.Account;
  const flags = acct.Flags >>> 0;
  const d = exp.deal;

  // 1. Account root: no alternate signing or drain paths; the seal and the releaser.
  block((flags & lsf.DisableMaster) !== 0, 'MASTER_DISABLED');
  block((flags & lsf.DepositAuth) !== 0, 'DEPOSIT_AUTH_ON');
  for (const [k, bit] of Object.entries({
    DISALLOW_NFT_OFFER: lsf.DisallowIncomingNFTokenOffer,
    DISALLOW_CHECK: lsf.DisallowIncomingCheck,
    DISALLOW_PAYCHAN: lsf.DisallowIncomingPayChan,
    DISALLOW_TRUSTLINE: lsf.DisallowIncomingTrustline,
  }))
    block((flags & bit) !== 0, k);
  for (const field of [
    'RegularKey',
    'NFTokenMinter',
    'MintedNFTokens',
    'AMMID',
    'VaultID',
    'LoanBrokerID',
    'Sponsor',
    'SponsoringOwnerCount',
    'SponsoringAccountCount',
  ])
    block(acct[field] === undefined || acct[field] === 0, `NO_${field.toUpperCase()}`, String(acct[field]));
  block(domainIsSeal(acct.Domain, d), 'DOMAIN_IS_SEAL');
  const releaserIsOpsB = exp.releaserAccount === d.lawyerOpsB && d.releaserAccount === d.lawyerOpsB;
  block(
    releaserIsOpsB,
    'RELEASER_IS_OPS_B',
    releaserIsOpsB ? undefined : `${exp.releaserAccount} ${d.releaserAccount}`,
  );

  // 2. Signer list: exactly the derived addresses of the four sealed public keys, weight 1 each.
  const lists = objects.filter((o) => o.LedgerEntryType === 'SignerList');
  block(lists.length === 1, 'ONE_SIGNER_LIST', String(lists.length));
  if (lists.length === 1) {
    const L = lists[0] as LedgerJson;
    const got = L.SignerEntries.map((e: LedgerJson) => `${e.SignerEntry.Account}:${e.SignerEntry.SignerWeight}`).sort();
    const want = [d.xPubA, d.lawyerPubA, d.xPubB, d.lawyerPubB].map((k) => `${addressOf(k)}:1`).sort();
    block(JSON.stringify(got) === JSON.stringify(want), 'SIGNERS_MATCH_KEYS', got.join(','));
    block(L.SignerQuorum === QUORUM, 'QUORUM_MATCH', String(L.SignerQuorum));
    const total = L.SignerEntries.reduce((a: number, e: LedgerJson) => a + e.SignerEntry.SignerWeight, 0);
    block(L.SignerQuorum === total, 'QUORUM_NEEDS_EVERY_SIGNER', `${L.SignerQuorum}/${total}`);
  }

  // 3. Owned objects: allow-list. Incoming objects: warnings (they cannot move our funds).
  const isQuarantine = (o: LedgerJson) =>
    o.Account === exp.escrow.owner &&
    o.Amount === exp.escrow.amountDrops &&
    (o.Condition ?? '').toUpperCase() === exp.escrow.conditionHex.toUpperCase();
  let preauths = 0;
  let ownedCount = 0;
  for (const o of objects) {
    const owner = ownerOf(o);
    const owned = owner === undefined || owner === me;
    if (o.LedgerEntryType === 'SignerList') {
      ownedCount++;
      continue;
    }
    if (o.LedgerEntryType === 'Escrow' && o.Destination === me && o.Account !== me) {
      if (!isQuarantine(o)) warn('FOREIGN_INCOMING_ESCROW', o.index); // cannot move our funds; clear before close
      continue;
    }
    if (o.LedgerEntryType === 'Credential' && o.Issuer === me) {
      const accepted = (o.Flags & lsf.CredentialAccepted) !== 0;
      block(exp.credentialSubjects.includes(o.Subject), 'CREDENTIAL_SUBJECT_EXPECTED', o.Subject);
      block(accepted, 'CREDENTIAL_ACCEPTED', o.Subject);
      if (!accepted) ownedCount++;
      continue;
    }
    if (o.LedgerEntryType === 'DepositPreauth' && o.Account === me) {
      preauths++;
      ownedCount++;
      block(o.Authorize === d.releaserAccount && !o.AuthorizeCredentials, 'PREAUTH_ONLY_RELEASER', o.Authorize);
      continue;
    }
    if (o.LedgerEntryType === 'Ticket' && o.Account === me) {
      ownedCount++;
      block((exp.allowedTicketSequences ?? []).includes(o.TicketSequence), 'TICKET_ALLOWED', String(o.TicketSequence));
      continue;
    }
    if (owned) {
      block(false, `UNEXPECTED_OWNED_${typeCode(o.LedgerEntryType)}`, o.index);
      ownedCount++;
    } else warn(`INCOMING_${typeCode(o.LedgerEntryType)}`, o.index);
  }
  block(preauths === 1, 'ONE_PREAUTH', String(preauths));
  block(acct.OwnerCount === ownedCount, 'OWNER_COUNT_MATCHES', `${acct.OwnerCount} vs ${ownedCount}`);

  if (exp.phase === 'funded') return f;
  // 4. The quarantine escrow, found by owner, amount and condition (DQ-5: owner plus sequence is proposed).
  // Every matching escrow must pass the timing rules, so the result does not depend on the order of `objects`.
  const q = objects.filter(
    (o) => o.LedgerEntryType === 'Escrow' && o.Account === exp.escrow.owner && o.Destination === me,
  );
  block(q.length >= 1, 'QUARANTINE_PRESENT', String(q.length));
  const matches = q.filter(isQuarantine);
  block(matches.length > 0, 'ESCROW_AMOUNT_AND_CONDITION');
  if (matches.length > 0) {
    block(
      matches.every((e) => e.FinishAfter === undefined),
      'NO_FINISH_DELAY_TRAP',
    );
    block(
      matches.every((e) => typeof e.CancelAfter === 'number' && e.CancelAfter >= exp.escrow.minCancelAfter),
      'CANCEL_AFTER_MARGIN',
      matches
        .map((e) => String(e.CancelAfter))
        .sort()
        .join(','),
    );
  }
  return f;
}
export const blocking = (f: Finding[]) => f.filter((x) => x.level === 'block' && !x.ok);
export const allOk = (f: Finding[]) => blocking(f).length === 0;
