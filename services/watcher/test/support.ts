// Fixtures for the watcher service tests: a model ledger with account state, and a funded deal wallet that passes the
// lock checker (the lock checker's own fixture, after the quarantine escrow has been finished).
import type { PublicDealData } from '@legx/contracts/deal';
import type { XrplJson } from '@legx/contracts/ports';
import { dealSeal, domain } from '@legx/core/dealcore';
import { type Expected, lsf } from '@legx/core/lockcheck';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import * as xrpl from 'xrpl';
import { FakeChain, FakeLink } from '../../../packages/xrpl/test/watcher/fakeLink.ts';
import type { DealWatch } from '../src/index.ts';

export { FakeChain };

const h32 = (n: number) => bytesToHex(new Uint8Array(32).fill(n)).toUpperCase();
const pub = (n: number) => `ED${h32(n)}`;
const addr = (n: number) => xrpl.encodeAccountID(new Uint8Array(20).fill(n));
export const WALLET = addr(0x10);
const OPS_B = addr(0x12);
export const ALICE = addr(0x31);
const BOB = addr(0x32);
const KEYS = [pub(3), pub(7), pub(4), pub(8)];
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
const ALL_FLAGS =
  lsf.DisableMaster |
  lsf.DepositAuth |
  lsf.DisallowIncomingNFTokenOffer |
  lsf.DisallowIncomingCheck |
  lsf.DisallowIncomingPayChan |
  lsf.DisallowIncomingTrustline;

export type Obj = Record<string, unknown>;
export interface Wallet {
  acct: Obj;
  objs: Obj[];
}

/** The wallet after funding: no quarantine escrow any more. */
export const fundedWallet = (): Wallet => ({
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
  ],
});

const expected = (): Expected => ({
  deal: structuredClone(DEAL),
  releaserAccount: OPS_B,
  credentialSubjects: [ALICE, BOB],
  escrow: {
    owner: ALICE,
    sequence: 7,
    amountDrops: '5000000000',
    conditionHex: `A0258020${'CC'.repeat(32)}810120`,
    minCancelAfter: 1000,
  },
});

export const funded = (over: Partial<DealWatch> = {}): DealWatch => ({
  dealId: '0190b2e0-0000-7000-8000-000000000001',
  wallet: WALLET,
  phase: 'funded',
  expected: expected(),
  ...over,
});

/** A model server: the chain of FakeLink plus a header with close_time and the deal wallet's state per ledger. */
export class LedgerLink extends FakeLink {
  /** Returns the wallet as of ledger `n`. */
  wallet: (n: number) => Wallet = () => fundedWallet();

  override async request(req: Parameters<FakeLink['request']>[0]): Promise<{ result: unknown }> {
    switch (req.command) {
      case 'ledger': {
        const base = (await super.request(req)).result as XrplJson;
        const n = base.ledger_index as number;
        return {
          result: { ...base, ledger: { ledger_index: n, ledger_hash: base.ledger_hash, close_time: 1000 + n } },
        };
      }
      case 'account_info': {
        this.calls.push(req);
        const n = this.at(req);
        return { result: { account_data: this.wallet(n).acct, ledger_index: n, validated: true } };
      }
      case 'account_objects': {
        this.calls.push(req);
        const n = this.at(req);
        return { result: { account_objects: this.wallet(n).objs, ledger_index: n, validated: true } };
      }
      default:
        return super.request(req);
    }
  }

  private at(req: Parameters<FakeLink['request']>[0]): number {
    if (!this.connected) throw new xrpl.ConnectionError('not connected');
    return req.ledger_index as number;
  }
}
