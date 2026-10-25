// P5.3-02: random inputs for every function of the Python reference, and the TypeScript answer for each.
// A case is plain JSON (hex strings), so it goes to tools/py-ref/cross.py unchanged.

import type { PublicDealData } from '@legx/contracts/deal';
import { presenceMsg } from '@legx/core/attest';
import { contractRoot } from '@legx/core/contract';
import { bindingMessage, dealSeal, domain, makeCondition, tupleHash } from '@legx/core/dealcore';
import { slotPolicy } from '@legx/core/frost';
import { opsBindMsg } from '@legx/core/opsBinding';
import { muFor, pqBindMsg, pqKeyHash } from '@legx/core/pq';
import { gateMemo } from '@legx/core/releaseGate';
import {
  buildSignedContractSeal,
  contractSigMsg,
  encodeMintMemo,
  MINT_MEMO_TYPE,
  nftUri,
} from '@legx/core/signedContract';
import { zkIdentityCommitment } from '@legx/core/zkIdentity';
import { sha256 } from '@noble/hashes/sha2.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { address, edKey, hex, hexUp, payout } from './gen.ts';
import type { Prng } from './prng.ts';

export interface RefCase {
  fn: string;
  args: Record<string, unknown>;
}
export type Fields = Record<string, unknown>;

const unhex = (s: string): Uint8Array => hexToBytes(s);
const strs = (v: unknown) => v as string[];
const str = (v: unknown) => v as string;

const CLIENT = ['phone', 'second-authenticator', 'recovery-agent'];
const CLIENT_SINGLE = ['phone', 'passkey-same-device', 'recovery-agent'];
const LAWYER = ['console', 'firm-hsm', 'partner'];
const POLICIES: Record<string, string[]> = {
  zk: ['zkpassport'],
  'zk-or-chip': ['zkpassport', 'nfc-chip'],
  chip: ['nfc-chip'],
};
const CONTEXTS = ['legx/dsse/v1', 'legx/pq-binding/v1', 'legx/checkpoint/v1'];

/** The 29 seal fields of a random deal (valid by DESIGN 6.6); `break` makes the releaser differ from lawyerOpsB. */
export function randomSealFields(r: Prng, broken = false): Fields {
  const policy = r.pick(Object.keys(POLICIES));
  const methods = POLICIES[policy] as string[];
  const opsB = address(r);
  const h32 = () => hex(r.bytes(32));
  return {
    contractRoot: h32(),
    signedContractSeal: h32(),
    walletAddress: address(r),
    xPubA: edKey(r),
    xPubB: edKey(r),
    commitmentA: h32(),
    commitmentB: h32(),
    idMethodA: r.pick(methods),
    idMethodB: r.pick(methods),
    identityPolicy: policy,
    lawyerPubA: edKey(r),
    lawyerPubB: edKey(r),
    lawyerCommitmentA: h32(),
    lawyerCommitmentB: h32(),
    lawyerOpsA: address(r),
    lawyerOpsB: opsB,
    releaserAccount: broken ? address(r) : opsB,
    slotPolicyA: h32(),
    slotPolicyLA: h32(),
    slotPolicyB: h32(),
    slotPolicyLB: h32(),
    pqKeyHashA: h32(),
    pqKeyHashLA: h32(),
    pqKeyHashB: h32(),
    pqKeyHashLB: h32(),
    signerAccounts: [address(r), address(r), address(r), address(r)],
    quorum: 4,
    payoutA: payout(r),
    payoutB: payout(r),
  };
}

export const FNS = [
  'tupleHash',
  'dealSeal',
  'domain',
  'contractRoot',
  'bindMsg',
  'contractSigMsg',
  'signedContractSeal',
  'nftUri',
  'mintMemo',
  'opsBindMsg',
  'presenceMsg',
  'pqKeyHash',
  'pqBindMsg',
  'slotPolicy',
  'zk',
  'condition',
  'gateMemo',
  'mu',
] as const;
export type Fn = (typeof FNS)[number];

export function randomCase(r: Prng, fn: Fn): RefCase {
  const h = (n = 32) => hex(r.bytes(n));
  const role = () => r.pick(['LA', 'LB']);
  const args = ((): Record<string, unknown> => {
    switch (fn) {
      case 'tupleHash':
        return { tag: r.text(24), parts: Array.from({ length: r.int(9) }, () => h(r.int(80))) };
      case 'dealSeal':
        return { fields: randomSealFields(r, r.chance(0.03)) };
      case 'domain':
        return { root: h(), seal: h() };
      case 'contractRoot': {
        const n = r.int(10);
        return { salts: Array.from({ length: n }, () => h()), clauses: Array.from({ length: n }, () => h(r.int(200))) };
      }
      case 'bindMsg':
        return { root: h(), C: h(), slotPub: hexUp(unhex(`ed${h()}`)), side: r.pick(['A', 'B', 'LA', 'LB']) };
      case 'contractSigMsg':
        return { root: h(), wallet: address(r), role: role() };
      case 'signedContractSeal':
        return { root: h(), wallet: address(r), pubA: edKey(r), sigLA: h(64), pubB: edKey(r), sigLB: h(64) };
      case 'nftUri':
        return { seal: h() };
      case 'mintMemo':
        return { pubA: edKey(r), sigLA: h(64), pubB: edKey(r), sigLB: h(64) };
      case 'opsBindMsg':
        return { root: h(), ops: address(r), lawyerPub: edKey(r), lc: h(), role: role() };
      case 'presenceMsg':
        return { seal: h(), side: r.pick(['A', 'B']), ledgerHash: h(), nonce: h() };
      case 'pqKeyHash':
        return { pubs: [h(1952), h(1952), h(1952)] };
      case 'pqBindMsg':
        return { seal: h(), slotPub: edKey(r), keyHash: h() };
      case 'slotPolicy': {
        const slot = r.pick(['A', 'B', 'LA', 'LB']);
        const roles = slot.length === 1 ? r.pick([CLIENT, CLIENT_SINGLE]) : LAWYER;
        return { slot, roles: roles.join(',') };
      }
      case 'zk':
        return { salt: h(), N: r.chance(0.8) ? String(r.u32()) + String(r.u32()) : `${r.text(12)}x` };
      case 'condition':
        return { preimage: h(r.chance(0.03) ? 31 : 32) };
      case 'gateMemo':
        return { envelope: h(r.int(300)) };
      case 'mu':
        return { pub: h(1952), ctx: hex(new TextEncoder().encode(r.pick(CONTEXTS))), msg: h(r.int(300)) };
    }
  })();
  return { fn, args };
}

const memoText = (m: { MemoType: string; MemoData: string }) => `${m.MemoType}:${m.MemoData}`;

/** What @legx/core gives for a case, in the same string form as cross.py; "ERR" when core refuses. */
export function tsRef(c: RefCase): string {
  const a = c.args;
  try {
    switch (c.fn) {
      case 'tupleHash':
        return hex(tupleHash(str(a.tag), strs(a.parts).map(unhex)));
      case 'dealSeal':
        return hex(dealSeal(a.fields as PublicDealData));
      case 'domain':
        return hexUp(domain(unhex(str(a.root)), unhex(str(a.seal))));
      case 'contractRoot':
        return hex(contractRoot(strs(a.clauses).map(unhex), strs(a.salts).map(unhex)));
      case 'bindMsg':
        return hex(bindingMessage(unhex(str(a.root)), unhex(str(a.C)), str(a.slotPub), str(a.side) as 'A'));
      case 'contractSigMsg':
        return hex(contractSigMsg(unhex(str(a.root)), str(a.wallet), str(a.role) as 'LA'));
      case 'signedContractSeal':
        return hex(
          buildSignedContractSeal(
            {
              contractRoot: unhex(str(a.root)),
              walletAddress: str(a.wallet),
              lawyerPubA: str(a.pubA),
              lawyerPubB: str(a.pubB),
            },
            { sigLA: unhex(str(a.sigLA)), sigLB: unhex(str(a.sigLB)) },
          ).seal,
        );
      case 'nftUri':
        return nftUri(unhex(str(a.seal)));
      case 'mintMemo':
        return `${MINT_MEMO_TYPE}:${encodeMintMemo({ lawyerPubA: str(a.pubA), lawyerPubB: str(a.pubB), sigLA: unhex(str(a.sigLA)), sigLB: unhex(str(a.sigLB)) })}`;
      case 'opsBindMsg':
        return hex(
          opsBindMsg({
            contractRoot: unhex(str(a.root)),
            opsAccount: str(a.ops),
            lawyerPub: str(a.lawyerPub),
            lawyerCommitment: unhex(str(a.lc)),
            role: str(a.role) as 'LA',
          }),
        );
      case 'presenceMsg':
        return hex(presenceMsg(unhex(str(a.seal)), str(a.side) as 'A', unhex(str(a.ledgerHash)), unhex(str(a.nonce))));
      case 'pqKeyHash':
        return hex(pqKeyHash(strs(a.pubs).map(unhex) as [Uint8Array, Uint8Array, Uint8Array]));
      case 'pqBindMsg':
        return hex(pqBindMsg(unhex(str(a.seal)), unhex(str(a.slotPub)), unhex(str(a.keyHash))));
      case 'slotPolicy':
        // core wants a set of roles in any order; the reference wants the canonical string. Shuffle for core.
        return hex(slotPolicy(str(a.slot) as 'A', str(a.roles).split(',').reverse()));
      case 'zk':
        return hex(zkIdentityCommitment(unhex(str(a.salt)), str(a.N)));
      case 'condition': {
        const { condition, fulfillment } = makeCondition(unhex(str(a.preimage)));
        return `${condition}:${fulfillment}`;
      }
      case 'gateMemo':
        return memoText(gateMemo(sha256(unhex(str(a.envelope)))));
      case 'mu':
        return hex(
          muFor(unhex(str(a.pub)), new TextDecoder().decode(unhex(str(a.ctx))) as 'legx/dsse/v1', unhex(str(a.msg))),
        );
    }
  } catch {
    return 'ERR';
  }
  throw new Error(`unknown fn ${c.fn}`);
}
