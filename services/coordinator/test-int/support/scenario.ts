// One deal run end to end against the real standalone ledger and a real Postgres, step by step through the public API.
// Every on-ledger transaction is built with the 2.3 builders and signed with real keys; the coordinator reads the
// results back from validated ledgers. Used by the T-P-06 model-based test and by the deterministic flow test.

import { randomBytes } from 'node:crypto';
import { bytesToHex, hexToBytes, makeCondition } from '@legx/core/dealcore';
import {
  build3,
  build5a,
  build5b,
  build5c,
  build5d,
  build5e,
  build5f,
  build5g,
  build7,
  DISALLOW_KINDS,
} from '@legx/xrpl';
import { ECDSA, Wallet } from 'xrpl';
import {
  account,
  dkgDone,
  gateRecord,
  identityOnboarded,
  keyBound,
  lawyerSigned,
  ok,
  opsBound,
  pqBind,
  publicData,
  shipData,
} from '../../test/support/lifecycle.ts';
import { call, contractRoot, holderOf, post, ROLES, type Role, type World } from '../../test/support/world.ts';
import type { RealLedger } from './real.ts';

/** The deal state after each setup step, in order (DESIGN 5.1). */
export const STAGE_STATE = [
  'DRAFT', // join: wallet, contract, keys, dkg, contract signatures, ops bindings, onboarding
  'CONTRACT_SIGNED', // mint
  'SHELL_OPEN',
  'QUARANTINED',
  'KEYS_READY',
  'WALLET_LOCKED',
  'VERIFIED',
  'SHIPPED',
  'RECEIVED',
  'RECEIVED', // gate passed (no state change)
  'FUNDED',
] as const;
export const STEPS = [
  'join',
  'mint',
  'shellOpen',
  'escrow',
  'pq',
  'lock',
  'verify',
  'ship',
  'receipt',
  'gate',
  'release',
] as const;

const GENESIS_PAY = 200; // XRP for each wallet that needs fees

export class Scenario {
  readonly w: World;
  readonly real: RealLedger;
  readonly shell = Wallet.generate(ECDSA.ed25519);
  readonly preimage = new Uint8Array(randomBytes(32));
  readonly cond = makeCondition(this.preimage);
  stage = 0; // steps done
  escrowSequence = 0;
  gateLeaf = '';
  shipLedger = 0;
  id = '';
  /** The last event bytes posted, for the retry command. */
  lastEvent: { role: Role; b64: string } | undefined;

  constructor(w: World, real: RealLedger, opsA: Wallet, opsB: Wallet, payA: string, payB: string) {
    this.w = w;
    this.real = real;
    w.addr.shell = this.shell.classicAddress;
    w.addr.opsA = opsA.classicAddress;
    w.addr.opsB = opsB.classicAddress;
    w.addr.payA = payA;
    w.addr.payB = payB;
    this.opsA = opsA;
    this.opsB = opsB;
  }
  readonly opsA: Wallet;
  readonly opsB: Wallet;

  private ctx = async () => ({
    network: 'standalone' as const,
    baseFeeDrops: Number((await this.real.port.fees()).baseFee),
  });
  private party = (r: Role) => this.w.parties[r].wallet;
  private pay = async (to: string, xrp: number) => {
    const { GENESIS } = await import('@legx/xrpl/fund');
    await this.real.submit(GENESIS, { TransactionType: 'Payment', Destination: to, Amount: String(xrp * 1_000_000) });
  };

  async create(newDeal: (w: World) => Promise<string>) {
    this.id = await newDeal(this.w);
  }

  /** Runs the next setup step. Returns the response of the last API call it made. */
  async next() {
    const step = STEPS[this.stage] as (typeof STEPS)[number];
    const r = await this[step]();
    this.stage++;
    return r;
  }

  private async join() {
    const { w, id } = this;
    ok(await call(w, holderOf(w, 'alice'), 'POST', `/deals/${id}/wallet`, { dealId: id, walletAddress: w.addr.shell }));
    ok(await call(w, holderOf(w, 'lawyerA'), 'POST', `/deals/${id}/contract`, { dealId: id, contractRoot }));
    for (const r of ROLES) {
      ok(await keyBound(w, id, r));
      ok(await dkgDone(w, id, r));
    }
    ok(await lawyerSigned(w, id, 'lawyerA'));
    ok(await lawyerSigned(w, id, 'lawyerB'));
    ok(await opsBound(w, id, 'lawyerA'));
    ok(await opsBound(w, id, 'lawyerB'));
    ok(await identityOnboarded(w, id, 'A'));
    return ok(await identityOnboarded(w, id, 'B'));
  }

  private async mint() {
    const t = await this.real.submit(this.opsA, { TransactionType: 'NFTokenMint', NFTokenTaxon: 0, Flags: 0 });
    return ok(
      await post(this.w, this.id, 'lawyerA', 'nft.minted', {
        nftoken_id: bytesToHex(randomBytes(32)).toUpperCase(),
        mint_tx_hash: t.hash,
        minter: this.opsA.classicAddress,
        signed_contract_seal: bytesToHex(randomBytes(32)),
      }),
    );
  }

  private async shellOpen() {
    await this.pay(this.party('alice').classicAddress, GENESIS_PAY);
    const t = await this.real.submit(this.party('alice'), {
      TransactionType: 'Payment',
      Destination: this.shell.classicAddress,
      Amount: '100000000',
    });
    return ok(
      await post(this.w, this.id, 'alice', 'shell.opened', {
        wallet_address: this.shell.classicAddress,
        funding_tx_hash: t.hash,
      }),
    );
  }

  private async escrow() {
    const header = await this.real.port.validatedLedger();
    const tx = build3(
      {
        alice: this.party('alice').classicAddress,
        shell: this.shell.classicAddress,
        amount: '50000000',
        condition: this.cond.condition,
        closeTime: header.closeTime,
        days: 3,
      },
      await this.ctx(),
    );
    const sent = await this.real.submit(this.party('alice'), tx as never);
    const t = await this.real.port.tx(sent.hash as never);
    this.escrowSequence = Number(t?.tx.Sequence);
    return ok(
      await post(this.w, this.id, 'alice', 'escrow.created', {
        escrow: {
          owner: this.party('alice').classicAddress,
          offer_sequence: this.escrowSequence,
          amount_drops: '50000000',
          condition: this.cond.condition,
          cancel_after: Number(t?.tx.CancelAfter),
        },
        tx_hash: sent.hash,
      }),
    );
  }

  private async pq() {
    return await pqBind(this.w, this.id);
  }

  private async lock() {
    const { w, id } = this;
    const pd = await publicData(w, id);
    const ctx = await this.ctx();
    const shell = this.shell.classicAddress;
    const signers = (['alice', 'lawyerA', 'bob', 'lawyerB'] as Role[]).map((r) => account(w, r));
    const hashes: string[] = [];
    const send = async (wallet: Wallet, tx: object) => hashes.push((await this.real.submit(wallet, tx as never)).hash);
    await this.pay(this.party('bob').classicAddress, GENESIS_PAY);
    await send(this.shell, build5a({ shell, signers }, ctx));
    await send(
      this.shell,
      build5b({ shell, contractRoot: hexToBytes(pd.publicData.contractRoot), dealSeal: hexToBytes(pd.dealSeal) }, ctx),
    );
    for (const kind of DISALLOW_KINDS) await send(this.shell, build5c({ shell, kind }, ctx));
    await send(this.shell, build5d({ shell, releaser: this.opsB.classicAddress }, ctx));
    for (const [side, role] of [
      ['A', 'alice'],
      ['B', 'bob'],
    ] as const) {
      await send(
        this.shell,
        build5e({ shell, subject: account(w, role), side, bindingSig: new Uint8Array(64).fill(1) }, ctx),
      );
      await send(this.party(role), build5f({ subject: account(w, role), shell, side }, ctx));
    }
    await send(this.shell, build5g({ shell }, ctx));
    return ok(await post(w, id, 'alice', 'wallet.locked', { tx_hashes: hashes, domain: pd.domain }));
  }

  private async verify() {
    const l = await this.real.port.validatedLedger();
    return ok(
      await post(this.w, this.id, 'lawyerB', 'lock.verified', {
        ledger: { ledger_index: l.ledgerIndex, ledger_hash: l.ledgerHash },
        findings: [],
      }),
    );
  }

  private async ship() {
    this.shipLedger = (await this.real.port.validatedLedger()).ledgerIndex;
    const s = await shipData(this.w, this.id, 'bob', this.shipLedger);
    return ok(await post(this.w, this.id, 'bob', 'shipment.signed', s.shipment()));
  }

  private async receipt() {
    // The receipt names the shipment's hash, which holds the ledger index it was signed at.
    const s = await shipData(this.w, this.id, 'bob', this.shipLedger);
    return ok(await post(this.w, this.id, 'alice', 'receipt.signed', s.receipt()));
  }

  private async gate() {
    const pd = await publicData(this.w, this.id);
    const l = await this.real.port.validatedLedger();
    const rec = {
      ...gateRecord(this.w, this.id, pd.dealSeal),
      ledger: { ledger_index: l.ledgerIndex, ledger_hash: l.ledgerHash },
    };
    const r = ok(await post(this.w, this.id, 'lawyerB', 'release.gate.passed', { gate: rec }));
    this.gateLeaf = r.leafHash;
    return r;
  }

  private async release() {
    const tx = build7(
      {
        releaser: this.opsB.classicAddress,
        owner: this.party('alice').classicAddress,
        offerSequence: this.escrowSequence,
        condition: this.cond.condition,
        fulfillment: this.cond.fulfillment,
        gateLeafHash: hexToBytes(this.gateLeaf),
      },
      await this.ctx(),
    );
    const t = await this.real.submit(this.opsB, tx as never);
    return ok(
      await post(this.w, this.id, 'lawyerB', 'release.performed', {
        finish_tx_hash: t.hash,
        ledger_index: t.ledgerIndex,
        gate_leaf_hash: this.gateLeaf,
      }),
    );
  }

  // ---- exits ----

  sigUrl = (req?: string) => `/deals/${this.id}/signature-requests${req ? `/${req}/signatures` : ''}`;
  signBlob = (role: Role, unsigned: Record<string, unknown>) => this.party(role).sign(unsigned as never, true).tx_blob;

  async request(purpose: string, role: Role = 'alice') {
    return await call(this.w, holderOf(this.w, role), 'POST', this.sigUrl(), { dealId: this.id, purpose });
  }
  async submitSig(requestId: string, role: Role, blob: string) {
    return await call(this.w, holderOf(this.w, role), 'POST', this.sigUrl(requestId), {
      dealId: this.id,
      requestId,
      role,
      signerBlob: blob,
    });
  }
  /** All four sign and the last one submits: returns the final answer. */
  async exit(purpose: string) {
    const req = ok(await this.request(purpose));
    let last: Awaited<ReturnType<Scenario['submitSig']>> | undefined;
    for (const r of ROLES) last = await this.submitSig(req.requestId, r, this.signBlob(r, req.unsignedTx));
    return { req, last };
  }
  state = async () => ok(await call(this.w, holderOf(this.w, 'alice'), 'GET', `/deals/${this.id}`)).state as string;
}
