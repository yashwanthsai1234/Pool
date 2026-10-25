// A fresh deal for one test (task 2.6): the role script of 2.5 (roles.ts) cut into named stages, so a hostile test can
// stop the deal at any phase, act, and carry on. `advance('funded')` runs P0 to P4; `advance('locked')` runs the whole
// lock (P5) and the lock check (P6). Every stage checks its own result, and a test also asserts its setup state before
// it attacks (an attack that passes because its setup failed is a false pass).
//
// The stages run the same steps, in the same order, as the full flow (T-I-01, full-flow.int.test.ts uses this file).
// Source: IMPLEMENTATION.md 2.5 and 2.6; DESIGN.md 5.2, 5.3, 5.4, 7.3
import { type Finding, GATE_CODES } from '@legx/contracts/records';
import { contractRoot } from '@legx/core/contract';
import { bindingMessage, dealSeal, domain, makeCondition, utf8ToBytes, verifyBinding } from '@legx/core/dealcore';
import { multisigFee } from '@legx/core/fees';
import { allOk, checkLock } from '@legx/core/lockcheck';
import {
  buildGatePassedRecord,
  checkRelease,
  type KeyRow,
  type ReleaseInput,
  verifyGatePassedRecord,
} from '@legx/core/releaseGate';
import { manifestRoot, rcptMsg, shipMsg } from '@legx/core/shipment';
import { buildSignedContractSeal, signContract } from '@legx/core/signedContract';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { expect } from 'vitest';
import type xrpl from 'xrpl';
import {
  build0a,
  build0b,
  build1,
  build2,
  build3,
  build5a,
  build5b,
  build5c,
  build5Domain,
  build5d,
  build5dUnauthorize,
  build5e,
  build5f,
  build5g,
  build7,
  build8,
  build9,
  buildSignerListRotation,
  DISALLOW_KINDS,
} from '../src/builders/index.ts';
import { nextSlot } from '../src/multisig.ts';
import { snapshot } from '../src/read.ts';
import {
  barDealLink,
  barVerification,
  type Chain,
  type ClientRole,
  type Curve,
  dealData,
  type Evidence,
  evidenceFor,
  type Json,
  type LawyerBase,
  type LawyerRole,
  type LedgerRef,
  ledgerRef,
  makeClient,
  makeLawyer,
  makeSlot,
  makeVerifier,
  newWallet,
  onboardingRecord,
  opsBoundData,
  passportRecordAt,
  pqBoundData,
  readGateLedger,
  type SlotRole,
  up,
  uuid7,
  type Verifier,
  withSlot,
} from './roles.ts';

type Wallet = InstanceType<typeof xrpl.Wallet>;

export const ESCROW_DROPS = '50000000';
export const STAGES = [
  'onboarded', // P0: Alice, Bob, the verifier and both lawyers are funded; LEGX_ATTORNEY issued and accepted
  'contract', // P2 and P3: both lawyer slots, the contract signatures, the signed-contract NFT
  'funded', // P4: step 2 (the shell exists with 100 XRP) and step 3 (the quarantine escrow)
  'keys', // P5 before the lock: client slots, bindings, the deal seal, the post-quantum bindings
  'signers', // 5a
  'domain', // 5b: Domain = the seal, DepositAuth on
  'disallow', // 5c: the four DisallowIncoming flags
  'preauth', // 5d: DepositPreauth for the releaser
  'credentials', // 5e and 5f
  'locked', // 5g, the setup key wiped, and the lock check of P6
] as const;
export type Stage = (typeof STAGES)[number];

export interface DealOptions {
  curve?: Curve;
  /** If set, `CancelAfter` is this many ledger seconds after step 3, not three days: the escrow can expire in a test. */
  cancelAfterSeconds?: number;
  /** The quarantine escrow's amount in drops (default ESCROW_DROPS, T-I-01's 50 XRP). */
  escrowDrops?: string;
}

/** What an exit paid: the validated transaction and the balances around it. */
export interface Exit {
  readonly hash: string;
  readonly deliveredBefore: bigint;
  readonly receiverBefore: bigint;
  readonly receiverAfter: bigint;
}

export class Deal {
  readonly c: Chain;
  readonly o: DealOptions;
  readonly curve: Curve;
  readonly escrowDrops: string;
  readonly dealId = uuid7();
  readonly root: Uint8Array;
  readonly rootHex: string;
  readonly ev: Evidence;
  readonly verifier: Verifier = makeVerifier();
  readonly aliceBase = makeClient('A');
  readonly bobBase = makeClient('B');
  readonly shell = newWallet('ed25519'); // the setup key (P1)
  readonly wallet: string;
  readonly history: LedgerRef[] = [];
  readonly onboarded = new Map<string, Uint8Array>(); // ops account -> the BarVerification envelope
  stage: Stage | undefined;
  setupKey: Wallet | undefined = this.shell;

  baseA: LawyerBase;
  baseB: LawyerBase;
  lawyerA!: LawyerRole;
  lawyerB!: LawyerRole;
  alice!: ClientRole;
  bob!: ClientRole;
  sc!: ReturnType<typeof buildSignedContractSeal> & { sigs: { sigLA: Uint8Array; sigLB: Uint8Array } };
  minted!: { hash: string; nftokenId: string };
  preimage = randomBytes(32);
  condition = '';
  fulfillment = '';
  escrowSequence = 0;
  /** CancelAfter of the quarantine escrow, in Ripple seconds. */
  cancelAfter = 0;
  data!: ReturnType<typeof dealData>;
  seal!: Uint8Array;
  bindings = {} as Record<'A' | 'B', Uint8Array>;
  readonly rec = {
    onboarding: {} as Partial<Record<'A' | 'B', Uint8Array>>,
    bar: {} as Partial<Record<'LA' | 'LB', { link: Uint8Array; verification: Uint8Array }>>,
    opsBound: {} as Partial<Record<'LA' | 'LB', Uint8Array>>,
    dkg: {} as Partial<Record<'A' | 'B' | 'LA' | 'LB', Uint8Array>>,
    pq: {} as Partial<Record<'A' | 'B' | 'LA' | 'LB', Uint8Array>>,
  };

  constructor(c: Chain, o: DealOptions = {}) {
    this.c = c;
    this.o = o;
    this.curve = o.curve ?? 'ed25519';
    this.escrowDrops = o.escrowDrops ?? ESCROW_DROPS;
    const clauses = ['clause 0: goods', 'clause 1: price'].map(utf8ToBytes);
    this.root = contractRoot(
      clauses,
      clauses.map(() => randomBytes(32)),
    );
    this.rootHex = bytesToHex(this.root);
    this.ev = evidenceFor(this.dealId, this.rootHex);
    this.wallet = this.shell.classicAddress;
    this.baseA = makeLawyer('LA', 'Firm A', this.curve, 'CA-0000001');
    this.baseB = makeLawyer('LB', 'Firm B', this.curve, 'CA-0000002');
  }

  // ---------- running the stages ----------

  /** Runs every stage up to and including `to` that has not run yet. */
  async advance(to: Stage): Promise<this> {
    const from = this.stage === undefined ? 0 : STAGES.indexOf(this.stage) + 1;
    for (const s of STAGES.slice(from, STAGES.indexOf(to) + 1)) {
      await this.c.step(`stage ${s}`, () => this.run[s]());
      this.stage = s;
    }
    return this;
  }

  private readonly run: Record<Stage, () => Promise<void>> = {
    onboarded: () => this.run_onboarded(),
    contract: () => this.run_contract(),
    funded: () => this.run_funded(),
    keys: () => this.run_keys(),
    signers: () => this.run_signers(),
    domain: () => this.run_domain(),
    disallow: () => this.run_disallow(),
    preauth: () => this.run_preauth(),
    credentials: () => this.run_credentials(),
    locked: () => this.lock(),
  };

  reached(s: Stage): boolean {
    return this.stage !== undefined && STAGES.indexOf(this.stage) >= STAGES.indexOf(s);
  }

  private closeNow = async () => (await ledgerRef(this.c)).closeTime;
  slots = () => [this.alice.slot, this.lawyerA.slot, this.bob.slot, this.lawyerB.slot];

  async onboardLawyer(l: LawyerBase) {
    const { c } = this;
    await c.fund(l.ops, 100);
    const at = await ledgerRef(c);
    this.history.push(at); // the gate looks up checked_at_ledger in validated history
    const v = await barVerification(this.ev, this.verifier, l, at);
    this.onboarded.set(l.ops.classicAddress, v.envelope);
    await c.send(
      this.verifier.issuer,
      build0a(
        {
          issuer: this.verifier.issuer.classicAddress,
          subject: l.ops.classicAddress,
          barVerificationSha256: v.sha256,
          closeTime: at.closeTime,
        },
        c.ctx,
      ),
    );
    await c.send(l.ops, build0b({ subject: l.ops.classicAddress, issuer: this.verifier.issuer.classicAddress }, c.ctx));
  }

  async run_onboarded() {
    const { c } = this;
    await c.fund(this.verifier.issuer, 100);
    await c.fund(this.aliceBase.wallet, 1000);
    await c.fund(this.bobBase.wallet, 100);
    await this.onboardLawyer(this.baseA);
    await this.onboardLawyer(this.baseB);
  }

  async signContractSeal() {
    const terms = {
      contractRoot: this.root,
      walletAddress: this.wallet,
      lawyerPubA: this.lawyerA.slot.pubHex,
      lawyerPubB: this.lawyerB.slot.pubHex,
    };
    const sigLA = await signContract(async (m) => this.lawyerA.slot.sign(m), terms, 'LA');
    const sigLB = await signContract(async (m) => this.lawyerB.slot.sign(m), terms, 'LB');
    return { ...buildSignedContractSeal(terms, { sigLA, sigLB }), sigs: { sigLA, sigLB } };
  }

  async mint() {
    const memo = {
      lawyerPubA: this.lawyerA.slot.pubHex,
      lawyerPubB: this.lawyerB.slot.pubHex,
      ...this.sc.sigs,
    };
    const r = await this.c.send(
      this.lawyerA.ops,
      build1({ lawyerOpsA: this.lawyerA.ops.classicAddress, signedContractSeal: this.sc.seal, memo }, this.c.ctx),
    );
    return { hash: r.hash, nftokenId: String(r.meta.nftoken_id) };
  }

  async run_contract() {
    this.lawyerA = withSlot(this.baseA, await makeSlot('LA'));
    this.lawyerB = withSlot(this.baseB, await makeSlot('LB'));
    this.sc = await this.signContractSeal();
    this.minted = await this.mint();
  }

  async run_funded() {
    const { c } = this;
    const { condition, fulfillment } = makeCondition(this.preimage);
    this.condition = condition;
    this.fulfillment = fulfillment;
    await c.send(
      this.aliceBase.wallet,
      build2({ alice: this.aliceBase.wallet.classicAddress, shell: this.wallet, amount: '100000000' }, c.ctx),
    );
    const tx = build3(
      {
        alice: this.aliceBase.wallet.classicAddress,
        shell: this.wallet,
        amount: this.escrowDrops,
        condition,
        closeTime: await this.closeNow(),
        days: 3,
      },
      c.ctx,
    );
    const now = await this.closeNow();
    if (this.o.cancelAfterSeconds !== undefined) tx.CancelAfter = now + this.o.cancelAfterSeconds;
    const r = await c.send(this.aliceBase.wallet, tx);
    this.escrowSequence = Number(r.tx.Sequence);
    this.cancelAfter = Number(tx.CancelAfter);
  }

  async writeLawyerRecords(l: LawyerRole) {
    const verification = this.onboarded.get(l.ops.classicAddress) as Uint8Array;
    this.rec.bar[l.role] = {
      link: await barDealLink(this.ev, this.verifier, l, verification, { dealId: this.dealId, rootHex: this.rootHex }),
      verification,
    };
    const who = l.role === 'LA' ? 'lawyerA' : 'lawyerB';
    this.rec.opsBound[l.role] = await this.ev.event('ops.bound', opsBoundData(l, this.rootHex), l.slot, who);
    this.rec.dkg[l.role] = await this.ev.event('frost.dkg.completed', l.slot.dkg, l.slot, who);
  }

  sealInput = () => ({
    rootHex: this.rootHex,
    signedContractSeal: this.sc.seal,
    wallet: this.wallet,
    alice: this.alice,
    bob: this.bob,
    lawyerA: this.lawyerA,
    lawyerB: this.lawyerB,
  });

  async sealPq() {
    for (const s of this.slots()) {
      const who = s.name === 'A' ? 'alice' : s.name === 'B' ? 'bob' : s.name === 'LA' ? 'lawyerA' : 'lawyerB';
      this.rec.pq[s.name] = await this.ev.event('pq.bound', pqBoundData(s, this.seal), s, who);
    }
  }

  async run_keys() {
    this.alice = withSlot(this.aliceBase, await makeSlot('A'));
    this.bob = withSlot(this.bobBase, await makeSlot('B'));
    await this.writeLawyerRecords(this.lawyerA);
    await this.writeLawyerRecords(this.lawyerB);
    this.rec.dkg.A = await this.ev.event('frost.dkg.completed', this.alice.slot.dkg, this.alice.slot, 'alice');
    this.rec.dkg.B = await this.ev.event('frost.dkg.completed', this.bob.slot.dkg, this.bob.slot, 'bob');
    const now = await this.closeNow();
    const d = { dealId: this.dealId, rootHex: this.rootHex, now };
    this.rec.onboarding.A = await onboardingRecord(this.ev, this.alice, this.lawyerA, d);
    this.rec.onboarding.B = await onboardingRecord(this.ev, this.bob, this.lawyerB, d);
    for (const p of [this.alice, this.bob]) {
      const msg = bindingMessage(this.root, p.commitment, p.slot.pubHex, p.side);
      this.bindings[p.side] = p.slot.sign(msg);
      expect(verifyBinding(p.slot.pubHex, msg, this.bindings[p.side])).toBe(true);
    }
    this.data = dealData(this.sealInput());
    this.seal = dealSeal(this.data);
    await this.sealPq();
  }

  /** A transaction signed by the shell's setup key (P1 to 5g). Throws after the key is wiped. */
  setup = (tx: xrpl.SubmittableTransaction) => {
    if (!this.setupKey) throw new Error('the shell setup key was wiped');
    return this.c.send(this.setupKey, tx);
  };

  async run_signers() {
    await this.setup(build5a({ shell: this.wallet, signers: this.slots().map((s) => s.address) }, this.c.ctx));
  }
  async run_domain() {
    await this.setup(build5b({ shell: this.wallet, contractRoot: this.root, dealSeal: this.seal }, this.c.ctx));
  }
  async run_disallow() {
    for (const kind of DISALLOW_KINDS) await this.setup(build5c({ shell: this.wallet, kind }, this.c.ctx));
  }
  async run_preauth() {
    await this.setup(build5d({ shell: this.wallet, releaser: this.lawyerB.ops.classicAddress }, this.c.ctx));
  }
  async run_credentials() {
    for (const p of [this.alice, this.bob]) {
      await this.setup(
        build5e(
          { shell: this.wallet, subject: p.wallet.classicAddress, side: p.side, bindingSig: this.bindings[p.side] },
          this.c.ctx,
        ),
      );
      await this.c.send(
        p.wallet,
        build5f({ subject: p.wallet.classicAddress, shell: this.wallet, side: p.side }, this.c.ctx),
      );
    }
  }

  /** 5g, the wipe, and the P6 lock check. With a short `CancelAfter`, only `CANCEL_AFTER_MARGIN` may fail. */
  async lock() {
    await this.wipe();
    const findings = await this.lockCheck();
    const blocked = findings.filter((f) => f.level === 'block' && !f.ok).map((f) => f.code);
    expect(blocked).toEqual(this.o.cancelAfterSeconds === undefined ? [] : ['CANCEL_AFTER_MARGIN']);
  }

  /**
   * Finishes the lock like `advance('locked')` but without requiring a clean lock check: an attack test has planted
   * something the checker must flag. Returns the blocking finding codes.
   */
  async lockFlagged(): Promise<string[]> {
    await this.advance('credentials');
    await this.wipe();
    this.stage = 'locked';
    return (await this.lockCheck()).filter((f) => f.level === 'block' && !f.ok).map((f) => f.code);
  }

  /** 5g: the setup key's last use; after it the shell signs only through the four slots. */
  async wipe() {
    await this.setup(build5g({ shell: this.wallet }, this.c.ctx));
    this.setupKey = undefined;
  }

  // ---------- reading the deal ----------

  expected = () => ({
    deal: this.data,
    releaserAccount: this.lawyerB.ops.classicAddress,
    credentialSubjects: [this.alice.wallet.classicAddress, this.bob.wallet.classicAddress],
    escrow: {
      owner: this.alice.wallet.classicAddress,
      sequence: this.escrowSequence,
      amountDrops: this.escrowDrops,
      conditionHex: this.condition,
    },
  });

  /** The lock checker on one validated ledger: every finding, blocking or not. */
  async lockCheck(): Promise<Finding[]> {
    const snap = await snapshot(this.c.rpc, [this.wallet] as never);
    const a = snap.accounts[this.wallet] as NonNullable<(typeof snap.accounts)[string]>;
    const exp = {
      ...this.expected(),
      escrow: { ...this.expected().escrow, minCancelAfter: snap.ledger.closeTime + 86_400 },
    };
    return checkLock(a.accountData as Json, a.objects as Json[], exp as never);
  }
  lockOk = async () => allOk(await this.lockCheck());

  async balance(address: string): Promise<bigint> {
    const r = await this.c.client.request({ command: 'account_info', account: address, ledger_index: 'validated' });
    return BigInt(r.result.account_data.Balance);
  }

  async accountFlags(address: string = this.wallet): Promise<number> {
    const r = await this.c.client.request({ command: 'account_info', account: address, ledger_index: 'validated' });
    return r.result.account_data.Flags;
  }

  /** The shell's objects of one type, from a validated ledger. */
  async objects(type: string, address: string = this.wallet): Promise<Json[]> {
    const r = await this.c.client.request({
      command: 'account_objects',
      account: address,
      type: type as never,
      ledger_index: 'validated',
    });
    return r.result.account_objects as unknown as Json[];
  }

  // ---------- release (P7) ----------

  passports: Partial<Record<'A' | 'B', Uint8Array>> = {};
  readonly shipments: Uint8Array[] = [];
  readonly receipts: Uint8Array[] = [];
  shipped: { hash: Uint8Array; root: Uint8Array; ledgerIndex: number } | undefined;

  /** OD-37: Bob's slot B signs shipMsg (build/SHIP_RECEIPT.md 2). */
  async ship() {
    const items = [{ sku: 'TEST-1', description: 'test goods', qty: 1, weight_g: 1000 }];
    const root = manifestRoot(items);
    const f = {
      dealId: this.dealId,
      dealSeal: this.seal,
      manifestRoot: root,
      carrier: 'TEST-POST',
      trackingId: `TEST-${this.dealId.slice(-8)}`,
      ledgerIndex: (await ledgerRef(this.c)).index,
    };
    const msg = shipMsg(f);
    this.shipped = { hash: sha256(msg), root, ledgerIndex: f.ledgerIndex };
    this.shipments.push(
      await this.ev.event(
        'shipment.signed',
        {
          manifest_root: bytesToHex(root),
          carrier: f.carrier,
          tracking_id: f.trackingId,
          ledger_index: f.ledgerIndex,
          ship_msg_hash: bytesToHex(this.shipped.hash),
          slot_sig: bytesToHex(this.bob.slot.sign(msg)),
        },
        this.bob.slot,
        'bob',
      ),
    );
  }

  /** OD-37: Alice's slot A signs rcptMsg over Bob's shipment, condition ok (build/SHIP_RECEIPT.md 3). */
  async receive() {
    if (!this.shipped) throw new Error('no shipment yet');
    const f = {
      dealId: this.dealId,
      dealSeal: this.seal,
      shipmentHash: this.shipped.hash,
      manifestRoot: this.shipped.root,
      condition: 'ok' as const,
      ledgerIndex: (await ledgerRef(this.c)).index,
    };
    const msg = rcptMsg(f);
    this.receipts.push(
      await this.ev.event(
        'receipt.signed',
        {
          shipment_hash: bytesToHex(f.shipmentHash),
          manifest_root: bytesToHex(f.manifestRoot),
          condition: f.condition,
          ledger_index: f.ledgerIndex,
          rcpt_msg_hash: bytesToHex(sha256(msg)),
          slot_sig: bytesToHex(this.alice.slot.sign(msg)),
        },
        this.alice.slot,
        'alice',
      ),
    );
  }

  async readInput(): Promise<ReleaseInput> {
    const keys: KeyRow[] = [...this.slots().flatMap((s) => s.rows), ...this.verifier.rows];
    for (const [p, by] of [
      [this.alice, this.lawyerA],
      [this.bob, this.lawyerB],
    ] as const) {
      const anchor = await ledgerRef(this.c);
      this.history.push(anchor);
      this.passports[p.side] = await passportRecordAt(this.ev, p, by, {
        dealId: this.dealId,
        rootHex: this.rootHex,
        seal: this.seal,
        anchor,
        nonce: randomBytes(32),
        now: await this.closeNow(),
      });
    }
    const ledger = await readGateLedger(this.c, {
      wallet: this.wallet,
      opsA: this.lawyerA.ops.classicAddress,
      opsB: this.lawyerB.ops.classicAddress,
      mintHash: this.minted.hash,
      history: this.history,
    });
    return {
      profile: 'production',
      ledger,
      records: {
        passport: this.passports,
        zkProof: {},
        onboarding: this.rec.onboarding,
        bar: this.rec.bar,
        opsBound: this.rec.opsBound,
        pqBound: this.rec.pq,
        dkgCompleted: this.rec.dkg,
        shipments: this.shipments,
        receipts: this.receipts,
        keys,
        slotHolders: {
          A: this.alice.slot.holderIds(),
          LA: this.lawyerA.slot.holderIds(),
          B: this.bob.slot.holderIds(),
          LB: this.lawyerB.slot.holderIds(),
        },
      },
      deal: {
        id: this.dealId,
        data: this.data,
        mintTxHash: this.minted.hash,
        nftokenId: this.minted.nftokenId,
        credentialSubjects: [this.alice.wallet.classicAddress, this.bob.wallet.classicAddress],
        escrow: {
          owner: this.alice.wallet.classicAddress,
          sequence: this.escrowSequence,
          amountDrops: this.escrowDrops,
          conditionHex: this.condition,
        },
      },
      submitter: this.lawyerB.ops.classicAddress,
      config: { verifierIssuer: this.verifier.issuer.classicAddress, verifierKeyIds: this.verifier.keyIds },
    };
  }

  /** Runs the release gate on a real snapshot: findings in the contract order, the input, and the signed record. */
  async gate() {
    if (!this.shipped) await this.ship();
    if (this.receipts.length === 0) await this.receive();
    const input = await this.readInput();
    const findings = checkRelease(input);
    expect(findings.map((x) => x.code)).toEqual([...GATE_CODES]);
    const record = async () => {
      const g = await buildGatePassedRecord(
        input,
        {
          event_id: uuid7(),
          seq: 0,
          occurred_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
          prev_hash: '00'.repeat(32),
          payload_commitment: '00'.repeat(32),
        },
        this.lawyerB.slot.holderSigner(0),
        async (_env, msg) => this.lawyerB.slot.sign(msg),
      );
      expect(
        verifyGatePassedRecord(g.envelopeBytes, {
          deal: { id: this.dealId, data: this.data },
          keys: input.records.keys,
          lawyerB: this.lawyerB.slot.holderIds(),
          at: input.ledger.closeTime,
        }),
      ).toEqual({ ok: true });
      return g;
    };
    return { input, findings, failing: findings.filter((x) => !x.ok).map((x) => x.code), record };
  }

  /** Step 7 as the builder makes it. `fulfillment` and `escrow` default to the deal's own. */
  finishTx(o: { from?: string; leaf?: Uint8Array; fulfillment?: string; condition?: string; sequence?: number } = {}) {
    return build7(
      {
        releaser: o.from ?? this.lawyerB.ops.classicAddress,
        owner: this.aliceBase.wallet.classicAddress,
        offerSequence: o.sequence ?? this.escrowSequence,
        condition: o.condition ?? this.condition,
        fulfillment: o.fulfillment ?? this.fulfillment,
        gateLeafHash: o.leaf ?? randomBytes(32),
      },
      this.c.ctx,
    );
  }

  /** The releaser finishes with the gate record's leaf hash (the passing path of T-I-01). */
  async release() {
    const g = await this.gate();
    expect(g.failing).toEqual([]);
    const rec = await g.record();
    return this.c.send(this.lawyerB.ops, this.finishTx({ leaf: rec.leafHash }));
  }

  /**
   * A new quarantine escrow with a new release code (OD-28 fallback): lawyer B (the new one) makes a new 32-byte code and
   * sends only the condition; Alice creates the escrow with the usual three days. Replaces the deal's escrow fields.
   */
  async newEscrow(days = 3) {
    const code = randomBytes(32);
    const { condition, fulfillment } = makeCondition(code);
    const r = await this.c.send(
      this.aliceBase.wallet,
      build3(
        {
          alice: this.aliceBase.wallet.classicAddress,
          shell: this.wallet,
          amount: this.escrowDrops,
          condition,
          closeTime: await this.closeNow(),
          days,
        },
        this.c.ctx,
      ),
    );
    this.preimage = code;
    this.condition = condition;
    this.fulfillment = fulfillment;
    this.escrowSequence = Number(r.tx.Sequence);
    this.cancelAfter = Number(r.tx.CancelAfter);
    return r;
  }

  // ---------- exits (P8) ----------

  /** A 4-of-4 payment from the shell on slot S to a sealed payout (`payoutB` pays Bob, `payoutA` refunds Alice). */
  async exit(to: 'bob' | 'alice', amount: string = this.escrowDrops): Promise<Exit> {
    const receiver = to === 'bob' ? this.bob.wallet.classicAddress : this.alice.wallet.classicAddress;
    const receiverBefore = await this.balance(receiver);
    const deliveredBefore = await this.balance(this.wallet);
    const slot = await nextSlot(this.c.rpc, this.wallet);
    const payout = to === 'bob' ? this.data.payoutB : this.data.payoutA;
    const r = await this.c.multisend(build8({ shell: this.wallet, payout, amount, slot }, this.c.ctx), this.slots(), 5);
    return { hash: r.hash, deliveredBefore, receiverBefore, receiverAfter: await this.balance(receiver) };
  }

  /** AccountDelete needs the account Sequence 256 ledgers old: waits, then closes the shell to Alice (4-of-4). */
  async closeShell(fee: string = String(this.c.fees.ownerReserveDrops)) {
    const seq = (await nextSlot(this.c.rpc, this.wallet)).sequence;
    const now = (await ledgerRef(this.c)).index;
    await this.c.advance(Math.max(0, seq + 256 - now));
    return this.c.multisend(
      build9({ shell: this.wallet, destination: this.alice.wallet.classicAddress, ownerReserveDrops: fee }, this.c.ctx),
      this.slots(),
    );
  }

  // ---------- changes after the lock ----------

  /** A 4-of-4 transaction with the fee of a four-signer transaction. */
  multi4(tx: Record<string, unknown>, by: readonly SlotRole[] = this.slots()) {
    const fee = String(multisigFee(this.c.ctx.baseFeeDrops as number, 4));
    return this.c.multisend({ ...tx, Fee: fee } as unknown as xrpl.SubmittableTransaction, by);
  }

  /**
   * Replaces the slot of `role` (a stolen share, DESIGN 6.4) or the whole lawyer (`next`, DESIGN 5.4): a new DKG, new
   * contract signatures, a new NFT, a 4-of-4 `SignerListSet` signed by the OLD four, then `Domain` set again to the new
   * seal signed by the NEW four, and new records. A new lawyer for slot LB also swaps the releaser (`DepositPreauth`).
   */
  async swapLawyer(role: 'LA' | 'LB', next?: LawyerBase) {
    const old = role === 'LA' ? this.lawyerA : this.lawyerB;
    const oldFour = this.slots();
    if (next) await this.onboardLawyer(next);
    const fresh = withSlot(next ?? old, await makeSlot(role)) as LawyerRole;
    if (role === 'LA') this.lawyerA = fresh;
    else this.lawyerB = fresh;
    this.sc = await this.signContractSeal();
    this.minted = await this.mint();
    this.data = dealData(this.sealInput());
    this.seal = dealSeal(this.data);
    if (next && role === 'LB') {
      const preauth = { shell: this.wallet, signers: 4 };
      await this.c.multisend(build5dUnauthorize({ ...preauth, releaser: old.ops.classicAddress }, this.c.ctx), oldFour);
      await this.c.multisend(build5d({ ...preauth, releaser: fresh.ops.classicAddress }, this.c.ctx), oldFour);
    }
    await this.c.multisend(
      buildSignerListRotation({ shell: this.wallet, signers: this.slots().map((s) => s.address) }, this.c.ctx),
      oldFour,
    );
    await this.c.multisend(
      build5Domain({ shell: this.wallet, contractRoot: this.root, dealSeal: this.seal, signers: 4 }, this.c.ctx),
      this.slots(),
    );
    await this.writeLawyerRecords(fresh);
    const client = role === 'LA' ? this.alice : this.bob;
    this.rec.onboarding[client.side] = await onboardingRecord(this.ev, client, fresh, {
      dealId: this.dealId,
      rootHex: this.rootHex,
      now: await this.closeNow(),
    });
    await this.sealPq();
    return { old, fresh, oldFour };
  }
}

export async function newDeal(c: Chain, to: Stage, o: DealOptions = {}): Promise<Deal> {
  const d = new Deal(c, o);
  await d.advance(to);
  return d;
}
