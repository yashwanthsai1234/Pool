// The full flow P0 to P8 with zero-knowledge identity (T-I-12, IMPLEMENTATION 2.9) on a real standalone ledger.
// It is the flow of 2.5 (test-int/full-flow.int.test.ts) with the chip identity replaced, per side, by a ZKPassport
// proof: onboarding proofs at P5 (bound to the contract root and the planned slot key), release proofs at P7 (bound
// to the real presenceMsg: deal seal, fresh ledger hash, lawyer nonce). Proofs are made FRESH by the vendored headless
// prover; the real SDK verifies them in devMode, so the gate runs in the demo profile (DESIGN 6.10: devMode only there).
// Source: DESIGN.md 5.2, 6.2, 6.10, 6.15, 6.17; IMPLEMENTATION.md 2.9
import { PublicDealData } from '@legx/contracts/deal';
import { GATE_CODES } from '@legx/contracts/records';
import { distinctTag, presenceMsg } from '@legx/core/attest';
import { contractRoot } from '@legx/core/contract';
import { bindingMessage, dealSeal, makeCondition, utf8ToBytes } from '@legx/core/dealcore';
import { allOk, checkLock } from '@legx/core/lockcheck';
import { PACKAGE_SUITES, XWING_SUITE } from '@legx/core/pq';
import {
  buildGatePassedRecord,
  checkRelease,
  type KeyRow,
  type ReleaseInput,
  verifyGatePassedRecord,
} from '@legx/core/releaseGate';
import { buildSignedContractSeal, signContract } from '@legx/core/signedContract';
import {
  boxDigest,
  checkReleaseQuery,
  checkZkResult,
  type Disclosure,
  onboardingBoundValue,
  openDisclosure,
  openSalt,
  releaseBoundValue,
  sealDisclosure,
  sealSalt,
  trustRecordOf,
  zkIdentityCommitment,
} from '@legx/core/zkIdentity';
import { onboardingQuery, releaseQuery } from '@legx/zk/request';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
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
  build5d,
  build5e,
  build5f,
  build5g,
  build7,
  build8,
  build9,
  DISALLOW_KINDS,
} from '../../src/builders/index.ts';
import { advanceLedgers } from '../../src/ledger.ts';
import { nextSlot } from '../../src/multisig.ts';
import { snapshot } from '../../src/read.ts';
import {
  barDealLink,
  barVerification,
  type Chain,
  type ClientRole,
  dealData,
  evidenceFor,
  type Json,
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
  type Side,
  uuid7,
  withSlot,
} from '../roles.ts';
import {
  MOCK_ALICE,
  MOCK_BOB,
  type MockPerson,
  type ProofSet,
  type Prover,
  portRequest,
  proofSetBytes,
  type ZkVerification,
} from './zkTools.ts';

const ESCROW_DROPS = '50000000';
const RIPPLE_EPOCH_OFFSET = 946_684_800;
const FACTS = { minAge: 18 };

export type IdMethod = 'zkpassport' | 'nfc-chip';

export interface ZkFlowOptions {
  readonly prover: Prover;
  readonly policy: 'zk' | 'zk-or-chip';
  readonly methods: Readonly<Record<Side, IdMethod>>;
  /** The mock passport of each zero-knowledge side (the same object for both sides is P2.9-08). */
  readonly persons?: Readonly<Record<Side, MockPerson>>;
  /** `gate`: stop after the gate passed record; `close`: run P7 step 7 and P8. */
  readonly through: 'gate' | 'close';
  /** Called after the gate record exists and before EscrowFinish, with the state an attack test needs. */
  readonly beforeFinish?: (s: ZkFlowState) => Promise<void>;
  /** Called after the EscrowFinish is validated and before P8 (a standalone server forgets old ledgers after P8's wait). */
  readonly afterFinish?: (s: ZkFlowState) => Promise<void>;
}

/** What one side keeps of its zero-knowledge identity. */
export interface ZkSideState {
  readonly side: Side;
  readonly method: IdMethod;
  readonly salt: Uint8Array;
  readonly identifier?: string;
  readonly onboarding?: { set: ProofSet; verification: ZkVerification; roleDisclosure: Disclosure };
  readonly release?: {
    set: ProofSet;
    verification: ZkVerification;
    anchor: LedgerRef;
    nonce: Uint8Array;
    msg: Uint8Array;
  };
}

export interface ZkFlowState {
  readonly c: Chain;
  readonly dealId: string;
  readonly wallet: string;
  readonly data: PublicDealData;
  readonly seal: Uint8Array;
  readonly input: ReleaseInput;
  readonly findings: ReturnType<typeof checkRelease>;
  readonly sides: Record<Side, ZkSideState>;
  readonly alice: ClientRole;
  readonly bob: ClientRole;
  readonly lawyerA: LawyerRole;
  readonly lawyerB: LawyerRole;
  readonly minted: { hash: string; nftokenId: string };
  readonly gate: Awaited<ReturnType<typeof buildGatePassedRecord>>;
  readonly condition: string;
  readonly escrowSequence: number;
  readonly txHashes: readonly string[];
  readonly wrapped: {
    boxes: Record<
      Side,
      { salt: Awaited<ReturnType<typeof sealSalt>>; disclosure: Awaited<ReturnType<typeof sealDisclosure>> }
    >;
  };
  readonly xwing: Record<'LA' | 'LB', { publicKey: Uint8Array; secretKey: Uint8Array }>;
  readonly ev: ReturnType<typeof evidenceFor>;
  readonly ledgerSnapshots: { shell: Json[] };
  readonly balances?: { bobBefore: bigint; bobAfter: bigint; aliceBefore: bigint; aliceAfter: bigint };
  readonly finishHash?: string;
}

/** Runs the flow and returns the state the assertions need. A failure names the phase and the step. */
export async function runZkFlow(c: Chain, o: ZkFlowOptions): Promise<ZkFlowState> {
  const { ctx } = c;
  const logStart = c.log.length;
  const dealId = uuid7();
  const clauses = ['clause 0: goods', 'clause 1: price'].map(utf8ToBytes);
  const root = contractRoot(
    clauses,
    clauses.map(() => randomBytes(32)),
  );
  const rootHex = bytesToHex(root);
  const ev = evidenceFor(dealId, rootHex);
  const verifier = makeVerifier();
  const baseSide = { A: makeClient('A'), B: makeClient('B') };
  const baseA = makeLawyer('LA', 'Firm A', 'ed25519', 'CA-0000001');
  const baseB = makeLawyer('LB', 'Firm B', 'secp256k1', 'CA-0000002');
  const shell = newWallet('ed25519');
  let setupKey: typeof shell | undefined = shell;
  const wallet = shell.classicAddress;
  const onboarded = new Map<string, Uint8Array>();
  const history: LedgerRef[] = [];
  const closeNow = async () => (await ledgerRef(c)).closeTime;
  const xsuite = PACKAGE_SUITES[XWING_SUITE] as NonNullable<(typeof PACKAGE_SUITES)[string]>;
  const xwing = { LA: await xsuite.keygen(), LB: await xsuite.keygen() };
  const persons = o.persons ?? { A: MOCK_ALICE, B: MOCK_BOB };
  const zkSalt = { A: randomBytes(32), B: randomBytes(32) };

  // ----- P0 -----
  async function onboardLawyer(l: typeof baseA) {
    await c.fund(l.ops, 100);
    const at = await ledgerRef(c);
    history.push(at);
    const v = await barVerification(ev, verifier, l, at);
    onboarded.set(l.ops.classicAddress, v.envelope);
    await c.step(`P0 step 0a ${l.firm}: verifier issues LEGX_ATTORNEY`, () =>
      c.send(
        verifier.issuer,
        build0a(
          {
            issuer: verifier.issuer.classicAddress,
            subject: l.ops.classicAddress,
            barVerificationSha256: v.sha256,
            closeTime: at.closeTime,
          },
          ctx,
        ),
      ),
    );
    await c.step(`P0 step 0b ${l.firm}: operations account accepts`, () =>
      c.send(l.ops, build0b({ subject: l.ops.classicAddress, issuer: verifier.issuer.classicAddress }, ctx)),
    );
  }
  await c.step('P0 fund the verifier, Alice and Bob', async () => {
    await c.fund(verifier.issuer, 100);
    await c.fund(baseSide.A.wallet, 1000);
    await c.fund(baseSide.B.wallet, 100);
  });
  await onboardLawyer(baseA);
  await onboardLawyer(baseB);

  // ----- P2 -----
  const lawyerA = await c.step('P2 DKG for lawyer slot LA', async () => withSlot(baseA, await makeSlot('LA')));
  const lawyerB = await c.step('P2 DKG for lawyer slot LB', async () => withSlot(baseB, await makeSlot('LB')));
  const sc = await c.step('P2 both lawyers sign the contract (FROST)', async () => {
    const terms = {
      contractRoot: root,
      walletAddress: wallet,
      lawyerPubA: lawyerA.slot.pubHex,
      lawyerPubB: lawyerB.slot.pubHex,
    };
    const sigLA = await signContract(async (m) => lawyerA.slot.sign(m), terms, 'LA');
    const sigLB = await signContract(async (m) => lawyerB.slot.sign(m), terms, 'LB');
    return { ...buildSignedContractSeal(terms, { sigLA, sigLB }), sigs: { sigLA, sigLB } };
  });

  // ----- P3 mint -----
  const minted = await c.step('P3 step 1 NFTokenMint with the signed-contract seal and memo', async () => {
    const memo = { lawyerPubA: lawyerA.slot.pubHex, lawyerPubB: lawyerB.slot.pubHex, ...sc.sigs };
    const r = await c.send(
      lawyerA.ops,
      build1({ lawyerOpsA: lawyerA.ops.classicAddress, signedContractSeal: sc.seal, memo }, ctx),
    );
    return { hash: r.hash, nftokenId: String(r.meta.nftoken_id) };
  });

  // ----- P4 fund -----
  const preimage = randomBytes(32);
  const { condition, fulfillment } = makeCondition(preimage);
  await c.step('P4 step 2 Alice funds the shell', () =>
    c.send(
      baseSide.A.wallet,
      build2({ alice: baseSide.A.wallet.classicAddress, shell: wallet, amount: '100000000' }, ctx),
    ),
  );
  const escrowTx = await c.step('P4 step 3 EscrowCreate to the shell', async () =>
    c.send(
      baseSide.A.wallet,
      build3(
        {
          alice: baseSide.A.wallet.classicAddress,
          shell: wallet,
          amount: ESCROW_DROPS,
          condition,
          closeTime: await closeNow(),
          days: 3,
        },
        ctx,
      ),
    ),
  );
  const escrowSequence = Number(escrowTx.tx.Sequence);
  const cancelAfter = Number(escrowTx.tx.CancelAfter) + RIPPLE_EPOCH_OFFSET; // unix seconds, for the expiry margin

  // ----- P5 keys, onboarding, lock -----
  const aliceSlot = await c.step('P5 DKG for client slot A', () => makeSlot('A'));
  const bobSlot = await c.step('P5 DKG for client slot B', () => makeSlot('B'));
  const slotOf = { A: aliceSlot, B: bobSlot };
  const lawyerOf = { A: lawyerA, B: lawyerB };
  const xwingOf = { A: xwing.LA, B: xwing.LB };

  const sides = { A: undefined, B: undefined } as unknown as Record<Side, ZkSideState>;
  const boxes = {} as ZkFlowState['wrapped']['boxes'];
  const clients = {} as Record<Side, ClientRole>;
  const onboardingRecs = {} as Record<Side, Uint8Array>;

  async function onboardSide(s: Side) {
    const method = o.methods[s];
    const slot = slotOf[s];
    const by = lawyerOf[s];
    if (method === 'nfc-chip') {
      const chipClient = withSlot(baseSide[s], slot);
      clients[s] = chipClient;
      sides[s] = { side: s, method, salt: zkSalt[s] };
      onboardingRecs[s] = await onboardingRecord(ev, chipClient, by, { dealId, rootHex, now: await closeNow() });
      return;
    }
    const { set, verification } = await c.idle(async () => {
      const made = await o.prover.prove({
        person: persons[s],
        dealId,
        stage: 'onboarding',
        build: (b) =>
          onboardingQuery(b, { facts: FACTS, contractRoot: root, slotPub: hexToBytes(slot.pubHex), cancelAfter }),
      });
      return { set: made, verification: (await o.prover.adapter.verifyDetailed(portRequest(made))).verification };
    });
    const checked = checkZkResult(verification, set.request.originalQuery, {
      stage: 'onboarding',
      dealId,
      profile: 'demo',
      cancelAfter,
      boundValue: onboardingBoundValue(root, hexToBytes(slot.pubHex)),
    });
    if (!checked.ok) throw new Error(`onboarding proof of ${s} refused: ${checked.code}`);
    const commitment = zkIdentityCommitment(zkSalt[s], checked.identifier);
    const shown = set.queryResult as unknown as Record<string, { disclose: { result: unknown } }>;
    const text = (k: string) => {
      const v = shown[k]?.disclose.result;
      return v instanceof Date ? v.toISOString() : String(v);
    };
    const facts: Disclosure = {
      firstname: text('firstname'),
      lastname: text('lastname'),
      birthdate: text('birthdate'),
      nationality: text('nationality'),
    };
    const pub = xwingOf[s].publicKey;
    const disclosure = await sealDisclosure(facts, pub, dealId, s);
    const saltBox = await sealSalt(zkSalt[s], pub, dealId, s);
    boxes[s] = { salt: saltBox, disclosure };
    clients[s] = { ...withSlot(baseSide[s], slot), salt: zkSalt[s], commitment };
    sides[s] = {
      side: s,
      method,
      salt: zkSalt[s],
      identifier: checked.identifier,
      onboarding: { set, verification, roleDisclosure: facts },
    };
    const query = set.request.originalQuery as Record<string, { gt?: string }>;
    onboardingRecs[s] = await ev.attestation(
      {
        deal_id: dealId,
        contract_root: rootHex,
        side: s,
        slot_pub: slot.pubHex,
        commitment: bytesToHex(commitment),
        disclosure_box_sha256: boxDigest(disclosure),
        distinct_tag: bytesToHex(distinctTag(dealId, utf8ToBytes(String(checked.identifier)))), // OD-29
        method: 'zkpassport',
        checks: {
          proof_verified: true,
          bound_value_matches: true,
          expiry_after_cancel_plus_30d: Date.parse(String(query.expiry_date?.gt)) / 1000 >= cancelAfter + 30 * 86400,
          age_over_18: true,
          scope: set.request.scope,
          domain: set.request.domain,
          unique_identifier: checked.identifier,
          proof_sha256: verification.proofSha256,
          trust: trustRecordOf(verification),
        },
        checked_by_role: `lawyer${s}`,
        sig_algs: ['ed25519', 'ml-dsa-65'],
      },
      by.slot.holderSigner(0),
    );
  }
  await c.step('P5 onboarding of A (proof made, verified by the SDK, sealed to lawyer A)', () => onboardSide('A'));
  await c.step('P5 onboarding of B (proof made, verified by the SDK, sealed to lawyer B)', () => onboardSide('B'));
  const alice = clients.A as ClientRole;
  const bob = clients.B as ClientRole;

  const rec = {
    bar: {} as Partial<Record<'LA' | 'LB', { link: Uint8Array; verification: Uint8Array }>>,
    opsBound: {} as Partial<Record<'LA' | 'LB', Uint8Array>>,
    dkg: {} as Partial<Record<'A' | 'B' | 'LA' | 'LB', Uint8Array>>,
    pq: {} as Partial<Record<'A' | 'B' | 'LA' | 'LB', Uint8Array>>,
  };
  await c.step('P2 bar links, operations-account bindings, DKG records', async () => {
    for (const l of [lawyerA, lawyerB]) {
      const verification = onboarded.get(l.ops.classicAddress) as Uint8Array;
      rec.bar[l.role] = { link: await barDealLink(ev, verifier, l, verification, { dealId, rootHex }), verification };
      const who = l.role === 'LA' ? 'lawyerA' : 'lawyerB';
      rec.opsBound[l.role] = await ev.event('ops.bound', opsBoundData(l, rootHex), l.slot, who);
      rec.dkg[l.role] = await ev.event('frost.dkg.completed', l.slot.dkg, l.slot, who);
    }
    rec.dkg.A = await ev.event('frost.dkg.completed', alice.slot.dkg, alice.slot, 'alice');
    rec.dkg.B = await ev.event('frost.dkg.completed', bob.slot.dkg, bob.slot, 'bob');
  });

  const bindings = await c.step('P5 client bindings (FROST, two shares each)', async () => {
    const out = {} as Record<Side, Uint8Array>;
    for (const p of [alice, bob]) out[p.side] = p.slot.sign(bindingMessage(root, p.commitment, p.slot.pubHex, p.side));
    return out;
  });

  const data = PublicDealData.parse({
    ...dealData({ rootHex, signedContractSeal: sc.seal, wallet, alice, bob, lawyerA, lawyerB }),
    idMethodA: o.methods.A,
    idMethodB: o.methods.B,
    identityPolicy: o.policy,
  });
  const seal = dealSeal(data);
  const slots = [alice.slot, lawyerA.slot, bob.slot, lawyerB.slot];
  await c.step('P5 deal seal and post-quantum bindings', async () => {
    for (const s of slots) {
      const who = s.name === 'A' ? 'alice' : s.name === 'B' ? 'bob' : s.name === 'LA' ? 'lawyerA' : 'lawyerB';
      rec.pq[s.name] = await ev.event('pq.bound', pqBoundData(s, seal), s, who);
    }
  });
  const setup = (tx: xrpl.SubmittableTransaction) => {
    if (!setupKey) throw new Error('the shell setup key was wiped');
    return c.send(setupKey, tx);
  };
  await c.step('P5 step 5a SignerListSet 4-of-4', () =>
    setup(build5a({ shell: wallet, signers: slots.map((s) => s.address) }, ctx)),
  );
  await c.step('P5 step 5b AccountSet Domain and DepositAuth', () =>
    setup(build5b({ shell: wallet, contractRoot: root, dealSeal: seal }, ctx)),
  );
  for (const kind of DISALLOW_KINDS)
    await c.step(`P5 step 5c AccountSet DisallowIncoming ${kind}`, () => setup(build5c({ shell: wallet, kind }, ctx)));
  await c.step('P5 step 5d DepositPreauth for the releaser', () =>
    setup(build5d({ shell: wallet, releaser: lawyerB.ops.classicAddress }, ctx)),
  );
  for (const p of [alice, bob]) {
    await c.step(`P5 step 5e CredentialCreate ${p.name}`, () =>
      setup(
        build5e({ shell: wallet, subject: p.wallet.classicAddress, side: p.side, bindingSig: bindings[p.side] }, ctx),
      ),
    );
    await c.step(`P5 step 5f CredentialAccept ${p.name}`, () =>
      c.send(p.wallet, build5f({ subject: p.wallet.classicAddress, shell: wallet, side: p.side }, ctx)),
    );
  }
  await c.step('P5 step 5g AccountSet DisableMaster', () => setup(build5g({ shell: wallet }, ctx)));
  setupKey = undefined;

  // ----- P6 lock check -----
  const lockSnap = await c.step('P6 lock checker on one validated ledger', async () => {
    const snap = await snapshot(c.rpc, [wallet] as never);
    const a = snap.accounts[wallet] as NonNullable<(typeof snap.accounts)[string]>;
    const findings = checkLock(
      a.accountData as Json,
      a.objects as Json[],
      {
        deal: data,
        releaserAccount: lawyerB.ops.classicAddress,
        credentialSubjects: [alice.wallet.classicAddress, bob.wallet.classicAddress],
        escrow: {
          owner: alice.wallet.classicAddress,
          sequence: escrowSequence,
          amountDrops: ESCROW_DROPS,
          conditionHex: condition,
          minCancelAfter: snap.ledger.closeTime + 86_400,
        },
      } as never,
    );
    if (!allOk(findings)) throw new Error(`lock checker: ${JSON.stringify(findings.filter((f) => !f.ok))}`);
    return a.objects as Json[];
  });

  // ----- P7 release: fresh proofs bound to the real presenceMsg -----
  const passports = {} as Partial<Record<Side, Uint8Array>>;
  const zkProof = {} as Partial<Record<Side, Uint8Array>>;
  for (const [s, p, by] of [
    ['A', alice, lawyerA],
    ['B', bob, lawyerB],
  ] as const) {
    await c.step(`P7 passport attestation of ${s} (${o.methods[s]}, bound to presenceMsg)`, async () => {
      const anchor = await ledgerRef(c);
      history.push(anchor);
      const nonce = randomBytes(32);
      if (o.methods[s] === 'nfc-chip') {
        passports[s] = await passportRecordAt(ev, p, by, {
          dealId,
          rootHex,
          seal,
          anchor,
          nonce,
          now: await closeNow(),
        });
        return;
      }
      const msg = presenceMsg(seal, s, hexToBytes(anchor.hash), nonce);
      const { set, verification } = await c.idle(async () => {
        const made = await o.prover.prove({
          person: persons[s],
          dealId,
          stage: 'release',
          build: (b) =>
            releaseQuery(b, { facts: FACTS, presenceMsg: msg, faceMatch: false, dealAllowsNoFaceMatch: true }),
        });
        return { set: made, verification: (await o.prover.adapter.verifyDetailed(portRequest(made))).verification };
      });
      const checked = checkZkResult(verification, set.request.originalQuery, {
        stage: 'release',
        dealId,
        profile: 'demo',
        boundValue: releaseBoundValue(msg),
        identity: { zkSalt32: zkSalt[s], commitment: bytesToHex(p.commitment) },
        faceMatchOptional: true,
      });
      if (!checked.ok) throw new Error(`release proof of ${s} refused: ${checked.code}`);
      const onboardingQ = (sides[s].onboarding as NonNullable<ZkSideState['onboarding']>).set.request.originalQuery;
      const same = checkReleaseQuery(onboardingQ, set.request.originalQuery, true);
      if (!same.ok) throw new Error(`release request differs from onboarding: ${same.code}`);
      (sides[s] as { release?: ZkSideState['release'] }).release = { set, verification, anchor, nonce, msg };
      zkProof[s] = proofSetBytes(set.proofs);
      passports[s] = await ev.attestation(
        {
          deal_id: dealId,
          contract_root: rootHex,
          deal_seal: bytesToHex(seal),
          side: s,
          commitment: bytesToHex(p.commitment),
          ledger_anchor: { ledger_index: anchor.index, ledger_hash: anchor.hash },
          method: 'zkpassport',
          checks: {
            proof_verified: true,
            identifier_matches: checked.identifier === sides[s].identifier,
            bound_value_is_presence_msg: true,
            document_not_expired: true,
            // OD-34: the headless prover makes no face match, so the honest result is false. The demo profile accepts it
            // (dev-mode proof) and the gate adds a DEMO_NO_FACE_MATCH warning; production would refuse it.
            face_match_passed: false,
            proof_sha256: verification.proofSha256,
            trust: trustRecordOf(verification),
          },
          presence_sig: bytesToHex(p.slot.sign(msg)),
          lawyer_nonce: bytesToHex(nonce),
          checked_by_role: `lawyer${s}`,
          sig_algs: ['ed25519', 'ml-dsa-65'],
        },
        by.slot.holderSigner(0),
      );
    });
  }

  const input = await c.step('P7 gate input from one validated ledger', async (): Promise<ReleaseInput> => {
    const keys: KeyRow[] = [...slots.flatMap((s) => s.rows), ...verifier.rows];
    const ledger = await readGateLedger(c, {
      wallet,
      opsA: lawyerA.ops.classicAddress,
      opsB: lawyerB.ops.classicAddress,
      mintHash: minted.hash,
      history,
    });
    return {
      profile: 'demo',
      ledger,
      records: {
        passport: passports,
        zkProof,
        onboarding: onboardingRecs,
        bar: rec.bar,
        opsBound: rec.opsBound,
        pqBound: rec.pq,
        dkgCompleted: rec.dkg,
        keys,
        slotHolders: {
          A: alice.slot.holderIds(),
          LA: lawyerA.slot.holderIds(),
          B: bob.slot.holderIds(),
          LB: lawyerB.slot.holderIds(),
        },
      },
      deal: {
        id: dealId,
        data,
        mintTxHash: minted.hash,
        nftokenId: minted.nftokenId,
        credentialSubjects: [alice.wallet.classicAddress, bob.wallet.classicAddress],
        escrow: {
          owner: alice.wallet.classicAddress,
          sequence: escrowSequence,
          amountDrops: ESCROW_DROPS,
          conditionHex: condition,
        },
      },
      submitter: lawyerB.ops.classicAddress,
      config: { verifierIssuer: verifier.issuer.classicAddress, verifierKeyIds: verifier.keyIds },
    };
  });
  const findings = checkRelease(input);
  const gate = await c.step('P7 release.gate.passed record (slot LB signs through FROST)', async () => {
    if (!findings.every((f) => f.ok)) return undefined as never;
    const g = await buildGatePassedRecord(
      input,
      {
        event_id: uuid7(),
        seq: 0,
        occurred_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
        prev_hash: '00'.repeat(32),
        payload_commitment: '00'.repeat(32),
      },
      lawyerB.slot.holderSigner(0),
      async (_env, msg) => lawyerB.slot.sign(msg),
    );
    const ok = verifyGatePassedRecord(g.envelopeBytes, {
      deal: { id: dealId, data },
      keys: input.records.keys,
      lawyerB: lawyerB.slot.holderIds(),
      at: input.ledger.closeTime,
    });
    if (!ok.ok) throw new Error(`gate record refused: ${JSON.stringify(ok)}`);
    return g;
  });

  const state: ZkFlowState = {
    c,
    dealId,
    wallet,
    data,
    seal,
    input,
    findings,
    sides,
    alice,
    bob,
    lawyerA,
    lawyerB,
    minted,
    gate,
    condition,
    escrowSequence,
    txHashes: [],
    wrapped: { boxes },
    xwing,
    ev,
    ledgerSnapshots: { shell: lockSnap },
  };
  if (!findings.every((f) => f.ok) || o.through === 'gate')
    return { ...state, txHashes: c.log.slice(logStart).map((l) => l.hash) };
  if (findings.filter((f) => f.level === 'block').length !== GATE_CODES.length)
    throw new Error('the gate did not run every code');
  await o.beforeFinish?.(state);

  // ----- P7 step 7 and P8 -----
  const balance = async (a: string) =>
    BigInt(
      (await c.client.request({ command: 'account_info', account: a, ledger_index: 'validated' })).result.account_data
        .Balance,
    );
  const finish = await c.step('P7 step 7 EscrowFinish from the releaser with the gate memo', () =>
    c.send(
      lawyerB.ops,
      build7(
        {
          releaser: lawyerB.ops.classicAddress,
          owner: alice.wallet.classicAddress,
          offerSequence: escrowSequence,
          condition,
          fulfillment,
          gateLeafHash: gate.leafHash,
        },
        ctx,
      ),
    ),
  );
  await o.afterFinish?.({ ...state, txHashes: c.log.slice(logStart).map((l) => l.hash), finishHash: finish.hash });
  const bobBefore = await balance(bob.wallet.classicAddress);
  const slotS = await nextSlot(c.rpc, wallet);
  await c.step('P8 step 8 Payment to Bob, 4-of-4 on slot S', () =>
    c.multisend(build8({ shell: wallet, payout: data.payoutB, amount: ESCROW_DROPS, slot: slotS }, ctx), slots, 5),
  );
  const bobAfter = await balance(bob.wallet.classicAddress);
  await c.step('P8 wait 256 ledgers', async () => {
    const seq = (await nextSlot(c.rpc, wallet)).sequence;
    const now = (await ledgerRef(c)).index;
    await advanceLedgers(c.client, Math.max(0, seq + 256 - now));
  });
  const aliceBefore = await balance(alice.wallet.classicAddress);
  await c.step('P8 step 9 AccountDelete to Alice, 4-of-4', () =>
    c.multisend(
      build9(
        {
          shell: wallet,
          destination: alice.wallet.classicAddress,
          ownerReserveDrops: String(c.fees.ownerReserveDrops),
        },
        ctx,
      ),
      slots,
    ),
  );
  const aliceAfter = await balance(alice.wallet.classicAddress);
  return {
    ...state,
    txHashes: c.log.slice(logStart).map((l) => l.hash),
    balances: { bobBefore, bobAfter, aliceBefore, aliceAfter },
    finishHash: finish.hash,
  };
}

/** The sealed boxes of a side open for its own lawyer only (P2.9-07 support, DESIGN 6.2, 6.10). */
export async function openBoxes(s: ZkFlowState, side: Side) {
  const lawyer = side === 'A' ? 'LA' : 'LB';
  const b = s.wrapped.boxes[side];
  return {
    salt: await openSalt(b.salt, s.xwing[lawyer].secretKey, s.dealId, side),
    disclosure: await openDisclosure(b.disclosure, s.xwing[lawyer].secretKey, s.dealId, side),
    other: await openSalt(b.salt, s.xwing[side === 'A' ? 'LB' : 'LA'].secretKey, s.dealId, side),
  };
}
