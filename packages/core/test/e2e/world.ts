// E2E-P1: the paper deal. Builds a whole deal with pure functions only and records every stage's output, so the
// suite can break one input at a time. The ledger is synthetic account_info / account_objects JSON.

import type { PublicDealData } from '@legx/contracts/deal';
import type { SignerPort } from '@legx/contracts/ports';
import type { KeyId } from '@legx/contracts/values';
import { chipAnswerAA, makePassport, makeTestPki } from '@legx/fixtures';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import * as xrpl from 'xrpl';
import { distinctTag, presenceMsg } from '../../src/attest.ts';
import { barNumberSha256, openBarCommitment } from '../../src/bar.ts';
import { contractRoot } from '../../src/contract.ts';
import { bindingMessage, dealSeal, domain, mth, passportCommitment, tupleHash } from '../../src/dealcore.ts';
import { type Envelope, pae } from '../../src/evidence.ts';
import { type Commitment, type SlotName, verifyEd25519Strict } from '../../src/frost.ts';
import { messageAllowed, type SealedDeal, type SignRequest } from '../../src/frostRules.ts';
import { signHybrid } from '../../src/hybridEnvelope.ts';
import { lsf } from '../../src/lockcheck.ts';
import { opsBindMsg } from '../../src/opsBinding.ts';
import { aaChallenge } from '../../src/passport/activeAuth.ts';
import { chipChecks, passportRecord } from '../../src/passport/passiveAuth.ts';
import { mldsaSign, nobleHybridSigner, pqBindMsg, pqKeygen, toBase64 } from '../../src/pq.ts';
import { signCheckpoint } from '../../src/pqCheckpoint.ts';
import {
  buildGatePassedRecord,
  checkRelease,
  gateMemo,
  type KeyRow,
  type ReleaseInput,
} from '../../src/releaseGate.ts';
import { buildSignedContractSeal, contractSigMsg, MINT_MEMO_TYPE } from '../../src/signedContract.ts';
import {
  checkZkResult,
  onboardingBoundValue,
  publicProofSet,
  releaseBoundValue,
  trustRecordOf,
  type ZkExpectation,
  zkIdentityCommitment,
} from '../../src/zkIdentity.ts';
import {
  ALICE,
  ATTEST,
  BOB,
  bytes,
  CONDITION,
  EVENT,
  h32,
  LEGX_ATTORNEY,
  nftokenId,
  OPS,
  proofSet,
  VERIFIER_ISSUER,
  WALLET,
} from '../helpers/gate.ts';
import { shipBuilders } from '../helpers/ship.ts';
import { zkSet } from '../helpers/zkFixtures.ts';
import { makeSlot, type Slot } from './slots.ts';

export type Json = Record<string, unknown>;
export type Side = 'A' | 'B';
export type Role = 'LA' | 'LB';
export const SLOT_NAMES = ['A', 'LA', 'B', 'LB'] as const;
const up = (b: Uint8Array) => bytesToHex(b).toUpperCase();

// ---------- the recorded zero-knowledge sets (packages/zk/fixtures, read as plain files) ----------

export const ZK = { onboarding: zkSet('alice-onboarding'), release: zkSet('alice-release') };
const FX = ZK.onboarding.inputs;
export const DEAL_ID = FX.deal1;
export const ZK_SALT = new Uint8Array(32).fill(0x61);
export const ZK_IDENTIFIER = ZK.onboarding.verification.uniqueIdentifier as string;
/** The recorded proofs are bound to the fixture's own deal inputs (seal 0x55.., slot key ed33..), so the results are
 * checked there; the live deal reuses their verification records (identifier, proof hash, trust record). */
export const FIXTURE_ONBOARD: ZkExpectation = {
  stage: 'onboarding',
  dealId: FX.deal1,
  boundValue: onboardingBoundValue(hexToBytes(FX.contractRoot), hexToBytes(FX.slotPub)),
  profile: 'demo',
  cancelAfter: FX.cancelAfter,
};
export const FIXTURE_RELEASE: ZkExpectation = {
  stage: 'release',
  dealId: FX.deal1,
  boundValue: releaseBoundValue(
    presenceMsg(hexToBytes(FX.dealSeal1), 'A', hexToBytes(FX.ledgerHash), hexToBytes(FX.lawyerNonce)),
  ),
  profile: 'demo',
  identity: { zkSalt32: ZK_SALT, commitment: bytesToHex(zkIdentityCommitment(ZK_SALT, ZK_IDENTIFIER)) },
  faceMatchOptional: true,
};
export const zkProofBytes = (s: typeof ZK.release) => utf8ToBytes(JSON.stringify(publicProofSet(s.proofs)));

// ---------- time and ledger ----------

/** 2027-06-01T12:00:00Z in Ripple epoch seconds: inside the fixture passport's validity windows. */
export const NOW = 865_080_000;
export const LEDGER = { index: 90_000_100, hash: up(new Uint8Array(32).fill(0x99)), closeTime: NOW };
export const ANCHOR = { ledger_index: 90_000_090, ledger_hash: up(new Uint8Array(32).fill(0x77)) };
const BAR_LEDGER = { ledger_index: 89_000_000, ledger_hash: up(new Uint8Array(32).fill(0x78)) };
const HISTORY = [
  { index: ANCHOR.ledger_index, hash: ANCHOR.ledger_hash, closeTime: NOW - 60 },
  { index: BAR_LEDGER.ledger_index, hash: BAR_LEDGER.ledger_hash, closeTime: NOW - 10 * 86_400 },
];
/** The fixture's CancelAfter (Unix 2030-01-01) in Ripple epoch seconds. */
const CANCEL_AFTER = FX.cancelAfter - 946_684_800;
export const NONCE = { A: FX.lawyerNonce, B: h32(0x53) };

// ---------- fixed keys ----------

const verifierPq = pqKeygen(new Uint8Array(32).fill(0x70));
const verifierEd = new Uint8Array(32).fill(0x71);
const VERIFIER_KEY_IDS = { ed25519: 'verifier/ed', mlDsa65: 'verifier/pq' };
const VERIFIER_ROWS: KeyRow[] = [
  {
    keyId: 'verifier/ed',
    alg: 'ed25519',
    publicKey: ed25519.getPublicKey(verifierEd),
    validFrom: 1,
    logged: true,
    pair: 'verifier',
  },
  {
    keyId: 'verifier/pq',
    alg: 'ml-dsa-65',
    publicKey: verifierPq.publicKey,
    validFrom: 1,
    logged: true,
    pair: 'verifier',
  },
];
const verifierSigner = nobleHybridSigner(
  {
    keyId: 'verifier/ed' as KeyId,
    publicKey: ed25519.getPublicKey(verifierEd),
    sign: async (m) => ed25519.sign(m, verifierEd),
  },
  { keyId: 'verifier/pq' as KeyId, secretKey: verifierPq.secretKey },
);
export const LOG = {
  origin: 'legx.dev/log/e2e',
  edSeed: new Uint8Array(32).fill(21),
  pq: ml_dsa44.keygen(new Uint8Array(32).fill(22)),
};
const CHIP_MRZ = {
  documentNumber: 'L898902C3',
  surname: 'ERIKSSON',
  givenNames: 'ANNA MARIA',
  dateOfBirth: '740812',
  sex: 'F',
  dateOfExpiry: '340415',
} as const;
const BAR = { LA: { jurisdiction: 'US-CA', number: 'A-123456' }, LB: { jurisdiction: 'US-NY', number: 'B-654321' } };

export interface DealOptions {
  /** Which fixtures client A uses: the recorded zero-knowledge path (default) or a second chip passport. */
  methodA?: 'zkpassport' | 'nfc-chip';
  policy?: 'zk' | 'zk-or-chip' | 'chip';
  /** Client A uses client B's chip passport (one person on both sides): with the same salt C_A equals C_B; with `other-salt` it does not. */
  sameChip?: boolean | 'other-salt';
  /** Slots from an earlier build can be reused (their enrollment keys stay valid, the seal differs). */
  slots?: Record<SlotName, Slot>;
}

async function makeSlots(): Promise<Record<SlotName, Slot>> {
  const out = {} as Record<SlotName, Slot>;
  let n = 0x60;
  for (const s of SLOT_NAMES) {
    out[s] = await makeSlot(s, n);
    n += 3;
  }
  return out;
}

/** Everything one paper deal produces, stage by stage. */
export async function buildPaperDeal(o: DealOptions = {}) {
  const methodA = o.methodA ?? 'zkpassport';
  // Stage 1 and 4: the four slots (a FROST DKG each, with transcripts and three-pair test-signing).
  const S = o.slots ?? (await makeSlots());

  // Stage 1: the contract names the wallet (clause 1 carries the wallet address).
  const clauses = [
    `The seller delivers the goods; the escrow wallet is ${WALLET}.`,
    'The buyer pays 5000 XRP into the escrow wallet.',
    'Both lawyers co-sign this contract; the wallet releases only on both lawyers and the gate.',
  ].map((c) => utf8ToBytes(c));
  const clauseSalts = clauses.map((_, i) => new Uint8Array(32).fill(0x40 + i));
  const root = contractRoot(clauses, clauseSalts);
  const rootHex = bytesToHex(root);

  const slotPubs = Object.fromEntries(SLOT_NAMES.map((s) => [s, hexToBytes(S[s].pubHex)])) as Record<
    SlotName,
    Uint8Array
  >;
  const sealedDeal = (seal?: Uint8Array): SealedDeal => ({
    walletAddress: WALLET,
    contractRoot: root,
    dealId: DEAL_ID,
    ...(seal ? { dealSeal: seal } : {}),
    payoutA: { account: ALICE, tag: 7 },
    payoutB: { account: BOB },
    exitAmountDrops: '5000000000',
    maxFeeDrops: '100',
    slotPubs,
  });
  /** A slot signs a tagged tupleHash message only if the holders' allow-list accepts it for this deal. */
  const signTagged = (
    slot: SlotName,
    tag: string,
    parts: Uint8Array[],
    seal?: Uint8Array,
    holders: [number, number] = [0, 1],
  ) => {
    const req: SignRequest = { kind: 'tagged', tag, parts };
    return S[slot].sign(
      tupleHash(tag, parts),
      (m: Uint8Array, _l: readonly Commitment[]) => messageAllowed(req, m, sealedDeal(seal), slot),
      holders[0],
      holders[1],
    );
  };

  // Stage 2: both lawyer slots sign the contract through FROST; stage 3: NFT URI and memo.
  const contractSigs = {
    sigLA: signTagged('LA', 'legx/contract-sign/v1', [root, utf8ToBytes(WALLET), utf8ToBytes('LA')]),
    sigLB: signTagged('LB', 'legx/contract-sign/v1', [root, utf8ToBytes(WALLET), utf8ToBytes('LB')]),
  };
  const terms = { contractRoot: root, walletAddress: WALLET, lawyerPubA: S.LA.pubHex, lawyerPubB: S.LB.pubHex };
  const sc = buildSignedContractSeal(terms, contractSigs);

  // Identity. Client A: zero-knowledge (recorded results) or chip; client B: chip. Lawyers: bar commitments.
  const pki = makeTestPki({ seed: new Uint8Array(32).fill(9) });
  const chipSeed = (n: number) => new Uint8Array(32).fill(n);
  const chip = (n: number) => {
    // Two clients hold two documents (another document number), so their OD-29 distinct tags differ.
    const mrz = n === 1 ? CHIP_MRZ : { ...CHIP_MRZ, documentNumber: `D2345678${n}` };
    const passport = makePassport({ pki, mrz, seed: chipSeed(n) });
    const salt = new Uint8Array(32).fill(0x70 + n);
    return { passport, salt, commitment: passportCommitment(passportRecord(passport.dg1, passport.sod), salt) };
  };
  const chipB = chip(1);
  const sameChipOf = (c: typeof chipB, how: true | 'other-salt') => {
    if (how !== 'other-salt') return c;
    const salt = new Uint8Array(32).fill(0x99);
    return {
      passport: c.passport,
      salt,
      commitment: passportCommitment(passportRecord(c.passport.dg1, c.passport.sod), salt),
    };
  };
  const chipA = methodA === 'nfc-chip' ? (o.sameChip ? sameChipOf(chipB, o.sameChip) : chip(2)) : undefined;
  const commitmentA = chipA ? chipA.commitment : zkIdentityCommitment(ZK_SALT, ZK_IDENTIFIER);
  const lawyerSalt = { LA: new Uint8Array(32).fill(0x81), LB: new Uint8Array(32).fill(0x82) };
  const LC = {
    LA: openBarCommitment(lawyerSalt.LA, BAR.LA.jurisdiction, BAR.LA.number),
    LB: openBarCommitment(lawyerSalt.LB, BAR.LB.jurisdiction, BAR.LB.number),
  };

  // Stage 6: the 29-field deal seal and the 01 Domain.
  const data = {
    contractRoot: rootHex,
    signedContractSeal: bytesToHex(sc.seal),
    walletAddress: WALLET,
    xPubA: S.A.pubHex,
    xPubB: S.B.pubHex,
    commitmentA: bytesToHex(commitmentA),
    commitmentB: bytesToHex(chipB.commitment),
    idMethodA: methodA,
    idMethodB: 'nfc-chip',
    identityPolicy: o.policy ?? 'zk-or-chip',
    lawyerPubA: S.LA.pubHex,
    lawyerPubB: S.LB.pubHex,
    lawyerCommitmentA: bytesToHex(LC.LA),
    lawyerCommitmentB: bytesToHex(LC.LB),
    lawyerOpsA: OPS.LA.address,
    lawyerOpsB: OPS.LB.address,
    releaserAccount: OPS.LB.address,
    slotPolicyA: S.A.policy,
    slotPolicyLA: S.LA.policy,
    slotPolicyB: S.B.policy,
    slotPolicyLB: S.LB.policy,
    pqKeyHashA: S.A.pqKeyHash,
    pqKeyHashLA: S.LA.pqKeyHash,
    pqKeyHashB: S.B.pqKeyHash,
    pqKeyHashLB: S.LB.pqKeyHash,
    signerAccounts: SLOT_NAMES.map((s) => xrpl.deriveAddress(S[s].pubHex)),
    quorum: 4,
    payoutA: `${ALICE}:7`,
    payoutB: BOB,
  } as unknown as PublicDealData;
  const seal = dealSeal(data);
  const sealHex = bytesToHex(seal);
  const dom = domain(root, seal);
  const sealed = sealedDeal(seal);

  // Slot bindings of each slot key to its commitment (DESIGN 6.5), FROST-signed, strict check on the aggregate.
  const commitmentOf: Record<SlotName, Uint8Array> = { A: commitmentA, B: chipB.commitment, LA: LC.LA, LB: LC.LB };
  const bindings = Object.fromEntries(
    SLOT_NAMES.map((s) => {
      const msg = bindingMessage(root, commitmentOf[s], S[s].pubHex, s);
      const sig = signTagged(s, 'legx/binding/v1', [root, commitmentOf[s], slotPubs[s], utf8ToBytes(s)], seal);
      return [s, { msg, sig }];
    }),
  ) as Record<SlotName, { msg: Uint8Array; sig: Uint8Array }>;

  // Hybrid evidence envelopes. Lawyer A's console signs A's records, lawyer B's console B's.
  const lawyerSigner = { A: S.LA.hybrid(0), B: S.LB.hybrid(0) };
  const envelopeBytes = async (payloadType: typeof ATTEST | typeof EVENT, body: unknown, signer: SignerPort) =>
    bytes(await signHybrid(payloadType, bytes(body), signer));
  let seq = 0;
  const event = (kind: string, d: Json, signer: SignerPort = lawyerSigner.A, over: Json = {}) =>
    envelopeBytes(
      EVENT,
      {
        _type: 'https://in-toto.io/Statement/v1',
        subject: [{ name: `deal:${DEAL_ID}`, digest: { sha256: rootHex } }],
        predicateType: 'https://legx.dev/event/v1',
        predicate: {
          event_id: '0192f1a0-7b3c-7d4e-8f00-000000000001',
          deal_id: DEAL_ID,
          seq: seq++,
          kind,
          actor: { role: 'lawyerA', key_id: 'LA/console/ed' },
          occurred_at: '2027-06-01T12:00:00Z',
          prev_hash: h32(0),
          payload_commitment: h32(0x44),
          sig_algs: ['ed25519', 'ml-dsa-65'],
          data: d,
          ...over,
        },
      },
      signer,
    );

  // Stage 5 and 9: identity checks. The zero-knowledge `checks` come from the recorded results (checked in their own
  // fixture world); the chip `checks` come from the real passive and active authentication code on fixture passports.
  const sideNonce = (s: Side) => hexToBytes(NONCE[s]);
  const presence = (s: Side, hash = ANCHOR.ledger_hash, nonce = sideNonce(s)) =>
    presenceMsg(seal, s, hexToBytes(hash), nonce);
  const chipFor = { A: chipA, B: chipB };
  const chipChecksFor = async (s: Side, atTime = NOW) => {
    const c = chipFor[s];
    if (!c) throw new Error('no chip for this side');
    const msg = presence(s);
    const r = await chipChecks({
      dg1: c.passport.dg1,
      sod: c.passport.sod,
      dg14: c.passport.dg14,
      dg15: c.passport.dg15,
      trustList: [pki.csca.cert],
      atTime,
      salt: c.salt,
      commitment: commitmentOf[s],
      presenceMsg: msg,
      aaSignature: chipAnswerAA(c.passport.aaKey as never, aaChallenge(msg)),
    });
    if (!r.ok) throw new Error(`chip checks failed: ${r.code}`);
    return r.checks as unknown as Json;
  };
  const onboardResult = checkZkResult(ZK.onboarding.verification, ZK.onboarding.request.originalQuery, FIXTURE_ONBOARD);
  const releaseResult = checkZkResult(ZK.release.verification, ZK.release.request.originalQuery, FIXTURE_RELEASE);
  if (!onboardResult.ok || !releaseResult.ok) throw new Error('the recorded zero-knowledge results must pass');
  // I-E5: the recorded release proof is bound to its fixture's seal, so the deal stores a set bound to its own
  // presenceMsg (the gate reads only its scope and custom_data, I-S-G3), and reuses the recorded verification record.
  const releaseProof = (nonceHex: string = NONCE.A) =>
    proofSet(DEAL_ID, presence('A', ANCHOR.ledger_hash, hexToBytes(nonceHex)));
  const zkReleaseFor = (proof: Uint8Array): Json => ({
    proof_verified: ZK.release.verification.verified,
    identifier_matches: releaseResult.ok,
    bound_value_is_presence_msg: releaseResult.ok,
    document_not_expired: releaseResult.ok,
    face_match_passed: true, // the recorded release has no face match; the deal turns it off (O12), see the status file
    proof_sha256: bytesToHex(sha256(proof)),
    trust: trustRecordOf(ZK.release.verification),
  });
  const zkRelease = zkReleaseFor(releaseProof());
  const zkOnboard: Json = {
    proof_verified: ZK.onboarding.verification.verified,
    bound_value_matches: onboardResult.ok,
    expiry_after_cancel_plus_30d: onboardResult.ok,
    age_over_18: (ZK.onboarding.request.originalQuery.age as { gte?: number }).gte === 18,
    scope: ZK.onboarding.verification.scope,
    domain: ZK.onboarding.verification.domain,
    unique_identifier: ZK_IDENTIFIER,
    proof_sha256: ZK.onboarding.verification.proofSha256,
    trust: trustRecordOf(ZK.onboarding.verification),
  };
  const methodOf = (s: Side) => (s === 'A' ? methodA : 'nfc-chip');
  /** A zkpassport release proof is bound to the attestation's own nonce, so a fresh nonce needs `releaseProof(nonce)`. */
  const releaseChecks = async (s: Side, nonceHex = NONCE[s]) =>
    methodOf(s) === 'zkpassport' ? zkReleaseFor(releaseProof(nonceHex)) : await chipChecksFor(s);
  const onboardChecks = async (s: Side) => (methodOf(s) === 'zkpassport' ? zkOnboard : await chipChecksFor(s));
  const clientSlot = (s: Side) => S[s];

  const passportPayload = async (s: Side, over: Json = {}): Promise<Json> => ({
    deal_id: DEAL_ID,
    contract_root: rootHex,
    deal_seal: sealHex,
    side: s,
    commitment: s === 'A' ? data.commitmentA : data.commitmentB,
    ledger_anchor: ANCHOR,
    method: methodOf(s),
    // a malformed nonce (a test of NONCE_LENGTH) keeps the default proof, the presence rule refuses it first
    checks: await releaseChecks(
      s,
      /^[0-9a-f]{64}$/.test(String(over.lawyer_nonce)) ? String(over.lawyer_nonce) : NONCE[s],
    ),
    presence_sig: bytesToHex(
      signTagged(
        s,
        'legx/passport-presence/v1',
        [seal, utf8ToBytes(s), hexToBytes(ANCHOR.ledger_hash), sideNonce(s)],
        seal,
      ),
    ),
    lawyer_nonce: NONCE[s],
    checked_by_role: `lawyer${s}`,
    sig_algs: ['ed25519', 'ml-dsa-65'],
    ...over,
  });
  const passport = async (s: Side, over: Json = {}, by: Side = s) =>
    envelopeBytes(ATTEST, await passportPayload(s, over), lawyerSigner[by]);
  const onboardPayload = async (s: Side, over: Json = {}): Promise<Json> => ({
    deal_id: DEAL_ID,
    contract_root: rootHex,
    side: s,
    slot_pub: clientSlot(s).pubHex,
    commitment: s === 'A' ? data.commitmentA : data.commitmentB,
    disclosure_box_sha256: h32(0x45),
    distinct_tag: bytesToHex(
      distinctTag(
        DEAL_ID,
        methodOf(s) === 'zkpassport' ? utf8ToBytes(ZK_IDENTIFIER) : sha256((chipFor[s] as typeof chipB).passport.dg1),
      ),
    ),
    method: methodOf(s),
    checks: await onboardChecks(s),
    checked_by_role: `lawyer${s}`,
    sig_algs: ['ed25519', 'ml-dsa-65'],
    ...over,
  });
  const onboarding = async (s: Side, over: Json = {}, by: Side = s) =>
    envelopeBytes(ATTEST, await onboardPayload(s, over), lawyerSigner[by]);

  // Bar records (verifier-signed).
  const verificationPayload = (r: Role, over: Json = {}): Json => ({
    jurisdiction: BAR[r].jurisdiction,
    bar_number_sha256: barNumberSha256(BAR[r].number),
    status: 'active',
    source: { kind: 'manual', url: 'https://example.org/bar', evidence_sha256: h32(0x47) },
    ops_account: OPS[r].address,
    checked_at_ledger: BAR_LEDGER,
    verifier_key_id: 'verifier/ed',
    sig_algs: ['ed25519', 'ml-dsa-65'],
    ...over,
  });
  const bar = async (r: Role, overV: Json = {}, overL: Json = {}, signer: SignerPort = verifierSigner) => {
    const verification = await envelopeBytes(ATTEST, verificationPayload(r, overV), signer);
    const link = await envelopeBytes(
      ATTEST,
      {
        deal_id: DEAL_ID,
        contract_root: rootHex,
        role: r,
        lawyer_pub: S[r].pubHex,
        bar_commitment: bytesToHex(LC[r]),
        ops_account: OPS[r].address,
        verification_sha256: bytesToHex(sha256(verification)),
        sig_algs: ['ed25519', 'ml-dsa-65'],
        ...overL,
      },
      signer,
    );
    return { link, verification };
  };

  // Operations bindings: the ops key and the lawyer slot (FROST, two shares) both sign opsBindMsg.
  const opsTerms = (r: Role) => ({
    contractRoot: root,
    opsAccount: OPS[r].address,
    lawyerPub: S[r].pubHex,
    lawyerCommitment: LC[r],
    role: r,
  });
  const opsData = (r: Role): Json => {
    const t = opsTerms(r);
    const msg = opsBindMsg(t);
    return {
      role: r,
      ops_account: OPS[r].address,
      ops_pub: OPS[r].pub,
      lawyer_pub: S[r].pubHex,
      bar_commitment: bytesToHex(LC[r]),
      sig_ops: up(ed25519.sign(msg, OPS[r].sk)),
      sig_lawyer: up(
        signTagged(
          r,
          'legx/ops-binding/v1',
          [root, utf8ToBytes(OPS[r].address), hexToBytes(S[r].pubHex), LC[r], utf8ToBytes(r)],
          seal,
        ),
      ),
    };
  };

  // Post-quantum bindings: 2 of 3 holder ML-DSA-65 signatures plus the FROST cross-signature (DESIGN 6.13).
  const pqData = (s: SlotName, holders: [number, number] = [0, 1]): Json => {
    const msg = pqBindMsg(seal, hexToBytes(S[s].pubHex), hexToBytes(S[s].pqKeyHash));
    return {
      binding: {
        slot: s,
        deal_seal: sealHex,
        slot_pub: S[s].pubHex,
        pq_key_hash: S[s].pqKeyHash,
        holder_sigs: holders.map((j) => ({
          key_id: S[s].holders[j]?.mlDsa65,
          sig: toBase64(
            mldsaSign('ml-dsa-65', (S[s].pq[j] as { secretKey: Uint8Array }).secretKey, msg, 'legx/pq-binding/v1'),
          ),
        })),
        cross_sig: bytesToHex(
          signTagged(s, 'legx/pq-binding/v1', [seal, hexToBytes(S[s].pubHex), hexToBytes(S[s].pqKeyHash)], seal),
        ),
      },
    };
  };

  // Stage 7: synthetic ledger snapshots (account_info, account_objects, the validated mint, the credentials).
  const nftId = nftokenId(OPS.LA.address);
  const mint = (over: Json = {}) => {
    const tx = OPS.LA.wallet.sign({
      TransactionType: 'NFTokenMint',
      Account: OPS.LA.address,
      NFTokenTaxon: 0,
      Flags: 8,
      URI: sc.uriHex,
      Memos: [{ Memo: { MemoType: MINT_MEMO_TYPE, MemoData: sc.memoHex } }],
      Fee: '12',
      Sequence: 5,
      LastLedgerSequence: LEDGER.index,
      ...over,
    } as xrpl.Transaction);
    return {
      hash: tx.hash,
      validated: true,
      ledger_index: LEDGER.index - 50,
      tx_blob: tx.tx_blob,
      meta: { TransactionResult: 'tesSUCCESS', nftoken_id: nftId },
    };
  };
  const mintTx = mint();
  const ALL_FLAGS =
    lsf.DisableMaster |
    lsf.DepositAuth |
    lsf.DisallowIncomingNFTokenOffer |
    lsf.DisallowIncomingCheck |
    lsf.DisallowIncomingPayChan |
    lsf.DisallowIncomingTrustline;
  const credential = (r: Role, over: Json = {}) => ({
    LedgerEntryType: 'Credential',
    Subject: OPS[r].address,
    Issuer: VERIFIER_ISSUER,
    CredentialType: LEGX_ATTORNEY,
    Flags: lsf.CredentialAccepted,
    Expiration: NOW + 90 * 86_400,
    ...over,
  });
  const walletObjects = [
    {
      LedgerEntryType: 'SignerList',
      SignerQuorum: 4,
      SignerEntries: data.signerAccounts.map((Account) => ({ SignerEntry: { Account, SignerWeight: 1 } })),
    },
    { LedgerEntryType: 'DepositPreauth', Account: WALLET, Authorize: OPS.LB.address },
    { LedgerEntryType: 'Credential', Issuer: WALLET, Subject: ALICE, Flags: lsf.CredentialAccepted },
    { LedgerEntryType: 'Credential', Issuer: WALLET, Subject: BOB, Flags: lsf.CredentialAccepted },
    {
      LedgerEntryType: 'Escrow',
      Account: ALICE,
      Destination: WALLET,
      Sequence: 7,
      Amount: '5000000000',
      Condition: CONDITION,
      CancelAfter: CANCEL_AFTER,
    },
  ];

  const ship = shipBuilders(DEAL_ID, seal, LEDGER.index);
  const keys: KeyRow[] = [...SLOT_NAMES.flatMap((s) => S[s].rows), ...VERIFIER_ROWS];
  const input: ReleaseInput = {
    profile: 'demo',
    ledger: {
      ...LEDGER,
      account: { Account: WALLET, Flags: ALL_FLAGS, Domain: up(dom), OwnerCount: 2 },
      objects: walletObjects,
      mintTx,
      credentials: [credential('LA'), credential('LB')],
      opsAccounts: {
        LA: { validated: true, account_data: { Account: OPS.LA.address, Flags: 0 } },
        LB: { validated: true, account_data: { Account: OPS.LB.address, Flags: 0 } },
      },
      history: HISTORY,
    },
    records: {
      passport: { A: await passport('A'), B: await passport('B') },
      zkProof: {
        A: methodA === 'zkpassport' ? releaseProof() : utf8ToBytes('unused'),
        B: utf8ToBytes('unused'),
      },
      onboarding: { A: await onboarding('A'), B: await onboarding('B') },
      bar: { LA: await bar('LA'), LB: await bar('LB') },
      opsBound: {
        LA: await event('ops.bound', opsData('LA')),
        LB: await event('ops.bound', opsData('LB'), lawyerSigner.B),
      },
      pqBound: Object.fromEntries(
        await Promise.all(
          SLOT_NAMES.map(async (s) => [
            s,
            await event('pq.bound', pqData(s), s.endsWith('B') ? lawyerSigner.B : lawyerSigner.A),
          ]),
        ),
      ),
      dkgCompleted: Object.fromEntries(
        await Promise.all(SLOT_NAMES.map(async (s) => [s, await event('frost.dkg.completed', S[s].dkgData)])),
      ),
      keys,
      slotHolders: { A: S.A.holders, LA: S.LA.holders, B: S.B.holders, LB: S.LB.holders },
      // OD-37: Bob's slot B signs the shipment and Alice's slot A the receipt, each through its allow-list.
      shipments: [
        await event(
          'shipment.signed',
          ship.shipmentData((_m, tag, parts) => signTagged('B', tag, parts, seal)),
          S.B.hybrid(0),
        ),
      ],
      receipts: [
        await event(
          'receipt.signed',
          ship.receiptData((_m, tag, parts) => signTagged('A', tag, parts, seal)),
          S.A.hybrid(0),
        ),
      ],
    },
    deal: {
      id: DEAL_ID,
      data,
      mintTxHash: mintTx.hash,
      nftokenId: nftId,
      credentialSubjects: [ALICE, BOB],
      escrow: { owner: ALICE, sequence: 7, amountDrops: '5000000000', conditionHex: CONDITION },
    },
    submitter: OPS.LB.address,
    config: { verifierIssuer: VERIFIER_ISSUER, verifierKeyIds: VERIFIER_KEY_IDS },
  };

  // Stage 10: the gate, the gate record (slot LB signs through the allow-list) and the memo.
  const EVENT_FIELDS = {
    event_id: '0192f1a0-7b3c-7d4e-8f00-0000000000ff',
    seq: 40,
    occurred_at: '2027-06-01T13:00:00Z',
    prev_hash: h32(0x21),
    payload_commitment: h32(0x22),
  };
  const findings = checkRelease(input);
  // A deal that is built to be blocked (a break case) has no gate record; `blocked` says so.
  const blocked = findings.some((f) => !f.ok);
  const gate = blocked
    ? { envelopeBytes: new Uint8Array(), leafHash: new Uint8Array(32) }
    : await buildGatePassedRecord(input, EVENT_FIELDS, lawyerSigner.B, async (envelope, msg) =>
        S.LB.sign(msg, (m) => messageAllowed({ kind: 'gate-record', envelope }, m, sealed, 'LB')),
      );
  const memo = gateMemo(gate.leafHash);

  // The evidence log: every stored record and the gate record are leaves; a hybrid checkpoint covers them.
  const recordBytes = (): Uint8Array[] => {
    const r = input.records;
    return [
      ...(['A', 'B'] as const).flatMap((s) => [r.passport[s], r.onboarding[s]]),
      ...(['LA', 'LB'] as const).flatMap((s) => [r.bar[s]?.verification, r.bar[s]?.link, r.opsBound[s]]),
      ...SLOT_NAMES.flatMap((s) => [r.pqBound[s], r.dkgCompleted[s]]),
      ...(r.shipments ?? []),
      ...(r.receipts ?? []),
      gate.envelopeBytes,
    ] as Uint8Array[];
  };
  const leaves = recordBytes();
  const checkpointBody = { origin: LOG.origin, treeSize: leaves.length, rootHash: mth(leaves) };
  const checkpoint = signCheckpoint(
    checkpointBody,
    { name: LOG.origin, seed: LOG.edSeed },
    { name: LOG.origin, secretKey: LOG.pq.secretKey },
    NOW,
  );

  // Every FROST aggregate in the deal verifies strictly under its slot key.
  const strictOk = [
    ...SLOT_NAMES.map((s) => verifyEd25519Strict(bindings[s].sig, bindings[s].msg, hexToBytes(S[s].pubHex))),
    verifyEd25519Strict(contractSigs.sigLA, contractSigMsg(root, WALLET, 'LA'), hexToBytes(S.LA.pubHex)),
    verifyEd25519Strict(contractSigs.sigLB, contractSigMsg(root, WALLET, 'LB'), hexToBytes(S.LB.pubHex)),
  ];

  return {
    S,
    releaseProof,
    clauses,
    clauseSalts,
    root,
    rootHex,
    sc,
    contractSigs,
    terms,
    data,
    seal,
    sealHex,
    dom,
    sealed,
    commitmentOf,
    lawyerSalt,
    LC,
    chipA,
    chipB,
    pki,
    bindings,
    strictOk,
    input,
    findings,
    gate,
    blocked,
    memo,
    EVENT_FIELDS,
    leaves,
    checkpoint,
    checkpointBody,
    lawyerSigner,
    // builders for re-signing a changed record in a break case
    passport,
    onboarding,
    bar,
    event,
    opsData,
    pqData,
    mint,
    credential,
    chipChecksFor,
    presence,
    signTagged,
    sealedDeal,
    ship,
    zkRelease,
    zkOnboard,
    walletObjects,
    envelopeBytes,
    methodA,
    pae,
  };
}
export type PaperDeal = Awaited<ReturnType<typeof buildPaperDeal>>;
