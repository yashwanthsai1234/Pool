// E2E-P1: the "paper deal" end-to-end suite and gate G1 (IMPLEMENTATION section 5, "Phase 1 end-to-end").
// A whole deal runs with pure functions only: contract, FROST DKG and signing, NFT URI and memo, zero-knowledge and chip
// identity, the 29-field seal, bindings, synthetic ledger snapshots, the lock checker, the release gate, the gate record
// and a hybrid checkpoint. Then one input at a time is broken (E2E-P1-02), an arbitrator recomputes everything from
// public data (-03), the clock and the network are stubbed to throw (-04), and a refresh, a recovery and a repair run
// in the middle of the deal (-05, -06, -07).
// Source: IMPLEMENTATION.md "Phase 1 end-to-end suite", DESIGN.md 6.4, 6.6, 6.9, 6.10, 6.12 to 6.17
import { readdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { GATE_CODES } from '@legx/contracts/records';
import { chipAnswerAA, makePassport } from '@legx/fixtures';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import * as xrpl from 'xrpl';
import { checkFreshNonce, checkTrustRecord, distinctTag, presenceMsg } from '../src/attest.ts';
import { openBarCommitment } from '../src/bar.ts';
import { clauseBytes, contractRoot as contractRootOf, proveClause, verifyClause } from '../src/contract.ts';
import {
  bindingMessage,
  dealSeal,
  domain,
  inclusionPath,
  makeCondition,
  mth,
  passportCommitment,
  SEAL_FIELDS,
  tupleHash,
  verifyInclusion,
} from '../src/dealcore.ts';
import {
  aggregateChecked,
  frostMsgBytes,
  idScalar,
  SigningSession,
  type SlotName,
  slotPolicy,
  slotPubkey,
  u32,
  verifyEd25519Strict,
} from '../src/frost.ts';
import { dkgCompletedRecord, judgeComplaint, testSignCheck, testSignMessage } from '../src/frostDkg.ts';
import {
  deletionStatement,
  type RefreshContext,
  refreshedEvent,
  refreshReceiveCommits,
  refreshReceiveShares,
  refreshStart,
} from '../src/frostRefresh.ts';
import { checkDelta, repairDelta, repairFinish, repairSigma } from '../src/frostRepair.ts';
import {
  cosign,
  messageAllowed,
  PROOF_FRESH_MS,
  RECOVERY_DELAY_MS,
  type RecoveryError,
  recoveryAuthorize,
  recoverySigned,
  recoveryStart,
  type SignRequest,
} from '../src/frostRules.ts';
import { EnrollmentRegistry, enrollmentKeyHash } from '../src/frostSetup.ts';
import { verifyHybrid } from '../src/hybridEnvelope.ts';
import { lsf } from '../src/lockcheck.ts';
import { opsBindMsg } from '../src/opsBinding.ts';
import { aaChallenge } from '../src/passport/activeAuth.ts';
import { chipChecks, passportRecord } from '../src/passport/passiveAuth.ts';
import { fromBase64Strict, mldsaSign, pqBindMsg, pqKeyHash, toBase64, verifyPqBinding } from '../src/pq.ts';
import { verifyCheckpoint } from '../src/pqCheckpoint.ts';
import {
  buildGatePassedRecord,
  checkRelease,
  gateMemo,
  type ReleaseInput,
  verifyGatePassedRecord,
} from '../src/releaseGate.ts';
import {
  buildSignedContractSeal,
  contractSigMsg,
  encodeMintMemo,
  MINT_MEMO_TYPE,
  nftUri,
  signContract,
  verifySignedContract,
} from '../src/signedContract.ts';
import { checkZkResult, zkIdentityCommitment } from '../src/zkIdentity.ts';
import { APPROVER, assertion } from './e2e/approval.ts';
import { fromBundle, toBundle } from './e2e/bundle.ts';
import { pyRef } from './e2e/pyref.ts';
import {
  ANCHOR,
  buildPaperDeal,
  DEAL_ID,
  FIXTURE_ONBOARD,
  FIXTURE_RELEASE,
  LEDGER,
  LOG,
  NONCE,
  NOW,
  type PaperDeal,
  SLOT_NAMES,
  ZK,
  ZK_IDENTIFIER,
  ZK_SALT,
  zkProofBytes,
} from './e2e/world.ts';
import { enc, enroll, noPinCheck, runDkg, slotSetup, xwing } from './helpers/frost.ts';
import { ALICE, h32, OPS, WALLET } from './helpers/gate.ts';
import { pyVector } from './helpers/pyref.ts';

vi.setConfig({ testTimeout: 300_000, hookTimeout: 300_000 });

let d: PaperDeal;
beforeAll(async () => {
  d = await buildPaperDeal();
});

// biome-ignore lint/suspicious/noExplicitAny: a copy of the gate input that a break case rewrites freely
type Mutable = any;
const up = (b: Uint8Array) => bytesToHex(b).toUpperCase();
const hex = (b: Uint8Array) => bytesToHex(b);
const failing = (i: ReleaseInput) => checkRelease(i).filter((f) => !f.ok);
const codeOf = async (f: () => unknown): Promise<string> => {
  try {
    await f();
  } catch (e) {
    return (e as { code?: string }).code ?? (e as Error).message;
  }
  return 'NO_THROW';
};

// =====================================================================================================================
// E2E-P1-01 the whole paper deal
// =====================================================================================================================

describe('E2E-P1-01 a whole deal, pure functions only', () => {
  it('stage 1 and 2: the contract names the wallet, and both lawyer slots sign it through FROST', () => {
    expect(new TextDecoder().decode(d.clauses[0])).toContain(WALLET);
    d.clauses.forEach((_, i) => {
      expect(verifyClause(proveClause(i, d.clauses, d.clauseSalts), d.root)).toBe(true);
    });
    // Every FROST aggregate (contract signatures, four bindings) verifies strictly under its slot key.
    expect(d.strictOk.every(Boolean)).toBe(true);
    expect(
      verifyEd25519Strict(d.contractSigs.sigLA, contractSigMsg(d.root, WALLET, 'LA'), hexToBytes(d.S.LA.pubHex)),
    ).toBe(true);
    // The same signature does not verify as lawyer B's.
    expect(
      verifyEd25519Strict(d.contractSigs.sigLA, contractSigMsg(d.root, WALLET, 'LB'), hexToBytes(d.S.LB.pubHex)),
    ).toBe(false);
  });

  it('stage 3: the NFT URI and the memo give the signed contract seal, and the sealed deal data carries it', () => {
    expect(verifySignedContract(d.terms, d.sc.memoHex, d.sc.uriHex)).toEqual({ ok: true });
    expect(d.data.signedContractSeal).toBe(hex(d.sc.seal));
    expect(d.sc.uriHex).toBe(nftUri(d.sc.seal));
    const mint = xrpl.decode(d.input.ledger.mintTx?.tx_blob ?? '') as {
      URI: string;
      Memos: { Memo: { MemoType: string; MemoData: string } }[];
    };
    expect(mint.URI).toBe(d.sc.uriHex);
    expect(mint.Memos[0]?.Memo).toEqual({ MemoType: MINT_MEMO_TYPE, MemoData: d.sc.memoHex });
  });

  it('stage 4: four FROST DKGs, with transcripts, three-pair test-signing and the sealed slotPolicy', () => {
    for (const s of SLOT_NAMES) {
      const slot = d.S[s];
      expect(slot.completed.kind).toBe('frost.dkg.completed');
      expect(slot.completed.testSignatures.map((t) => t.pair)).toEqual([
        [1, 2],
        [1, 3],
        [2, 3],
      ]);
      for (const t of slot.completed.testSignatures) {
        expect(verifyEd25519Strict(t.sig, testSignMessage(slot.k.ctx, slot.pub, t.pair), slotPubkey(slot.pub))).toBe(
          true,
        );
      }
      expect(slot.completed.transcriptSigs).toHaveLength(3);
      expect(hex(slot.completed.slotPolicy)).toBe(hex(slotPolicy(s, slot.roles)));
      expect(up(slot.completed.slotPub)).toBe(slot.pubHex);
    }
    expect(d.data.slotPolicyA).toBe(d.S.A.policy);
    expect(d.S.A.roles).toEqual(['phone', 'second-authenticator', 'recovery-agent']);
    expect(d.S.LA.roles).toEqual(['console', 'firm-hsm', 'partner']);
  });

  it('stage 5: client A passes the zero-knowledge path from the recorded results, client B the chip path', async () => {
    // The recorded results are checked in their own fixture world (their proofs are bound to the fixture seal).
    expect(checkZkResult(ZK.onboarding.verification, ZK.onboarding.request.originalQuery, FIXTURE_ONBOARD)).toEqual({
      ok: true,
      identifier: ZK_IDENTIFIER,
    });
    expect(checkZkResult(ZK.release.verification, ZK.release.request.originalQuery, FIXTURE_RELEASE)).toEqual({
      ok: true,
      identifier: ZK_IDENTIFIER,
    });
    // C_A comes from the identifier and a salt; the live deal seals it.
    expect(d.data.commitmentA).toBe(hex(zkIdentityCommitment(ZK_SALT, ZK_IDENTIFIER)));
    expect(d.data.idMethodA).toBe('zkpassport');
    // The lawyer nonce is inside the presence message A's slot signed (and the chip challenge is its first 8 bytes).
    const payload = JSON.parse(
      new TextDecoder().decode(
        fromBase64Strict(JSON.parse(new TextDecoder().decode(d.input.records.passport.A)).payload) as Uint8Array,
      ),
    );
    expect(payload.lawyer_nonce).toBe(NONCE.A);
    expect(
      verifyEd25519Strict(
        hexToBytes(payload.presence_sig),
        presenceMsg(d.seal, 'A', hexToBytes(ANCHOR.ledger_hash), hexToBytes(NONCE.A)),
        hexToBytes(d.S.A.pubHex),
      ),
    ).toBe(true);
    // Client B: the chip fixture passport, with the active-authentication answer over presenceMsg.
    expect(d.data.idMethodB).toBe('nfc-chip');
    const checks = await d.chipChecksFor('B');
    expect(checks).toEqual({
      sod_signature_valid: true,
      ds_cert_chains_to_csca: true,
      dg1_hash_in_sod: true,
      document_not_expired: true,
      commitment_opens: true,
      chip_authentication: 'AA',
      chip_auth_available: true,
    });
  });

  it('stage 6: the 29-field seal, the Domain, the bindings, the bar commitments', () => {
    expect(SEAL_FIELDS).toHaveLength(29);
    expect(Object.keys(d.data)).toHaveLength(29);
    expect(d.seal).toHaveLength(32);
    expect(d.dom).toHaveLength(65);
    expect(d.dom[0]).toBe(1);
    expect(hex(d.dom.slice(1, 33))).toBe(d.rootHex);
    expect(hex(d.dom.slice(33))).toBe(d.sealHex);
    expect(d.input.ledger.account.Domain).toBe(up(d.dom));
    for (const s of SLOT_NAMES)
      expect(hex(d.bindings[s].msg)).toBe(hex(bindingMessage(d.root, d.commitmentOf[s], d.S[s].pubHex, s)));
    expect(hex(d.LC.LA)).toBe(hex(openBarCommitment(d.lawyerSalt.LA, 'US-CA', 'A-123456')));
    // The seal moves when any one of the 29 fields moves.
    for (const f of SEAL_FIELDS) {
      const key = f[0];
      const v = (d.data as unknown as Record<string, unknown>)[key];
      if (typeof v !== 'string' || !/^[0-9a-fA-F]{64}$/.test(v)) continue;
      const flipped = { ...d.data, [key]: (v.startsWith('0') ? '1' : '0') + v.slice(1) };
      expect(hex(dealSeal(flipped as typeof d.data))).not.toBe(d.sealHex);
    }
  });

  it('stage 7 to 10: lock checker, bar, credentials, operations and post-quantum bindings, the gate, the record and the memo', async () => {
    // all 15 codes, in the DESIGN 6.17 order, every one passing
    expect(d.findings.map((f) => f.code)).toEqual([...GATE_CODES]);
    expect(d.findings.filter((f) => !f.ok)).toEqual([]);
    for (const c of [
      'LOCK_OK',
      'ONBOARDING_OK',
      'IDS_DISTINCT',
      'IDENTITY_POLICY_OK',
      'PQ_BINDINGS_OK',
      'SLOT_SETUP_OK',
    ] as const) {
      expect(d.findings.find((f) => f.code === c)?.ok).toBe(true);
    }
    // the gate record: both signatures, the memo
    const ctx = { deal: d.input.deal, keys: d.input.records.keys, lawyerB: d.input.records.slotHolders.LB, at: NOW };
    expect(verifyGatePassedRecord(d.gate.envelopeBytes, ctx)).toEqual({ ok: true });
    expect(d.memo.MemoType).toBe(up(utf8ToBytes('legx/release-gate/v1')));
    expect(d.memo.MemoData).toBe(up(sha256(d.gate.envelopeBytes)));
    expect(hex(d.gate.leafHash)).toBe(hex(sha256(d.gate.envelopeBytes)));
  });

  it('every evidence envelope is hybrid-signed; the checkpoint carries both lines and covers the gate record', () => {
    const reg = (id: string) => d.input.records.keys.find((k) => k.keyId === id);
    const envs = d.leaves.slice(0, -1).concat(d.gate.envelopeBytes);
    expect(envs.length).toBeGreaterThan(15);
    for (const b of envs) {
      const v = verifyHybrid(JSON.parse(new TextDecoder().decode(b)), reg, NOW);
      expect(v.ok).toBe(true);
    }
    const cp = verifyCheckpoint(d.checkpoint, LOG.origin, {
      ed: { name: LOG.origin, publicKey: ed25519.getPublicKey(LOG.edSeed) },
      pq: { name: LOG.origin, publicKey: LOG.pq.publicKey },
    });
    expect(cp.ok).toBe(true);
    if (cp.ok) {
      expect(cp.treeSize).toBe(d.leaves.length);
      expect(cp.timestamp).toBe(NOW + 946_684_800); // the 0x06 timestamp is the ledger close time, not the clock
      expect(hex(cp.rootHash)).toBe(hex(d.checkpointBody.rootHash));
    }
    const at = d.leaves.length - 1;
    const path = inclusionPath(at, d.leaves);
    expect(verifyInclusion(d.leaves[at] as Uint8Array, at, d.leaves.length, path, d.checkpointBody.rootHash)).toBe(
      true,
    );
  });
});

// =====================================================================================================================
// every byte that has a Python vector (tools/py-ref/vectors) and the Python reference on this deal's own inputs
// =====================================================================================================================

describe('E2E-P1 Python reference cross-checks', () => {
  type V = { fn: string; inputs: Record<string, unknown>; output: unknown };
  const read = (file: string): V[] => JSON.parse(new TextDecoder().decode(new Uint8Array(require_fs(file)))) as V[];
  const h = hexToBytes;
  const s = (x: unknown) => String(x);
  const sealFieldsOf = (i: Record<string, unknown>) =>
    ({
      ...i,
      commitmentA: i.C_A,
      commitmentB: i.C_B,
      lawyerCommitmentA: i.LC_A,
      lawyerCommitmentB: i.LC_B,
      C_A: undefined,
      C_B: undefined,
      LC_A: undefined,
      LC_B: undefined,
    }) as never;
  const handlers: Record<string, (i: Record<string, unknown>) => string> = {
    'tuple_hash/tupleHash': (i) => hex(tupleHash(s(i.tag), (i.parts as string[]).map(h))),
    'contract_root/contractRoot': (i) => {
      const clauses = (i.clauses_hex as string[]).map(h);
      return hex(contractRootOf(clauses, (i.salts as string[]).map(h)));
    },
    'identity/zk': (i) => hex(zkIdentityCommitment(h(s(i.salt)), s(i.N))),
    'identity/chip': (i) => hex(passportCommitment(passportRecord(h(s(i.dg1)), h(s(i.sod))), h(s(i.salt)))),
    'identity/bar': (i) => hex(openBarCommitment(h(s(i.salt)), s(i.jurisdiction), s(i.bar))),
    'identity/distinctTag': (i) => hex(distinctTag(s(i.dealId), h(s(i.x)))),
    'slot_policy/slotPolicy': (i) => hex(slotPolicy(s(i.slot) as SlotName, s(i.roles).split(','))),
    'bind_msg/bindMsg': (i) => hex(bindingMessage(h(s(i.root)), h(s(i.C)), s(i.slotPub), s(i.side) as 'A')),
    'deal_seal/dealSeal': (i) => hex(dealSeal(sealFieldsOf(i))),
    'deal_seal/domain': (i) => up(domain(h(s(i.root)), h(s(i.seal)))),
    'condition/condition': (i) => makeCondition(h(s(i.preimage))).condition.toLowerCase(),
    'condition/fulfillment': (i) => makeCondition(h(s(i.preimage))).fulfillment.toLowerCase(),
    'signed_contract/contractSigMsg': (i) => hex(contractSigMsg(h(s(i.root)), s(i.wallet), s(i.role) as 'LA')),
    'signed_contract/signedContractSeal': (i) =>
      hex(
        buildSignedContractSeal(
          { contractRoot: h(s(i.root)), walletAddress: s(i.wallet), lawyerPubA: s(i.pubA), lawyerPubB: s(i.pubB) },
          { sigLA: h(s(i.sigLA)), sigLB: h(s(i.sigLB)) },
        ).seal,
      ),
    'signed_contract/nftUri': (i) => nftUri(h(s(i.seal))),
    'pq/pqKeyHash': (i) => hex(pqKeyHash((i.pubs as string[]).map(h) as [Uint8Array, Uint8Array, Uint8Array])),
    'pq/pqBindMsg': (i) => hex(pqBindMsg(h(s(i.dealSeal)), h(s(i.slotPub)), h(s(i.pqKeyHash)))),
    'ops_bind/opsBindMsg': (i) =>
      hex(
        opsBindMsg({
          contractRoot: h(s(i.root)),
          opsAccount: s(i.ops),
          lawyerPub: s(i.lawyerPub),
          lawyerCommitment: h(s(i.LC)),
          role: s(i.role) as 'LA',
        }),
      ),
    'presence/presenceMsg': (i) =>
      hex(presenceMsg(h(s(i.dealSeal)), s(i.side) as 'A', h(s(i.ledgerHash)), h(s(i.nonce)))),
  };
  const files = [
    'bind_msg',
    'condition',
    'contract_root',
    'deal_seal',
    'gate_memo',
    'identity',
    'ops_bind',
    'pq',
    'presence',
    'signed_contract',
    'slot_policy',
    'tuple_hash',
  ];

  it.each(files)('every vector in %s.json equals our bytes', (file) => {
    const vectors = read(file);
    expect(vectors.length).toBeGreaterThan(0);
    for (const v of vectors) {
      if (file === 'gate_memo') {
        expect(gateMemo(sha256(h(s(v.inputs.envelope))))).toEqual(v.output);
      } else if (file === 'signed_contract' && v.fn === 'mintMemo') {
        const i = v.inputs;
        expect({
          MemoType: MINT_MEMO_TYPE,
          MemoData: encodeMintMemo({
            lawyerPubA: s(i.pubA),
            lawyerPubB: s(i.pubB),
            sigLA: h(s(i.sigLA)),
            sigLB: h(s(i.sigLB)),
          }),
        }).toEqual(v.output);
      } else if (v.fn === 'clauseBytes') {
        expect(hex(clauseBytes(s(v.inputs.text))), 'contract_root/clauseBytes').toBe(v.output);
      } else {
        const run = handlers[`${file}/${v.fn}`];
        expect(run, `a handler for ${file}/${v.fn}`).toBeDefined();
        expect((run as (i: Record<string, unknown>) => string)(v.inputs), `${file}/${v.fn}`).toBe(v.output);
      }
    }
  });

  it('clauseBytes (I-E1): NFC, CRLF to LF, one leading BOM removed, a lone CR or lone surrogate refused', () => {
    expect(new TextDecoder('utf-8', { ignoreBOM: true }).decode(clauseBytes('\uFEFF\uFEFFa\r\nb'))).toBe('\uFEFFa\nb');
    expect(clauseBytes('Cle\u0301')).toEqual(clauseBytes('Cl\u00e9'));
    expect(() => clauseBytes('a\rb')).toThrow('LONE_CR');
    expect(() => clauseBytes('a\r')).toThrow('LONE_CR');
    expect(() => clauseBytes('a\uD800b')).toThrow('LONE_SURROGATE');
    expect(hex(clauseBytes('a\uD83D\uDE00'))).toBe('61f09f9880');
  });

  it("the Python reference, run on this deal's own inputs, gives every recipe byte for byte", () => {
    const ps = d.data as unknown as Record<string, string | string[] | number>;
    const seal: Record<string, unknown> = {
      ...ps,
      C_A: ps.commitmentA,
      C_B: ps.commitmentB,
      LC_A: ps.lawyerCommitmentA,
      LC_B: ps.lawyerCommitmentB,
    };
    for (const k of ['commitmentA', 'commitmentB', 'lawyerCommitmentA', 'lawyerCommitmentB']) delete seal[k];
    const out = pyRef<Record<string, any>>({
      seal,
      salts: d.clauseSalts.map(hex),
      clauses: d.clauses.map((c) => new TextDecoder().decode(c)),
      wallet: WALLET,
      pubLA: d.S.LA.pubHex,
      pubLB: d.S.LB.pubHex,
      sigLA: hex(d.contractSigs.sigLA),
      sigLB: hex(d.contractSigs.sigLB),
      roles: Object.fromEntries(SLOT_NAMES.map((n) => [n, d.S[n].roles.join(',')])),
      slotPubs: Object.fromEntries(SLOT_NAMES.map((n) => [n, d.S[n].pubHex])),
      commitments: Object.fromEntries(SLOT_NAMES.map((n) => [n, hex(d.commitmentOf[n])])),
      pqPubs: Object.fromEntries(SLOT_NAMES.map((n) => [n, d.S[n].pq.map((p) => hex(p.publicKey))])),
      ops: { LA: { ops: OPS.LA.address, lc: hex(d.LC.LA) }, LB: { ops: OPS.LB.address, lc: hex(d.LC.LB) } },
      presence: {
        A: { ledgerHash: ANCHOR.ledger_hash, nonce: NONCE.A },
        B: { ledgerHash: ANCHOR.ledger_hash, nonce: NONCE.B },
      },
      zk: { salt: hex(ZK_SALT), N: ZK_IDENTIFIER },
      chip: { salt: hex(d.chipB.salt), dg1: hex(d.chipB.passport.dg1), sod: hex(d.chipB.passport.sod) },
      bar: {
        LA: { salt: hex(d.lawyerSalt.LA), jurisdiction: 'US-CA', bar: 'A-123456' },
        LB: { salt: hex(d.lawyerSalt.LB), jurisdiction: 'US-NY', bar: 'B-654321' },
      },
      gateEnvelope: hex(d.gate.envelopeBytes),
    });
    expect(out.contractRoot).toBe(d.rootHex);
    expect(out.dealSeal).toBe(d.sealHex);
    expect(out.domain).toBe(up(d.dom));
    expect(out.contractSigMsg).toEqual({
      LA: hex(contractSigMsg(d.root, WALLET, 'LA')),
      LB: hex(contractSigMsg(d.root, WALLET, 'LB')),
    });
    expect(out.signedContractSeal).toBe(hex(d.sc.seal));
    expect(out.nftUri).toBe(d.sc.uriHex);
    expect(out.mintMemo).toEqual({ MemoType: MINT_MEMO_TYPE, MemoData: d.sc.memoHex });
    for (const n of SLOT_NAMES) {
      expect(out.slotPolicy[n]).toBe(d.S[n].policy);
      expect(out.bindMsg[n]).toBe(hex(d.bindings[n].msg));
      expect(out.pqKeyHash[n]).toBe(d.S[n].pqKeyHash);
      expect(out.pqBindMsg[n]).toBe(hex(pqBindMsg(d.seal, hexToBytes(d.S[n].pubHex), hexToBytes(d.S[n].pqKeyHash))));
    }
    for (const r of ['LA', 'LB'] as const) {
      expect(out.opsBindMsg[r]).toBe(
        hex(
          opsBindMsg({
            contractRoot: d.root,
            opsAccount: OPS[r].address,
            lawyerPub: d.S[r].pubHex,
            lawyerCommitment: d.LC[r],
            role: r,
          }),
        ),
      );
    }
    for (const sd of ['A', 'B'] as const)
      expect(out.presenceMsg[sd]).toBe(hex(d.presence(sd, ANCHOR.ledger_hash, hexToBytes(NONCE[sd]))));
    expect(out.zkCommitment).toBe(d.data.commitmentA);
    expect(out.chipCommitment).toBe(d.data.commitmentB);
    expect(out.barCommitment).toEqual({ LA: hex(d.LC.LA), LB: hex(d.LC.LB) });
    expect(out.gateMemo).toEqual(d.memo);
  });
});

// =====================================================================================================================
// E2E-P1-02 break one input at each stage, one at a time: the first failing check names it
// =====================================================================================================================

// biome-ignore lint/suspicious/noExplicitAny: break cases rewrite arbitrary parts of a copied gate input
type Mut = (i: any, w: PaperDeal) => void | Promise<void>;
type Case = {
  id: string;
  stage: string;
  what: string;
  run: () => Promise<string> | string;
  first: string;
  codes?: string[];
};
const cases: Case[] = [];
/** A gate case: break one input of a copy of the valid gate input; the first blocking finding must name it. */
const gate = (id: string, what: string, mut: Mut, first: string, codes?: string[]) => {
  const c: Case = {
    id,
    stage: 'gate',
    what,
    first,
    run: async () => {
      const i = structuredClone(d.input);
      await mut(i, d);
      const f = failing(i);
      lastCodes = f.map((x) => x.code);
      return f[0] ? `${f[0].code}:${f[0].detail}` : 'PASSES';
    },
  };
  if (codes) c.codes = codes;
  cases.push(c);
};
let lastCodes: string[] = [];
/** A stage case: a stage's own check, with one input broken. */
const stage = (id: string, st: string, what: string, run: Case['run'], first: string) =>
  cases.push({ id, stage: st, what, run, first });

const slotKeyRow = (i: ReleaseInput, id: string, publicKey: Uint8Array) =>
  ({
    ...i,
    records: { ...i.records, keys: i.records.keys.map((k) => (k.keyId === id ? { ...k, publicKey } : k)) },
  }) as ReleaseInput;

// ---- stage: contract, NFT ----
stage(
  'C-01',
  'contract',
  'a lawyer slot signs a contract that names another wallet',
  () => codeOf(() => d.signTagged('LA', 'legx/contract-sign/v1', [d.root, utf8ToBytes(ALICE), utf8ToBytes('LA')])),
  'MESSAGE_REFUSED',
);
stage(
  'C-02',
  'contract',
  'lawyer B signs as role LA',
  () => codeOf(() => d.signTagged('LB', 'legx/contract-sign/v1', [d.root, utf8ToBytes(WALLET), utf8ToBytes('LA')])),
  'MESSAGE_REFUSED',
);
stage(
  'C-03',
  'contract',
  'the memo carries a signature over another wallet',
  () => {
    const bad = d.S.LA.sign(contractSigMsg(d.root, ALICE, 'LA'));
    const sc = buildSignedContractSeal(d.terms, { sigLA: bad, sigLB: d.contractSigs.sigLB });
    return verifySignedContract(d.terms, sc.memoHex, sc.uriHex).ok
      ? 'ok'
      : (verifySignedContract(d.terms, sc.memoHex, sc.uriHex) as { code: string }).code;
  },
  'SIG_LA_INVALID',
);
stage(
  'C-04',
  'contract',
  'the memo lists lawyer keys in the wrong order',
  () => {
    const memo = encodeMintMemo({
      lawyerPubA: d.S.LB.pubHex,
      lawyerPubB: d.S.LA.pubHex,
      sigLA: d.contractSigs.sigLB,
      sigLB: d.contractSigs.sigLA,
    });
    const r = verifySignedContract(d.terms, memo, d.sc.uriHex);
    return r.ok ? 'ok' : r.code;
  },
  'KEYS_NOT_SEALED',
);
stage(
  'C-05',
  'contract',
  'the NFT URI holds another seal',
  () => {
    const r = verifySignedContract(d.terms, d.sc.memoHex, nftUri(sha256(utf8ToBytes('other'))));
    return r.ok ? 'ok' : r.code;
  },
  'SEAL_MISMATCH',
);
gate(
  'C-06',
  'the mint is by lawyer B instead of lawyer A',
  (i, w) => {
    const tx = OPS.LB.wallet.sign({ TransactionType: 'AccountSet', Account: OPS.LB.address, Fee: '12', Sequence: 1 });
    i.ledger.mintTx = { ...w.input.ledger.mintTx, hash: tx.hash, tx_blob: tx.tx_blob };
    i.deal.mintTxHash = tx.hash;
  },
  'CONTRACT_SEAL_OK:NOT_OPS_A_MINT',
);
gate(
  'C-07',
  'the mint is not validated',
  (i) => {
    i.ledger.mintTx.validated = false;
  },
  'CONTRACT_SEAL_OK:MINT_NOT_VALIDATED',
);
gate(
  'C-08',
  'the minted memo carries a signature over another wallet',
  (i, w) => {
    const bad = w.S.LA.sign(contractSigMsg(w.root, ALICE, 'LA'));
    const sc = buildSignedContractSeal(w.terms, { sigLA: bad, sigLB: w.contractSigs.sigLB });
    const m = w.mint({ Memos: [{ Memo: { MemoType: MINT_MEMO_TYPE, MemoData: sc.memoHex } }] });
    i.ledger.mintTx = m;
    i.deal.mintTxHash = m.hash;
  },
  'CONTRACT_SEAL_OK:SIG_LA_INVALID',
  ['CONTRACT_SEAL_OK'],
);

const scCode = (terms: typeof d.terms, memo: string, uri: string) => {
  const r = verifySignedContract(terms, memo, uri);
  return r.ok ? 'ok' : r.code;
};
stage(
  'C-09',
  'contract',
  'the sealed lawyer key in the terms is not hex',
  () => scCode({ ...d.terms, lawyerPubA: 'not hex' }, d.sc.memoHex, d.sc.uriHex),
  'KEYS_NOT_SEALED',
);
stage(
  'C-10',
  'contract',
  'the URI is hex of the wrong text',
  () => scCode(d.terms, d.sc.memoHex, up(utf8ToBytes('legx:sc:v1:xyz'))),
  'URI_MALFORMED',
);
stage(
  'C-11',
  'contract',
  'the URI is lowercase hex',
  () => scCode(d.terms, d.sc.memoHex, d.sc.uriHex.toLowerCase()),
  'URI_MALFORMED',
);
stage(
  'C-12',
  'contract',
  'the memo has the wrong version byte',
  () => scCode(d.terms, `02${d.sc.memoHex.slice(2)}`, d.sc.uriHex),
  'MEMO_MALFORMED',
);
stage(
  'C-13',
  'contract',
  'the memo is one byte short',
  () => scCode(d.terms, d.sc.memoHex.slice(2), d.sc.uriHex),
  'MEMO_MALFORMED',
);
stage(
  'C-14',
  'contract',
  'a memo key without the ED prefix',
  () => scCode(d.terms, `${d.sc.memoHex.slice(0, 2)}EE${d.sc.memoHex.slice(4)}`, d.sc.uriHex),
  'MEMO_MALFORMED',
);
stage(
  'C-15',
  'contract',
  'a lawyer slot signs the contract through signContract with a signature that does not verify',
  () => codeOf(() => signContract(async () => d.contractSigs.sigLB, d.terms, 'LA')),
  'contract signature for LA does not verify',
);
stage(
  'C-16',
  'contract',
  'signContract returns the verified FROST signature',
  async () => (hex(await signContract(async (m) => d.S.LA.sign(m), d.terms, 'LA')).length === 128 ? 'ok' : 'bad'),
  'ok',
);
stage(
  'C-17',
  'contract',
  'a memo built from a short signature is refused',
  () =>
    codeOf(() =>
      encodeMintMemo({
        lawyerPubA: d.S.LA.pubHex,
        lawyerPubB: d.S.LB.pubHex,
        sigLA: new Uint8Array(63),
        sigLB: d.contractSigs.sigLB,
      }),
    ),
  'mint memo must be 195 bytes, got 194',
);

// ---- stage: FROST signing ----
const msgA = enc('paper deal signing message');
stage(
  'S-01',
  'frost-sign',
  'a third share signs alone',
  () =>
    codeOf(() => {
      const s = SigningSession.open(d.S.A.share(2), d.S.A.pub, msgA);
      s.signShare(msgA, [s.commitment], () => ({ ok: true }));
    }),
  'BELOW_THRESHOLD',
);
stage(
  'S-02',
  'frost-sign',
  'a nonce is reused for a second share',
  () =>
    codeOf(() => {
      const s = [0, 1].map((i) => SigningSession.open(d.S.A.share(i), d.S.A.pub, msgA));
      const list = s.map((x) => x.commitment);
      (s[0] as SigningSession).signShare(msgA, list, () => ({ ok: true }));
      (s[0] as SigningSession).signShare(msgA, list, () => ({ ok: true }));
    }),
  'NONCE_USED',
);
stage(
  'S-03',
  'frost-sign',
  'one signature share is wrong',
  () =>
    codeOf(() => {
      const s = [0, 1].map((i) => SigningSession.open(d.S.A.share(i), d.S.A.pub, msgA));
      const list = s.map((x) => x.commitment);
      const shares = Object.fromEntries(
        s.map((x, i) => [d.S.A.share(i).identifier, x.signShare(msgA, list, () => ({ ok: true }))]),
      );
      const id1 = d.S.A.share(1).identifier;
      shares[id1] = (shares[id1] as Uint8Array).map((b, k) => (k === 0 ? b ^ 1 : b));
      aggregateChecked(d.S.A.pub, list, msgA, shares);
    }),
  'SHARE_INVALID',
);
stage(
  'S-04',
  'frost-sign',
  'a share of slot B is used with slot A public data',
  () => codeOf(() => SigningSession.open(d.S.B.share(0), d.S.A.pub, msgA)),
  'SHARE_INVALID',
);
stage(
  'S-05',
  'frost-sign',
  'the signing session is asked to sign another message',
  () =>
    codeOf(() => {
      const s = SigningSession.open(d.S.A.share(0), d.S.A.pub, msgA);
      s.signShare(enc('another message'), [s.commitment], () => ({ ok: true }));
    }),
  'SESSION_MISMATCH',
);
stage(
  'S-06',
  'frost-sign',
  'the allow-list refuses an exit to an unsealed account',
  () =>
    codeOf(() => {
      const tx = {
        TransactionType: 'Payment',
        Account: WALLET,
        Destination: OPS.LA.address,
        Amount: '5000000000',
        Fee: '50',
        Sequence: 9,
      };
      const signer = xrpl.deriveAddress(d.S.A.pubHex);
      const msg = hexToBytes(xrpl.encodeForMultiSigning(tx as xrpl.Transaction, signer));
      d.S.A.sign(msg, (m) => messageAllowedFor(tx, m, 'A'));
    }),
  'MESSAGE_REFUSED',
);
stage(
  'S-07',
  'frost-sign',
  'a pq-binding is signed over another deal seal',
  () =>
    codeOf(() =>
      d.signTagged(
        'A',
        'legx/pq-binding/v1',
        [sha256(enc('other seal')), hexToBytes(d.S.A.pubHex), hexToBytes(d.S.A.pqKeyHash)],
        d.seal,
      ),
    ),
  'MESSAGE_REFUSED',
);
stage(
  'S-08',
  'frost-sign',
  'lawyer A is asked to sign a gate record',
  () => codeOf(() => d.S.LA.sign(sha256(enc('x')), (m) => messageAllowedGate(m))),
  'MESSAGE_REFUSED',
);

function messageAllowedFor(tx: Record<string, unknown>, m: Uint8Array, slot: SlotName) {
  return messageAllowed({ kind: 'xrpl-multisign', tx } as SignRequest, m, d.sealedDeal(d.seal), slot);
}
function messageAllowedGate(m: Uint8Array) {
  return messageAllowed({ kind: 'gate-record', envelope: d.gate.envelopeBytes }, m, d.sealedDeal(d.seal), 'LA');
}

// ---- stage: FROST DKG ----
stage(
  'D-01',
  'frost-dkg',
  'a holder is shown a different round-1 message (a transcript seen differently)',
  async () => {
    const { ctx, holders } = slotSetup('A');
    const alt = (await import('../src/frostDkg.ts')).dkgStart(ctx, 1, {
      signer: holders[0]!.signer,
      cipher: xwing,
      pinned: noPinCheck,
    }).out[0]!;
    const { dkgStart, dkgReceiveRound1, dkgReceiveEcho } = await import('../src/frostDkg.ts');
    const starts = holders.map((h, i) => dkgStart(ctx, i + 1, { signer: h.signer, cipher: xwing, pinned: noPinCheck }));
    const r1 = starts.flatMap((x) => x.out);
    const echoes = starts.map(
      (x) =>
        dkgReceiveRound1(
          x.state,
          r1.filter((m) => m.from !== x.state.me).map((m) => (m.from === 1 && x.state.me === 2 ? alt : m)),
        ).out[0]!,
    );
    const s3 = starts[2]!;
    return codeOf(() =>
      dkgReceiveEcho(
        s3.state,
        echoes.filter((e) => e.from !== s3.state.me),
      ),
    );
  },
  'TRANSCRIPT_MISMATCH',
);
stage(
  'D-02',
  'frost-dkg',
  'a swapped enrollment key (a key that was never pinned)',
  async () => {
    const { dkgStart } = await import('../src/frostDkg.ts');
    const { ctx, holders } = slotSetup('LA');
    const reg = new EnrollmentRegistry();
    for (const h of holders) {
      reg.pin(h.key);
      reg.markLogged(enrollmentKeyHash(h.key));
    }
    const evil = enroll('evil', 'firm-hsm');
    const swapped = { ...ctx, holders: ctx.holders.map((h, i) => (i === 1 ? { ...h, edPub: evil.key.edPub } : h)) };
    return codeOf(() => dkgStart(swapped, 1, { signer: holders[0]!.signer, cipher: xwing, pinned: reg.check }));
  },
  'KEY_NOT_PINNED',
);
stage(
  'D-03',
  'frost-dkg',
  'holder 1 deals holder 2 a share that fails the Feldman check',
  async () => {
    const { readRound1 } = await import('../src/frostDkg.ts');
    const { enrollmentSigned } = await import('../src/frost.ts');
    const { ctx, holders } = slotSetup('B');
    const aad = tupleHash('legx/frost-dkg-r2/v1', [ctx.sessionId, u32(1), u32(2)]);
    const run = await runDkg(ctx, holders, {
      r2: async (m, round1) => {
        if (m.from !== 1 || m.to !== 2) return m;
        const kem = readRound1(
          ctx,
          1,
          round1.filter((x) => x.from !== 1),
        ).get(2)!.kemPub;
        return enrollmentSigned(holders[0]!.signer, {
          ...m,
          fields: [await xwing.seal(kem, aad, new Uint8Array(32).fill(7))],
        });
      },
    });
    const verdict = await judgeComplaint(ctx, run.round1, run.results[1]!.out[0]!, xwing);
    return `guilty:${verdict.guilty}`;
  },
  'guilty:1',
);
stage(
  'D-04',
  'frost-dkg',
  'a pair signs a test message that is not its own',
  () =>
    codeOf(() => {
      const S = d.S.A;
      const msg = testSignMessage(S.k.ctx, S.pub, [1, 3]);
      const sessions = [0, 1].map((i) => SigningSession.open(S.share(i), S.pub, msg));
      const list = sessions.map((x) => x.commitment);
      (sessions[0] as SigningSession).signShare(msg, list, testSignCheck(S.k.ctx, S.pub, 1));
    }),
  'MESSAGE_REFUSED',
);
stage(
  'D-05',
  'frost-dkg',
  "a pair fails test-signing: its signature is another pair's",
  () =>
    codeOf(() => {
      const S = d.S.B;
      const t = S.testSignatures;
      dkgCompletedRecord({
        ctx: S.k.ctx,
        pub: S.pub,
        round1: S.k.run.round1,
        echoes: S.k.run.echoes,
        testSignatures: [t[0]!, t[1]!, { ...t[2]!, sig: t[0]!.sig }],
      });
    }),
  'SLOT_SETUP_FAILED',
);
stage(
  'D-06',
  'frost-dkg',
  'only two pairs were test-signed',
  () =>
    codeOf(() => {
      const S = d.S.LB;
      dkgCompletedRecord({
        ctx: S.k.ctx,
        pub: S.pub,
        round1: S.k.run.round1,
        echoes: S.k.run.echoes,
        testSignatures: S.testSignatures.slice(0, 2),
      });
    }),
  'SLOT_SETUP_FAILED',
);
stage(
  'D-07',
  'frost-dkg',
  "one holder's echo signature is missing",
  () =>
    codeOf(() => {
      const S = d.S.LA;
      dkgCompletedRecord({
        ctx: S.k.ctx,
        pub: S.pub,
        round1: S.k.run.round1,
        echoes: S.k.run.echoes.slice(0, 2),
        testSignatures: S.testSignatures,
      });
    }),
  'SLOT_SETUP_FAILED',
);

const withDkg =
  (slot: SlotName, mut: (data: any) => void): Mut =>
  async (i, w) => {
    const data = structuredClone(w.S[slot].dkgData) as Record<string, unknown>;
    mut(data);
    i.records.dkgCompleted[slot] = await w.event('frost.dkg.completed', data);
  };
gate(
  'D-08',
  'the recorded roles are single-device roles, not the sealed ones',
  withDkg('A', (x) => {
    x.roles = ['phone', 'passkey-same-device', 'recovery-agent'];
  }),
  'SLOT_SETUP_OK:A:SLOT_POLICY_MISMATCH',
  ['SLOT_SETUP_OK'],
);
gate(
  'D-08b',
  'the recorded roles come in another order (the policy hash is order-independent)',
  withDkg('A', (x) => {
    x.roles = [...(x.roles as string[])].reverse();
  }),
  'PASSES',
);
gate(
  'D-09',
  'the recorded policy hash differs from the sealed one',
  withDkg('LB', (x) => {
    x.slot_policy = h32(9);
  }),
  'SLOT_SETUP_OK:LB:SLOT_POLICY_MISMATCH',
  ['SLOT_SETUP_OK'],
);
gate(
  'D-10',
  "the recorded group key is another slot's",
  withDkg('B', (x) => {
    x.group_pub = d.S.A.pubHex;
  }),
  'SLOT_SETUP_OK:B:GROUP_KEY_NOT_SEALED',
  ['SLOT_SETUP_OK'],
);
gate(
  'D-11',
  'one pair fails test-signing in the recorded event',
  withDkg('B', (x) => {
    (x.test_sigs as string[])[2] = (x.test_sigs as string[])[0] as string;
  }),
  'SLOT_SETUP_OK:B:TEST_SIGNATURE_INVALID',
  ['SLOT_SETUP_OK'],
);
gate(
  'D-12',
  'a different transcript hash than the holders signed',
  withDkg('LA', (x) => {
    x.transcript_hash = h32(0x5a);
  }),
  'SLOT_SETUP_OK:LA:TRANSCRIPT_NOT_SIGNED',
  ['SLOT_SETUP_OK'],
);
gate(
  'D-13',
  'a swapped enrollment key: the registry holds another Ed25519 key for A/phone',
  (i, w) => {
    i.records.keys = i.records.keys.map((k: any) =>
      k.keyId === 'A/phone/ed' ? { ...k, publicKey: ed25519.getPublicKey(new Uint8Array(32).fill(3)) } : k,
    );
  },
  'SLOT_SETUP_OK:A:TRANSCRIPT_NOT_SIGNED',
  ['SLOT_SETUP_OK'],
);
gate(
  'D-14',
  'the dkg event of slot A is missing',
  (i) => {
    delete i.records.dkgCompleted.A;
  },
  'SLOT_SETUP_OK:A:MISSING',
  ['SLOT_SETUP_OK'],
);

// ---- stage: post-quantum bindings ----
const withPq =
  (slot: SlotName, mut: (b: any) => void): Mut =>
  async (i, w) => {
    const data = structuredClone(w.pqData(slot)) as { binding: Record<string, unknown> };
    mut(data.binding);
    i.records.pqBound[slot] = await w.event('pq.bound', data);
  };
gate(
  'Q-01',
  'a stripped ML-DSA signature: only one holder signed',
  withPq('A', (b) => {
    b.holder_sigs = b.holder_sigs.slice(0, 1);
  }),
  'PQ_BINDINGS_OK:A:BELOW_TWO_HOLDERS',
  ['PQ_BINDINGS_OK'],
);
gate(
  'Q-02',
  'a wrong pqKeyHash in the binding',
  withPq('LA', (b) => {
    b.pq_key_hash = h32(0x66);
  }),
  'PQ_BINDINGS_OK:LA:PQ_KEY_HASH_MISMATCH',
  ['PQ_BINDINGS_OK'],
);
gate(
  'Q-03',
  'the cross-signature is by another slot',
  withPq('B', (b) => {
    b.cross_sig = hex(d.S.A.sign(pqBindMsg(d.seal, hexToBytes(d.S.B.pubHex), hexToBytes(d.S.B.pqKeyHash))));
  }),
  'PQ_BINDINGS_OK:B:CROSS_SIG_INVALID',
  ['PQ_BINDINGS_OK'],
);
gate(
  'Q-04',
  'the same holder signs twice',
  withPq('LB', (b) => {
    b.holder_sigs = [b.holder_sigs[0], b.holder_sigs[0]];
  }),
  'PQ_BINDINGS_OK:LB:DUPLICATE_HOLDER',
  ['PQ_BINDINGS_OK'],
);
gate(
  'Q-05',
  'a holder key of another slot signs',
  withPq('A', (b) => {
    b.holder_sigs[1].key_id = d.S.B.holders[0]?.mlDsa65;
  }),
  'PQ_BINDINGS_OK:A:HOLDER_KEY_UNKNOWN',
  ['PQ_BINDINGS_OK'],
);
gate(
  'Q-06',
  'one ML-DSA signature has a flipped byte',
  withPq('A', (b) => {
    const raw = fromBase64Strict(b.holder_sigs[0].sig) as Uint8Array;
    raw[5] = (raw[5] ?? 0) ^ 1;
    b.holder_sigs[0].sig = toBase64(raw);
  }),
  'PQ_BINDINGS_OK:A:HOLDER_SIG_INVALID',
  ['PQ_BINDINGS_OK'],
);
gate(
  'Q-07',
  'the binding names another deal seal',
  withPq('LA', (b) => {
    b.deal_seal = h32(0x77);
  }),
  'PQ_BINDINGS_OK:LA:SEAL_MISMATCH',
  ['PQ_BINDINGS_OK'],
);
gate(
  'Q-08',
  'the binding names another slot key',
  withPq('B', (b) => {
    b.slot_pub = d.S.A.pubHex;
  }),
  'PQ_BINDINGS_OK:B:SLOT_PUB_MISMATCH',
  ['PQ_BINDINGS_OK'],
);
gate(
  'Q-09',
  'the cross-signature is stripped',
  withPq('A', (b) => {
    delete b.cross_sig;
  }),
  'PQ_BINDINGS_OK:A:CROSS_SIG_MISSING',
  ['PQ_BINDINGS_OK'],
);
gate(
  'Q-10',
  "a holder's ML-DSA key is replaced in the registry: the three keys no longer give the sealed hash",
  (i) => {
    i.records.keys = i.records.keys.map((k: any) =>
      k.keyId === 'B/partner/pq' || k.keyId === 'B/recovery-agent/pq'
        ? { ...k, publicKey: new Uint8Array(k.publicKey.length).fill(9) }
        : k,
    );
  },
  'PQ_BINDINGS_OK:B:PQ_KEY_HASH_MISMATCH',
);
stage(
  'Q-11',
  'pq',
  'a record whose sig_algs lists Ed25519 only cannot be hybrid-signed',
  () => codeOf(() => d.event('pq.bound', {}, d.lawyerSigner.A, { sig_algs: ['ed25519'] })),
  'SIG_ALGS_MISMATCH',
);
gate(
  'Q-12',
  'a stored attestation whose sig_algs was changed after signing',
  async (i, w) => {
    const env = JSON.parse(new TextDecoder().decode(i.records.passport.B));
    const body = JSON.parse(new TextDecoder().decode(fromBase64Strict(env.payload) as Uint8Array));
    body.sig_algs = ['ed25519'];
    env.payload = toBase64(utf8ToBytes(JSON.stringify(body)));
    i.records.passport.B = utf8ToBytes(JSON.stringify(env));
  },
  'PASSPORT_B_OK:ENVELOPE_INVALID:SIG_ALGS_MISMATCH',
);
stage(
  'Q-13',
  'pq',
  'an ML-DSA signature over the binding with the wrong context fails',
  () => {
    const msg = pqBindMsg(d.seal, hexToBytes(d.S.A.pubHex), hexToBytes(d.S.A.pqKeyHash));
    const holders = d.S.A.pq.map((p, j) => ({ keyId: `k${j}`, mlDsa65: p.publicKey })) as [
      { keyId: string; mlDsa65: Uint8Array },
      { keyId: string; mlDsa65: Uint8Array },
      { keyId: string; mlDsa65: Uint8Array },
    ];
    const sig = (j: number, ctx: 'legx/pq-binding/v1' | 'legx/dsse/v1') => ({
      keyId: `k${j}`,
      sig: mldsa(d.S.A.pq[j]!.secretKey, msg, ctx),
    });
    const r = verifyPqBinding(
      {
        dealSeal: d.seal,
        slotPub: hexToBytes(d.S.A.pubHex),
        pqKeyHash: hexToBytes(d.S.A.pqKeyHash),
        holderSigs: [sig(0, 'legx/pq-binding/v1'), sig(1, 'legx/dsse/v1')],
        crossSig: d.S.A.sign(msg),
      },
      { dealSeal: d.seal, slotPub: hexToBytes(d.S.A.pubHex), pqKeyHash: hexToBytes(d.S.A.pqKeyHash) },
      holders,
      (p, m, s) => verifyEd25519Strict(s, m, p),
    );
    return r.ok ? 'ok' : r.code;
  },
  'HOLDER_SIG_INVALID',
);
const mldsa = (sk: Uint8Array, msg: Uint8Array, ctx: 'legx/pq-binding/v1' | 'legx/dsse/v1') =>
  mldsaSign('ml-dsa-65', sk, msg, ctx);

// ---- stage: operations bindings ----
const withOps =
  (role: 'LA' | 'LB', mut: (o: any, msg: Uint8Array) => void): Mut =>
  async (i, w) => {
    const o = structuredClone(w.opsData(role)) as Record<string, unknown>;
    mut(
      o,
      opsBindMsg({
        contractRoot: w.root,
        opsAccount: OPS[role].address,
        lawyerPub: w.S[role].pubHex,
        lawyerCommitment: w.LC[role],
        role,
      }),
    );
    i.records.opsBound[role] = await w.event('ops.bound', o);
  };
gate(
  'O-01',
  "a swapped operations key: lawyer B's key presented for lawyer A's account",
  withOps('LA', (o) => {
    o.ops_pub = OPS.LB.pub;
  }),
  'OPS_BINDINGS_OK:LA:OPS_KEY_NOT_AUTHORIZED',
  ['OPS_BINDINGS_OK'],
);
gate(
  'O-02',
  'the lawyer slot signature is by the other lawyer slot',
  withOps('LA', (o, msg) => {
    o.sig_lawyer = up(d.S.LB.sign(msg));
  }),
  'OPS_BINDINGS_OK:LA:LAWYER_SIG_INVALID',
  ['OPS_BINDINGS_OK'],
);
gate(
  'O-03',
  'the operations key signature is over another message',
  withOps('LB', (o) => {
    o.sig_ops = up(ed25519.sign(sha256(enc('other')), OPS.LB.sk));
  }),
  'OPS_BINDINGS_OK:LB:OPS_SIG_INVALID',
  ['OPS_BINDINGS_OK'],
);
gate(
  'O-04',
  'the operations account has its master key disabled and no regular key',
  (i) => {
    i.ledger.opsAccounts.LA.account_data.Flags = lsf.DisableMaster;
  },
  'OPS_BINDINGS_OK:LA:OPS_KEY_NOT_AUTHORIZED',
  ['OPS_BINDINGS_OK'],
);
gate(
  'O-05',
  'the account snapshot is not validated',
  (i) => {
    i.ledger.opsAccounts.LB.validated = false;
  },
  'OPS_BINDINGS_OK:LB:NOT_VALIDATED',
  ['OPS_BINDINGS_OK'],
);

// ---- stage: bar records and credentials ----
gate(
  'B-01',
  'the bar status is not active',
  async (i, w) => {
    i.records.bar.LA = await w.bar('LA', { status: 'not_active' });
  },
  'BAR_A_OK:NOT_ACTIVE',
  ['BAR_A_OK'],
);
gate(
  'B-02',
  'the bar check is older than 30 days by ledger time',
  async (i, w) => {
    const old = { ledger_index: 88_000_000, ledger_hash: up(new Uint8Array(32).fill(0x79)) };
    i.ledger.history.push({ index: old.ledger_index, hash: old.ledger_hash, closeTime: NOW - 31 * 86_400 });
    i.records.bar.LB = await w.bar('LB', { checked_at_ledger: old });
  },
  'BAR_B_OK:STALE',
  ['BAR_B_OK'],
);
gate(
  'B-03',
  'the verification is for another operations account',
  async (i, w) => {
    i.records.bar.LB = await w.bar('LB', { ops_account: OPS.LA.address });
  },
  'BAR_B_OK:OPS_MISMATCH',
  ['BAR_B_OK'],
);
gate(
  'B-04',
  'the link carries another bar commitment',
  async (i, w) => {
    i.records.bar.LA = await w.bar('LA', {}, { bar_commitment: h32(7) });
  },
  'BAR_A_OK:COMMITMENT_MISMATCH',
  ['BAR_A_OK'],
);
gate(
  'B-05',
  "the bar records are signed by a lawyer key, not the verifier's",
  async (i, w) => {
    i.records.bar.LA = await w.bar('LA', {}, {}, w.lawyerSigner.A);
  },
  'BAR_A_OK:WRONG_SIGNER',
  ['BAR_A_OK'],
);
gate(
  'B-06',
  'the link names another deal',
  async (i, w) => {
    i.records.bar.LA = await w.bar('LA', {}, { deal_id: '0192f1a0-7b3c-7d4e-8f00-0000000000a9' });
  },
  'BAR_A_OK:WRONG_DEAL',
  ['BAR_A_OK'],
);
gate(
  'B-07',
  'the attorney credential is expired at the gate ledger',
  (i) => {
    i.ledger.credentials[0].Expiration = NOW - 1;
  },
  'ATTORNEY_CREDENTIAL_A_OK:EXPIRED',
  ['ATTORNEY_CREDENTIAL_A_OK'],
);
gate(
  'B-08',
  'the attorney credential is from another issuer',
  (i) => {
    i.ledger.credentials[1].Issuer = ALICE;
  },
  'ATTORNEY_CREDENTIAL_B_OK:WRONG_ISSUER',
  ['ATTORNEY_CREDENTIAL_B_OK'],
);
gate(
  'B-09',
  'the attorney credential was never accepted',
  (i) => {
    i.ledger.credentials[0].Flags = 0;
  },
  'ATTORNEY_CREDENTIAL_A_OK:NOT_ACCEPTED',
  ['ATTORNEY_CREDENTIAL_A_OK'],
);

// ---- stage: lock ----
gate(
  'L-01',
  'the setup key is left on',
  (i) => {
    i.ledger.account.Flags &= ~lsf.DisableMaster;
  },
  'LOCK_OK:MASTER_DISABLED',
  ['LOCK_OK'],
);
gate(
  'L-02',
  'the signer quorum is 3',
  (i) => {
    i.ledger.objects[0].SignerQuorum = 3;
  },
  'LOCK_OK:QUORUM_MATCH,QUORUM_NEEDS_EVERY_SIGNER',
  ['LOCK_OK'],
);
gate(
  'L-03',
  "the Domain holds another deal's seal",
  (i, w) => {
    i.ledger.account.Domain = up(domain(w.root, sha256(enc('another deal'))));
  },
  'LOCK_OK:DOMAIN_IS_SEAL',
  ['LOCK_OK'],
);
gate(
  'L-04',
  'the escrow can be cancelled within a day',
  (i) => {
    i.ledger.objects[4].CancelAfter = NOW + 3600;
  },
  'LOCK_OK:CANCEL_AFTER_MARGIN',
  ['LOCK_OK'],
);
gate(
  'L-05',
  'an unexpected offer is owned by the wallet',
  (i) => {
    i.ledger.objects.push({ LedgerEntryType: 'Offer', Account: WALLET });
  },
  'LOCK_OK:UNEXPECTED_OWNED_OFFER,OWNER_COUNT_MATCHES',
  ['LOCK_OK'],
);
gate(
  'L-06',
  'the submitter is not the sealed releaser',
  (i) => {
    i.submitter = OPS.LA.address;
  },
  'RELEASER_SEALED:SUBMITTER_NOT_SEALED',
  ['RELEASER_SEALED'],
);
gate(
  'L-07',
  'the DepositPreauth authorizes another account',
  (i) => {
    i.ledger.objects[1].Authorize = OPS.LA.address;
  },
  'LOCK_OK:PREAUTH_ONLY_RELEASER',
  ['LOCK_OK', 'RELEASER_SEALED'],
);

// ---- stage: passport attestations, presence, nonces ----
gate(
  'P-01',
  "lawyer B signs client A's passport attestation",
  async (i, w) => {
    i.records.passport.A = await w.passport('A', {}, 'B');
  },
  'PASSPORT_A_OK:WRONG_SIGNER',
  ['PASSPORT_A_OK'],
);
gate(
  'P-02',
  "the presence signature is by the other client's slot",
  async (i, w) => {
    const sig = hex(w.S.B.sign(w.presence('A')));
    i.records.passport.A = await w.passport('A', { presence_sig: sig });
  },
  'PASSPORT_A_OK:PRESENCE_INVALID',
  ['PASSPORT_A_OK'],
);
gate(
  'P-03',
  'the presence signature is older than 1 hour by ledger time',
  async (i, w) => {
    const old = { ledger_index: 90_000_050, ledger_hash: up(new Uint8Array(32).fill(0x66)) };
    i.ledger.history.push({ index: old.ledger_index, hash: old.ledger_hash, closeTime: NOW - 3601 });
    const sig = hex(
      w.signTagged(
        'B',
        'legx/passport-presence/v1',
        [w.seal, utf8ToBytes('B'), hexToBytes(old.ledger_hash), hexToBytes(NONCE.B)],
        w.seal,
      ),
    );
    i.records.passport.B = await w.passport('B', { ledger_anchor: old, presence_sig: sig });
  },
  'PASSPORT_B_OK:STALE',
  ['PASSPORT_B_OK'],
);
gate(
  'P-04',
  'the presence signature is exactly 1 hour old and still fresh',
  async (i, w) => {
    const old = { ledger_index: 90_000_051, ledger_hash: up(new Uint8Array(32).fill(0x65)) };
    i.ledger.history.push({ index: old.ledger_index, hash: old.ledger_hash, closeTime: NOW - 3600 });
    const sig = hex(
      w.signTagged(
        'B',
        'legx/passport-presence/v1',
        [w.seal, utf8ToBytes('B'), hexToBytes(old.ledger_hash), hexToBytes(NONCE.B)],
        w.seal,
      ),
    );
    i.records.passport.B = await w.passport('B', { ledger_anchor: old, presence_sig: sig });
  },
  'PASSES',
);
gate(
  'P-05',
  'the lawyer nonce was changed after the presence signature',
  async (i, w) => {
    i.records.passport.B = await w.passport('B', { lawyer_nonce: h32(0x54) });
  },
  'PASSPORT_B_OK:PRESENCE_INVALID',
  ['PASSPORT_B_OK'],
);
gate(
  'P-06',
  'the lawyer nonce has 31 bytes',
  async (i, w) => {
    i.records.passport.A = await w.passport('A', { lawyer_nonce: NONCE.A.slice(2) });
  },
  'PASSPORT_A_OK:NONCE_LENGTH',
  ['PASSPORT_A_OK'],
);
gate(
  'P-07',
  'the attestation names another deal seal',
  async (i, w) => {
    i.records.passport.B = await w.passport('B', { deal_seal: h32(0x31) });
  },
  'PASSPORT_B_OK:WRONG_DEAL',
  ['PASSPORT_B_OK'],
);
gate(
  'P-08',
  'the attestation states another commitment',
  async (i, w) => {
    i.records.passport.A = await w.passport('A', { commitment: h32(0x32) });
  },
  'PASSPORT_A_OK:COMMITMENT_MISMATCH',
  ['PASSPORT_A_OK'],
);
gate(
  'P-09',
  'the ledger anchor is not in validated history',
  async (i, w) => {
    i.records.passport.B = await w.passport('B', { ledger_anchor: { ...ANCHOR, ledger_index: 12345 } });
  },
  'PASSPORT_B_OK:ANCHOR_UNKNOWN',
  ['PASSPORT_B_OK'],
);
gate(
  'P-10',
  "the anchor hash differs from the ledger's (and the presence signature covers that hash)",
  async (i, w) => {
    const wrong = up(new Uint8Array(32).fill(1));
    const sig = hex(
      w.signTagged(
        'B',
        'legx/passport-presence/v1',
        [w.seal, utf8ToBytes('B'), hexToBytes(wrong), hexToBytes(NONCE.B)],
        w.seal,
      ),
    );
    i.records.passport.B = await w.passport('B', {
      ledger_anchor: { ...ANCHOR, ledger_hash: wrong },
      presence_sig: sig,
    });
  },
  'PASSPORT_B_OK:ANCHOR_MISMATCH',
  ['PASSPORT_B_OK'],
);
stage(
  'P-11',
  'nonce',
  'a lawyer nonce is reused',
  () => {
    const r = checkFreshNonce(hexToBytes(NONCE.A), new Set([NONCE.A]));
    return r.ok ? 'ok' : r.code;
  },
  'NONCE_REUSED',
);
stage(
  'P-12',
  'nonce',
  'a lawyer nonce of 31 bytes',
  () => {
    const r = checkFreshNonce(hexToBytes(NONCE.A).slice(1), new Set());
    return r.ok ? 'ok' : r.code;
  },
  'NONCE_LENGTH',
);
stage(
  'P-13',
  'nonce',
  'a fresh nonce is accepted',
  () => {
    const r = checkFreshNonce(hexToBytes(NONCE.B), new Set([NONCE.A]));
    return r.ok ? 'ok' : r.code;
  },
  'ok',
);

gate(
  'P-14',
  'the ledger anchor is not an object',
  async (i, w) => {
    i.records.passport.A = await w.passport('A', { ledger_anchor: 'x' });
  },
  'PASSPORT_A_OK:PAYLOAD_MALFORMED',
  ['PASSPORT_A_OK'],
);
gate(
  'P-15',
  'the lawyer nonce is not hex',
  async (i, w) => {
    i.records.passport.B = await w.passport('B', { lawyer_nonce: 'zz'.repeat(32) });
  },
  'PASSPORT_B_OK:PAYLOAD_MALFORMED',
  ['PASSPORT_B_OK'],
);
gate(
  'P-16',
  'the onboarding attestation carries an unknown field',
  async (i, w) => {
    i.records.onboarding.B = await w.onboarding('B', { extra: 1 });
  },
  'ONBOARDING_OK:B:PAYLOAD_MALFORMED',
  ['ONBOARDING_OK'],
);
stage(
  'P-17',
  'presence',
  'presenceMsg refuses a 31-byte seal',
  () => codeOf(() => presenceMsg(d.seal.slice(1), 'A', hexToBytes(ANCHOR.ledger_hash), hexToBytes(NONCE.A))),
  'dealSeal and ledgerHash must be 32 bytes',
);
stage(
  'P-18',
  'presence',
  'presenceMsg refuses a nonce of 31 bytes and a third side',
  () =>
    `${(() => {
      try {
        presenceMsg(d.seal, 'A', hexToBytes(ANCHOR.ledger_hash), new Uint8Array(31));
      } catch (e) {
        return (e as Error).message;
      }
    })()}|${(() => {
      try {
        presenceMsg(d.seal, 'C' as 'A', hexToBytes(ANCHOR.ledger_hash), hexToBytes(NONCE.A));
      } catch (e) {
        return (e as Error).message;
      }
    })()}`,
  'NONCE_LENGTH|side must be A or B',
);
gate(
  'Q-14',
  "a holder's ML-DSA key is missing from the registry: lawyer A's keys are bound to no seal",
  (i) => {
    i.records.keys = i.records.keys.filter((k: { keyId: string }) => k.keyId !== 'LA/partner/pq');
  },
  'PASSPORT_A_OK:WRONG_SIGNER',
);
stage(
  'Q-15',
  'pq',
  'a truncated ML-DSA signature is an invalid signature, not a crash',
  () => {
    const msg = pqBindMsg(d.seal, hexToBytes(d.S.A.pubHex), hexToBytes(d.S.A.pqKeyHash));
    const holders = d.S.A.pq.map((p, j) => ({ keyId: `k${j}`, mlDsa65: p.publicKey })) as [
      { keyId: string; mlDsa65: Uint8Array },
      { keyId: string; mlDsa65: Uint8Array },
      { keyId: string; mlDsa65: Uint8Array },
    ];
    const r = verifyPqBinding(
      {
        dealSeal: d.seal,
        slotPub: hexToBytes(d.S.A.pubHex),
        pqKeyHash: hexToBytes(d.S.A.pqKeyHash),
        holderSigs: [
          { keyId: 'k0', sig: new Uint8Array(10) },
          { keyId: 'k1', sig: new Uint8Array(10) },
        ],
        crossSig: d.S.A.sign(msg),
      },
      { dealSeal: d.seal, slotPub: hexToBytes(d.S.A.pubHex), pqKeyHash: hexToBytes(d.S.A.pqKeyHash) },
      holders,
      (p, m, sg) => verifyEd25519Strict(sg, m, p),
    );
    return r.ok ? 'ok' : r.code;
  },
  'HOLDER_SIG_INVALID',
);
stage(
  'F-01',
  'frost-id',
  'a FROST identifier that is not lowercase hex',
  () => codeOf(() => idScalar('ZZ')),
  'INPUT_INVALID',
);

// ---- stage: zero-knowledge results (the lawyer console's checkZkResult, fixture world) ----
const zkr = (
  set: typeof ZK.release,
  x: Partial<typeof FIXTURE_RELEASE>,
  trust: Record<string, unknown> = {},
  top: Record<string, unknown> = {},
) => {
  const r = checkZkResult(
    { ...set.verification, ...top, trust: { ...set.verification.trust, ...trust } } as never,
    set.request.originalQuery,
    { ...FIXTURE_RELEASE, ...x } as never,
  );
  return r.ok ? 'ok' : r.code;
};
stage(
  'Z-01',
  'zk',
  'a wrong zero-knowledge scope (another deal)',
  () => zkr(ZK.release, { dealId: ZK_DEAL2 }),
  'WRONG_SCOPE',
);
stage(
  'Z-02',
  'zk',
  'a wrong bound value (another deal seal)',
  () => zkr(ZK.release, { boundValue: ZK.onboarding.verification.committedInputs.custom_data as string }),
  'BOUND_VALUE_MISMATCH',
);
stage(
  'Z-03',
  'zk',
  'a devMode result in the production profile',
  () => zkr(ZK.release, { profile: 'production' }),
  'DEVMODE_REFUSED',
);
stage(
  'Z-04',
  'zk',
  'a Sepolia result in the production profile',
  () => zkr(ZK.release, { profile: 'production' }, { devMode: false }),
  'SEPOLIA_REFUSED',
);
stage(
  'Z-05',
  'zk',
  'a mock identifier in the production profile',
  () => zkr(ZK.release, { profile: 'production' }, { devMode: false, chainId: 1 }),
  'MOCK_IDENTIFIER_REFUSED',
);
stage(
  'Z-06',
  'zk',
  'the result belongs to another domain',
  () => zkr(ZK.release, {}, {}, { domain: 'evil.example' }),
  'WRONG_DOMAIN',
);
stage(
  'Z-07',
  'zk',
  'the proof does not verify',
  () => zkr(ZK.release, {}, {}, { verified: false }),
  'PROOF_NOT_VERIFIED',
);
stage(
  'Z-08',
  'zk',
  'the identifier gives another commitment than the sealed C_A',
  () =>
    zkr(ZK.release, {
      identity: { zkSalt32: new Uint8Array(32).fill(1), commitment: FIXTURE_RELEASE.identity?.commitment ?? '' },
    }),
  'IDENTIFIER_MISMATCH',
);
stage(
  'Z-09',
  'zk',
  'the document expires before CancelAfter plus 30 days',
  () => {
    const r = checkZkResult(ZK.onboarding.verification, ZK.onboarding.request.originalQuery, {
      ...FIXTURE_ONBOARD,
      cancelAfter: FIXTURE_ONBOARD.cancelAfter! + 1,
    });
    return r.ok ? 'ok' : r.code;
  },
  'EXPIRY_TOO_EARLY',
);
stage(
  'Z-10',
  'zk',
  'a trust record with a missing field',
  () => {
    const t = { ...(d.zkRelease.trust as Record<string, unknown>) };
    delete t.root;
    const r = checkTrustRecord(t, 'demo');
    return r.ok ? 'ok' : r.code;
  },
  'ZK_RECORD_INCOMPLETE',
);
gate(
  'Z-11',
  'a devMode result in the production profile reaches the gate',
  (i) => {
    i.profile = 'production';
  },
  'PASSPORT_A_OK:DEVMODE_REFUSED',
  ['PASSPORT_A_OK', 'ONBOARDING_OK'],
);
gate(
  'Z-12',
  'the stored proof set is not the one the attestation hashed',
  (i) => {
    i.records.zkProof.A = utf8ToBytes('another proof set');
  },
  'PASSPORT_A_OK:PROOF_HASH_MISMATCH',
  ['PASSPORT_A_OK'],
);
gate(
  'Z-13',
  'the face match result is absent (an explicit false is a demo-only result, OD-34)',
  async (i, w) => {
    i.records.passport.A = await w.passport('A', { checks: { ...w.zkRelease, face_match_passed: undefined } });
  },
  'PASSPORT_A_OK:CHECK_FALSE:face_match_passed',
  ['PASSPORT_A_OK'],
);
gate(
  'Z-14',
  'the bound value is not the presence message',
  async (i, w) => {
    i.records.passport.A = await w.passport('A', { checks: { ...w.zkRelease, bound_value_is_presence_msg: false } });
  },
  'PASSPORT_A_OK:CHECK_FALSE:bound_value_is_presence_msg',
  ['PASSPORT_A_OK'],
);
gate(
  'Z-15',
  'the onboarding attestation states another C_side',
  async (i, w) => {
    i.records.onboarding.A = await w.onboarding('A', { commitment: h32(0x33) });
  },
  'ONBOARDING_OK:A:COMMITMENT_MISMATCH',
  ['ONBOARDING_OK'],
);
gate(
  'Z-16',
  'a method the policy does not allow: client B presents zkpassport while the seal says nfc-chip',
  async (i, w) => {
    i.records.passport.B = await w.passport('B', { method: 'zkpassport', checks: w.zkRelease });
  },
  'PASSPORT_B_OK:METHOD_MISMATCH',
  ['PASSPORT_B_OK', 'IDENTITY_POLICY_OK'],
);
gate(
  'Z-17',
  'the onboarding attestation is by the wrong lawyer',
  async (i, w) => {
    i.records.onboarding.B = await w.onboarding('B', {}, 'A');
  },
  'ONBOARDING_OK:B:WRONG_SIGNER',
  ['ONBOARDING_OK'],
);
gate(
  'Z-18',
  'the onboarding trust record is incomplete',
  async (i, w) => {
    const t = { ...(w.zkOnboard.trust as Record<string, unknown>) };
    delete t.block_hash;
    i.records.onboarding.A = await w.onboarding('A', { checks: { ...w.zkOnboard, trust: t } });
  },
  'ONBOARDING_OK:A:ZK_RECORD_INCOMPLETE',
  ['ONBOARDING_OK'],
);
stage(
  'Z-19',
  'zk',
  'a seal whose policy forbids a sealed method cannot be built',
  () => codeOf(() => dealSeal({ ...d.data, identityPolicy: 'chip' } as typeof d.data)),
  'idMethod zkpassport not allowed by chip',
);
const ZK_DEAL2 = ZK.onboarding.inputs.deal2;

// ---- stage: chip identity ----
const chipBase = () => {
  const msg = d.presence('B');
  const c = d.chipB;
  return {
    dg1: c.passport.dg1,
    sod: c.passport.sod,
    dg14: c.passport.dg14,
    dg15: c.passport.dg15,
    trustList: [d.pki.csca.cert],
    atTime: NOW,
    salt: c.salt,
    commitment: d.commitmentOf.B,
    presenceMsg: msg,
    aaSignature: chipAnswerAA(c.passport.aaKey as never, aaChallenge(msg)),
  };
};
const chipCode = async (over: Record<string, unknown>) => {
  const r = await chipChecks({ ...chipBase(), ...over } as never);
  return r.ok ? 'ok' : r.code;
};
stage(
  'H-01',
  'chip',
  'the commitment does not open (a wrong salt)',
  () => chipCode({ salt: new Uint8Array(32).fill(1) }),
  'COMMITMENT_MISMATCH',
);
stage(
  'H-02',
  'chip',
  'no chip authentication answer',
  () => chipCode({ aaSignature: undefined }),
  'CHIP_AUTH_REQUIRED',
);
stage(
  'H-03',
  'chip',
  'the active-authentication answer is over another challenge',
  () => chipCode({ aaSignature: chipAnswerAA(d.chipB.passport.aaKey as never, aaChallenge(d.presence('A'))) }),
  'CHIP_AUTH_INVALID',
);
stage(
  'H-04',
  'chip',
  'the document signer chains to no trusted CSCA',
  () => chipCode({ trustList: [] }),
  'DS_NOT_CHAINED',
);
stage(
  'H-05',
  'chip',
  'the document expired (ledger time 2036)',
  () => chipCode({ atTime: Math.floor(Date.parse('2036-01-01T00:00:00Z') / 1000) - 946_684_800 }),
  'DOCUMENT_EXPIRED',
);
stage(
  'H-06',
  'chip',
  'a relayed chip: DG15 of another chip',
  async () => {
    return chipCode({ dg15: (await otherChip()).dg15 });
  },
  'DG15_HASH_MISMATCH',
);
const otherChip = async () => {
  return makePassport({
    pki: d.pki,
    mrz: {
      documentNumber: 'L898902C3',
      surname: 'ERIKSSON',
      givenNames: 'ANNA MARIA',
      dateOfBirth: '740812',
      sex: 'F',
      dateOfExpiry: '340415',
    },
    seed: new Uint8Array(32).fill(3),
  });
};
stage(
  'H-07',
  'chip',
  'the SOD is truncated',
  () => chipCode({ sod: d.chipB.passport.sod.slice(0, 100) }),
  'SOD_MALFORMED',
);
gate(
  'H-08',
  'chip checks say the commitment did not open',
  async (i, w) => {
    i.records.passport.B = await w.passport('B', {
      checks: { ...(await w.chipChecksFor('B')), commitment_opens: false },
    });
  },
  'PASSPORT_B_OK:CHECK_FALSE:commitment_opens',
  ['PASSPORT_B_OK'],
);

// ---- stage: gate record, checkpoint ----
stage(
  'R-01',
  'record',
  'a blocked gate builds no record',
  () =>
    codeOf(async () => {
      const i = structuredClone(d.input);
      i.ledger.account.Flags &= ~lsf.DisableMaster;
      await buildGatePassedRecord(i, d.EVENT_FIELDS, d.lawyerSigner.B, async (_e, m) => d.S.LB.sign(m));
    }),
  'GATE_BLOCKED',
);
stage(
  'R-02',
  'record',
  "slot LB's signature is by slot LA",
  () => codeOf(() => buildGatePassedRecord(d.input, d.EVENT_FIELDS, d.lawyerSigner.B, async (_e, m) => d.S.LA.sign(m))),
  'SLOT_LB_SIG_INVALID',
);
stage(
  'R-03',
  'record',
  'the gate record is signed by lawyer A',
  async () => {
    const rec = await buildGatePassedRecord(d.input, d.EVENT_FIELDS, d.lawyerSigner.A, async (_e, m) => d.S.LB.sign(m));
    const r = verifyGatePassedRecord(rec.envelopeBytes, {
      deal: d.input.deal,
      keys: d.input.records.keys,
      lawyerB: d.input.records.slotHolders.LB,
      at: NOW,
    });
    return r.ok ? 'ok' : r.code;
  },
  'WRONG_SIGNER',
);
stage(
  'R-04',
  'record',
  'the memo is built from a 31-byte hash',
  () => codeOf(() => gateMemo(new Uint8Array(31))),
  'leaf hash must be 32 bytes',
);
stage(
  'R-05',
  'record',
  'a flipped byte inside the stored gate record',
  () => {
    const env = JSON.parse(new TextDecoder().decode(d.gate.envelopeBytes));
    const sig = fromBase64Strict(env.signatures[0].sig) as Uint8Array;
    sig[3] = (sig[3] ?? 0) ^ 1;
    env.signatures[0].sig = toBase64(sig);
    const b = utf8ToBytes(JSON.stringify(env));
    const r = verifyGatePassedRecord(b, {
      deal: d.input.deal,
      keys: d.input.records.keys,
      lawyerB: d.input.records.slotHolders.LB,
      at: NOW,
    });
    return r.ok ? 'ok' : r.code;
  },
  'ENVELOPE_INVALID:ED_SIGNATURE_INVALID',
);
const cpKeys = () => ({
  ed: { name: LOG.origin, publicKey: ed25519.getPublicKey(LOG.edSeed) },
  pq: { name: LOG.origin, publicKey: LOG.pq.publicKey },
});
stage(
  'K-01',
  'checkpoint',
  'a flipped byte in the checkpoint text',
  () => {
    const r = verifyCheckpoint(
      d.checkpoint.replace(/\n(\d+)\n/, (_m, n) => `\n${Number(n) + 1}\n`),
      LOG.origin,
      cpKeys(),
    );
    return r.ok ? 'ok' : r.code;
  },
  'ED_SIGNATURE_INVALID',
);
stage(
  'K-02',
  'checkpoint',
  'the post-quantum line is stripped',
  () => {
    const lines = d.checkpoint.trimEnd().split('\n');
    const r = verifyCheckpoint(`${lines.slice(0, -1).join('\n')}\n`, LOG.origin, cpKeys());
    return r.ok ? 'ok' : r.code;
  },
  'PQ_LINE_MISSING',
);
stage(
  'K-03',
  'checkpoint',
  'the Ed25519 line is stripped',
  () => {
    const lines = d.checkpoint.trimEnd().split('\n');
    const r = verifyCheckpoint(`${lines.slice(0, -2).join('\n')}\n${lines.at(-1)}\n`, LOG.origin, cpKeys());
    return r.ok ? 'ok' : r.code;
  },
  'ED_LINE_MISSING',
);
stage(
  'K-04',
  'checkpoint',
  'the checkpoint is for another log origin',
  () => {
    const r = verifyCheckpoint(d.checkpoint, 'legx.dev/log/other', cpKeys());
    return r.ok ? 'ok' : r.code;
  },
  'ORIGIN_MISMATCH',
);
stage(
  'K-05',
  'checkpoint',
  'a record is changed after the checkpoint: its inclusion proof fails',
  () => {
    const at = 2;
    const path = inclusionPath(at, d.leaves);
    const changed = d.leaves[at]!.slice();
    changed[0] = (changed[0] ?? 0) ^ 1;
    return verifyInclusion(changed, at, d.leaves.length, path, d.checkpointBody.rootHash) ? 'ok' : 'INCLUSION_FAILED';
  },
  'INCLUSION_FAILED',
);

// ---- identity: one person on both sides ----
let sameChipDeal: PaperDeal;
stage(
  'I-01',
  'identity',
  'one person on both sides: C_A equals C_B',
  async () => {
    sameChipDeal ??= await buildPaperDeal({ methodA: 'nfc-chip', sameChip: true, slots: d.S });
    const f = failing(sameChipDeal.input);
    return `${f[0]?.code}:${f[0]?.detail}|${f.map((x) => x.code)}`;
  },
  'IDS_DISTINCT:COMMITMENTS_EQUAL|IDS_DISTINCT',
);
let chipPolicyDeal: PaperDeal;
stage(
  'I-02',
  'identity',
  'a zero-knowledge attestation under a chip-only policy',
  async () => {
    chipPolicyDeal ??= await buildPaperDeal({ methodA: 'nfc-chip', policy: 'chip', slots: d.S });
    const i = structuredClone(chipPolicyDeal.input);
    i.records.passport.A = await chipPolicyDeal.passport('A', {
      method: 'zkpassport',
      checks: chipPolicyDeal.zkRelease,
    });
    const f = failing(i);
    return `${f[0]?.code}:${f[0]?.detail}`;
  },
  'PASSPORT_A_OK:METHOD_NOT_ALLOWED',
);
stage(
  'I-03',
  'identity',
  'both clients with chip passports pass the gate in the production profile',
  async () => {
    chipPolicyDeal ??= await buildPaperDeal({ methodA: 'nfc-chip', policy: 'chip', slots: d.S });
    const i = structuredClone(chipPolicyDeal.input);
    (i as { profile: string }).profile = 'production';
    const f = failing(i);
    return f.length === 0 ? 'ok' : `${f[0]?.code}:${f[0]?.detail}`;
  },
  'ok',
);

describe('E2E-P1-02 break one input at a time; the first failing check names it', () => {
  it('has at least 65 cases', () => {
    expect(cases.length).toBeGreaterThanOrEqual(65);
    expect(new Set(cases.map((c) => c.id)).size).toBe(cases.length);
  });
  it.each(cases.map((c) => [c.id, c.stage, c.what, c] as const))('%s [%s] %s', async (_id, _st, _what, c) => {
    const got = await c.run();
    expect(got).toBe(c.first);
    if (c.codes) expect(lastCodes).toEqual(c.codes);
  });
});

describe('E2E-P1-02 probes: what the gate does not bind (recorded as issues, pinned so a fix is noticed)', () => {
  it('E2E-3 (I-E2 fixed): SLOT_SETUP_OK refuses Ed25519 enrollment keys that are not the real holders', async () => {
    // The seal binds the holders' ML-DSA keys (pqKeyHash, OD-21); the slot key's test signatures bind their Ed25519
    // enrollment keys (testSignMessage), so three fresh keys that "sign" the DKG echo, with the real group key,
    // session, policy and test signatures copied, are refused.
    const S = d.S.A;
    const evil = [0, 1, 2].map((j) => ({ id: `evil/A/${j}/ed`, sk: new Uint8Array(32).fill(0xe0 + j) }));
    const i = structuredClone(d.input) as Mutable;
    i.records.keys = [
      ...i.records.keys,
      ...evil.map((e) => ({
        keyId: e.id,
        alg: 'ed25519' as const,
        publicKey: ed25519.getPublicKey(e.sk),
        validFrom: 1,
        logged: true,
      })),
    ];
    i.records.slotHolders.A = S.holders.map((h, j) => ({
      ed25519: (evil[j] as (typeof evil)[0]).id,
      mlDsa65: h.mlDsa65,
    })) as never;
    const data = structuredClone(S.dkgData) as Record<string, any>;
    const session = hexToBytes(data.session_id);
    const transcript = hexToBytes(data.transcript_hash);
    data.holder_sigs = evil.map((e, j) => ({
      key_id: e.id,
      sig: hex(
        ed25519.sign(frostMsgBytes({ session, kind: 'dkg-echo', from: j + 1, to: 0, fields: [transcript] }), e.sk),
      ),
    }));
    i.records.dkgCompleted.A = await d.event('frost.dkg.completed', data);
    expect(failing(i).map((f) => `${f.code}:${f.detail}`)).toEqual(['SLOT_SETUP_OK:A:TEST_SIGNATURE_INVALID']);
  });

  it('E2E-5 (I-E4 fixed, OD-29): one person with one chip passport on both sides fails IDS_DISTINCT, whatever the salts', async () => {
    const same = await buildPaperDeal({ methodA: 'nfc-chip', sameChip: 'other-salt', slots: d.S });
    expect(same.data.commitmentA).not.toBe(same.data.commitmentB);
    expect(same.chipA?.passport.dg1).toEqual(same.chipB.passport.dg1);
    expect(failing(same.input).map((f) => `${f.code}:${f.detail}`)).toEqual(['IDS_DISTINCT:IDENTIFIERS_EQUAL']);
  });

  it('KNOWN GAP E2E-4 (OD-2): the gate does not look at the scope, the domain or the bound value inside a zero-knowledge attestation', async () => {
    const i = structuredClone(d.input);
    i.records.onboarding.A = await d.onboarding('A', {
      checks: { ...d.zkOnboard, scope: 'legx/v1/another-deal', domain: 'evil.example' },
    });
    expect(failing(i)).toEqual([]);
    // the console's own check (checkZkResult) is what names them, see Z-01 and Z-06
  });
});

// =====================================================================================================================
// E2E-P1-03 an arbitrator recomputes everything from public data
// =====================================================================================================================

describe('E2E-P1-03 recompute from public data only', () => {
  it('the same seal, the same slot policies, the same bindings, the same signatures and the same gate result', () => {
    // The public bundle is plain JSON: nothing but what the ledger and the evidence log hold.
    const bundle = JSON.stringify({
      input: toBundle(d.input),
      checkpoint: d.checkpoint,
      leaves: d.leaves.map((l) => toBase64(l)),
      gate: toBase64(d.gate.envelopeBytes),
    });
    const b = JSON.parse(bundle) as { input: unknown; checkpoint: string; leaves: string[]; gate: string };
    const input = fromBundle(b.input) as ReleaseInput;
    const seal = dealSeal(input.deal.data);
    expect(hex(seal)).toBe(d.sealHex);
    expect(input.ledger.account.Domain).toBe(up(domain(hexToBytes(input.deal.data.contractRoot), seal)));
    // slot policies from the recorded roles
    const reg = (id: string) => input.records.keys.find((k) => k.keyId === id);
    for (const s of SLOT_NAMES) {
      const ev = JSON.parse(
        new TextDecoder().decode(
          fromBase64Strict(JSON.parse(new TextDecoder().decode(input.records.dkgCompleted[s])).payload) as Uint8Array,
        ),
      );
      const data = ev.predicate.data;
      expect(hex(slotPolicy(s, data.roles))).toBe(
        (input.deal.data as unknown as Record<string, string>)[`slotPolicy${s}`],
      );
      expect(data.group_pub).toBe(
        (input.deal.data as unknown as Record<string, string>)[
          { A: 'xPubA', B: 'xPubB', LA: 'lawyerPubA', LB: 'lawyerPubB' }[s]
        ],
      );
      // post-quantum binding recomputed from the registry
      const pqEv = JSON.parse(
        new TextDecoder().decode(
          fromBase64Strict(JSON.parse(new TextDecoder().decode(input.records.pqBound[s])).payload) as Uint8Array,
        ),
      );
      const bind = pqEv.predicate.data.binding;
      const holders = input.records.slotHolders[s].map((h) => ({
        keyId: h.mlDsa65,
        mlDsa65: reg(h.mlDsa65)?.publicKey as Uint8Array,
      }));
      expect(hex(pqKeyHash(holders.map((h) => h.mlDsa65) as [Uint8Array, Uint8Array, Uint8Array]))).toBe(
        (input.deal.data as unknown as Record<string, string>)[`pqKeyHash${s}`],
      );
      expect(
        verifyPqBinding(
          {
            dealSeal: seal,
            slotPub: hexToBytes(bind.slot_pub),
            pqKeyHash: hexToBytes(bind.pq_key_hash),
            holderSigs: bind.holder_sigs.map((h: any) => ({
              keyId: h.key_id,
              sig: fromBase64Strict(h.sig) as Uint8Array,
            })),
            crossSig: hexToBytes(bind.cross_sig),
          },
          { dealSeal: seal, slotPub: hexToBytes(bind.slot_pub), pqKeyHash: hexToBytes(bind.pq_key_hash) },
          holders as [(typeof holders)[0], (typeof holders)[0], (typeof holders)[0]],
          (p, m, sg) => verifyEd25519Strict(sg, m, p),
        ),
      ).toEqual({ ok: true });
    }
    // hybrid signatures on every stored envelope, from the registry rows alone
    for (const rec of [
      ...Object.values(input.records.passport),
      ...Object.values(input.records.onboarding),
      ...Object.values(input.records.opsBound),
      ...Object.values(input.records.pqBound),
      ...Object.values(input.records.dkgCompleted),
    ]) {
      expect(verifyHybrid(JSON.parse(new TextDecoder().decode(rec as Uint8Array)), reg, NOW).ok).toBe(true);
    }
    // the checkpoint lines and the inclusion of the gate record
    const cp = verifyCheckpoint(b.checkpoint, LOG.origin, cpKeys());
    expect(cp.ok).toBe(true);
    const leaves = b.leaves.map((l) => fromBase64Strict(l) as Uint8Array);
    if (cp.ok) expect(hex(cp.rootHash)).toBe(hex(verifyRoot(leaves)));
    // the zero-knowledge records: the stored proof set hashes to the recorded proof_sha256, and the trust record is complete
    const pass = JSON.parse(
      new TextDecoder().decode(
        fromBase64Strict(JSON.parse(new TextDecoder().decode(input.records.passport.A)).payload) as Uint8Array,
      ),
    );
    expect(hex(sha256(input.records.zkProof.A as Uint8Array))).toBe(pass.checks.proof_sha256);
    expect(checkTrustRecord(pass.checks.trust, 'demo')).toEqual({ ok: true });
    expect(hex(sha256(zkProofBytes(ZK.release)))).toBe(ZK.release.verification.proofSha256);
    // the gate, rerun on the bundle: the same findings, and the gate record verifies
    expect(checkRelease(input)).toEqual(d.findings);
    expect(
      verifyGatePassedRecord(fromBase64Strict(b.gate) as Uint8Array, {
        deal: input.deal,
        keys: input.records.keys,
        lawyerB: input.records.slotHolders.LB,
        at: NOW,
      }),
    ).toEqual({ ok: true });
  });
});
const verifyRoot = (leaves: Uint8Array[]) => mth(leaves);
const require_fs = (file: string) =>
  readFileSync(join(import.meta.dirname, '../../../tools/py-ref/vectors', `${file}.json`));

// =====================================================================================================================
// E2E-P1-04 no function reads the clock or the network
// =====================================================================================================================

describe('E2E-P1-04 Date.now, fetch and WebSocket stubbed to throw', () => {
  const saved = { now: Date.now, fetch: globalThis.fetch, ws: (globalThis as { WebSocket?: unknown }).WebSocket };
  afterAll(() => {
    Date.now = saved.now;
    globalThis.fetch = saved.fetch;
    (globalThis as { WebSocket?: unknown }).WebSocket = saved.ws;
  });
  it('a no-argument new Date() is never called either (the wall clock cannot leak in another way)', async () => {
    const RealDate = Date;
    const calls: string[] = [];
    Error.stackTraceLimit = 100;
    const Guarded = new Proxy(RealDate, {
      construct(target, args, nt) {
        if (args.length === 0) calls.push(new Error('new Date()').stack ?? 'new Date()');
        return Reflect.construct(target, args, nt);
      },
    });
    globalThis.Date = Guarded;
    try {
      const again = await buildPaperDeal({ slots: d.S });
      expect(again.findings.filter((f) => !f.ok)).toEqual([]);
      expect(checkRelease(again.input).every((f) => f.ok)).toBe(true);
      verifyCheckpoint(again.checkpoint, LOG.origin, cpKeys());
    } finally {
      globalThis.Date = RealDate;
    }
    // Only the code under test counts: the fixture PKI (packages/fixtures) stamps certificates with the clock.
    expect(calls.filter((c) => c.includes('/packages/core/src/'))).toEqual([]);
  });

  it('the whole deal, built again from nothing, still passes', async () => {
    const boom = (what: string) => () => {
      throw new Error(`${what} was called`);
    };
    Date.now = boom('Date.now');
    globalThis.fetch = boom('fetch') as never;
    (globalThis as { WebSocket?: unknown }).WebSocket = boom('WebSocket');
    let second: PaperDeal;
    try {
      second = await buildPaperDeal();
      expect(checkRelease(second.input).every((f) => f.ok)).toBe(true);
      expect(second.findings.filter((f) => !f.ok)).toEqual([]);
      expect(
        verifyGatePassedRecord(second.gate.envelopeBytes, {
          deal: second.input.deal,
          keys: second.input.records.keys,
          lawyerB: second.input.records.slotHolders.LB,
          at: NOW,
        }).ok,
      ).toBe(true);
      expect(verifyCheckpoint(second.checkpoint, LOG.origin, cpKeys()).ok).toBe(true);
    } finally {
      Date.now = saved.now;
      globalThis.fetch = saved.fetch;
      (globalThis as { WebSocket?: unknown }).WebSocket = saved.ws;
    }
    // @zkpassport/sdk is never loaded: the zero-knowledge results are recorded files
    expect(Object.keys(createRequire(import.meta.url).cache).filter((k) => k.includes('@zkpassport'))).toEqual([]);
    for (const dir of ['../src', './e2e']) {
      for (const f of readdirSync(join(import.meta.dirname, dir), { recursive: true, encoding: 'utf8' }).filter((x) =>
        x.endsWith('.ts'),
      )) {
        expect(readFileSync(join(import.meta.dirname, dir, f), 'utf8').includes("from '@zkpassport"), f).toBe(false);
      }
    }
  });
});

// =====================================================================================================================
// E2E-P1-05 / 06 / 07 refresh, recovery and repair in the middle of the deal
// =====================================================================================================================

async function refreshSlot(slotName: SlotName, participants = [1, 2, 3]) {
  const S = d.S[slotName];
  const ctx: RefreshContext = {
    ...S.k.ctx,
    sessionId: crypto.getRandomValues(new Uint8Array(32)),
    pub: S.pub,
    participants,
  };
  const starts = participants.map((p) =>
    refreshStart(ctx, p, S.share(p - 1), { signer: S.k.holders[p - 1]!.signer, cipher: xwing }),
  );
  const commits = starts.flatMap((x) => x.out);
  const states = starts.map((x) => x.state);
  const subs = [];
  for (const st of states)
    subs.push(
      ...(
        await refreshReceiveCommits(
          st,
          commits.filter((m) => m.from !== st.me),
        )
      ).out,
    );
  const results = [];
  for (const st of states)
    results.push(
      await refreshReceiveShares(
        st,
        subs.filter((m) => m.to === st.me),
      ),
    );
  return { ctx, results };
}

describe("E2E-P1-05 refresh client A's slot in the middle of the deal", () => {
  it('keeps the group key, xPubA and slotPolicyA; the refreshed slot signs; old and new shares do not combine; deletion statements decide COMPLETE', async () => {
    const S = d.S.A;
    const { ctx, results } = await refreshSlot('A');
    const pub = results[0]!.pub;
    const before = { pub: S.pubHex, policy: S.policy, seal: d.sealHex };
    expect(up(slotPubkey(pub))).toBe(before.pub);
    expect(d.data.xPubA).toBe(before.pub);
    expect(hex(slotPolicy('A', S.roles))).toBe(d.data.slotPolicyA);
    expect(pub.verifyingShares).not.toEqual(S.pub.verifyingShares);
    // the seal is a function of the sealed data only: unchanged
    expect(hex(dealSeal(d.data))).toBe(before.seal);

    // the refreshed slot signs a new presence statement (a fresh lawyer nonce) that the gate accepts in place of the old
    const freshNonce = h32(0x5a);
    const msg = presenceMsg(d.seal, 'A', hexToBytes(ANCHOR.ledger_hash), hexToBytes(freshNonce));
    const sessions = [0, 1].map((k) => SigningSession.open(results[k]!.share, pub, msg));
    const list = sessions.map((x) => x.commitment);
    const sig = aggregateChecked(
      pub,
      list,
      msg,
      Object.fromEntries(
        sessions.map((x, k) => [results[k]!.share.identifier, x.signShare(msg, list, () => ({ ok: true }))]),
      ),
    );
    expect(verifyEd25519Strict(sig, msg, hexToBytes(d.data.xPubA))).toBe(true);
    const i = structuredClone(d.input);
    i.records.passport.A = await d.passport('A', { lawyer_nonce: freshNonce, presence_sig: hex(sig) });
    i.records.zkProof.A = d.releaseProof(freshNonce); // a fresh release proof for the fresh presence (I-S-G3)
    expect(failing(i)).toEqual([]);
    expect(checkRelease(d.input)).toEqual(d.findings); // and the old records still pass

    // an old share with a new share does not combine; old shares still combine with each other until deleted
    const mixed = await codeOf(() => {
      const s = [SigningSession.open(S.share(0), pub, msg), SigningSession.open(results[1]!.share, pub, msg)];
      return s;
    });
    expect(mixed).toBe('SHARE_INVALID');
    expect(verifyEd25519Strict(S.sign(msg), msg, hexToBytes(d.data.xPubA))).toBe(true);

    // frost.refreshed: COMPLETE only with every remaining holder's deletion statement
    const st = S.k.holders.map((h, k) => deletionStatement(h.signer, ctx, k + 1, pub));
    expect(refreshedEvent(ctx, pub, st).status).toBe('COMPLETE');
    const some = refreshedEvent(ctx, pub, st.slice(0, 2));
    expect([some.status, some.missing]).toEqual(['INCOMPLETE', [3]]);
    expect(some.oldVerifyingShares).toEqual(S.pub.verifyingShares);
  });
});

describe("E2E-P1-06 recovery: client A's phone share is lost", () => {
  it('the second authenticator and the recovery agent sign after the 72-hour delay; one second early is refused', async () => {
    const S = d.S.A;
    const t0 = 1_900_000_000_000;
    const { state, notices } = recoveryStart({
      kind: 'client',
      slot: 'A',
      at: t0,
      proof: { identifier: ZK_IDENTIFIER, provedAt: t0 - PROOF_FRESH_MS + 1000 },
      onboardingIdentifier: ZK_IDENTIFIER,
      faceMatch: true,
    });
    expect(notices).toEqual(['old-device', 'lawyerA', 'lawyerB']);
    const early = (() => {
      try {
        recoveryAuthorize(state, t0 + RECOVERY_DELAY_MS - 1000);
        return 'NO_THROW';
      } catch (e) {
        return (e as RecoveryError).code;
      }
    })();
    expect(early).toBe('RECOVERY_DELAY');
    const authorized = recoveryAuthorize(state, t0 + RECOVERY_DELAY_MS);
    expect(authorized.records.map((r) => r.kind)).toEqual(['frost.recovery.requested', 'frost.recovery.authorized']);

    // holders 2 (second-authenticator, needs a user-verified approval) and 3 (recovery-agent) sign a presence message
    const nonce = h32(0x5b);
    const parts = [d.seal, utf8ToBytes('A'), hexToBytes(ANCHOR.ledger_hash), hexToBytes(nonce)];
    const msg = tupleHash('legx/passport-presence/v1', parts);
    const sessions = [1, 2].map((k) => SigningSession.open(S.share(k), S.pub, msg));
    const list = sessions.map((x) => x.commitment);
    const roleAt = (k: number) => S.roles[k] as 'second-authenticator';
    const sharesOut = Object.fromEntries(
      [1, 2].map((k, n) => [
        S.share(k).identifier,
        (sessions[n] as SigningSession).signShare(msg, list, (m) =>
          cosign({
            request: { kind: 'tagged', tag: 'legx/passport-presence/v1', parts },
            msg: m,
            deal: d.sealedDeal(d.seal),
            slot: 'A',
            role: roleAt(k),
            ...(k === 1 ? { approval: assertion(sha256(m)), approver: APPROVER } : {}),
          }),
        ),
      ]),
    );
    const sig = aggregateChecked(S.pub, list, msg, sharesOut);
    expect(verifyEd25519Strict(sig, msg, hexToBytes(d.data.xPubA))).toBe(true);
    // the evidence names the share holders that took part
    const participants = list.map((c) => S.roles[Number(idScalar(c.identifier)) - 1]);
    expect(participants).toEqual(['second-authenticator', 'recovery-agent']);
    const signed = recoverySigned(authorized, t0 + RECOVERY_DELAY_MS + 1, participants as never);
    expect(signed.records.at(-1)).toMatchObject({
      kind: 'frost.recovery.signed',
      detail: 'signed by second-authenticator,recovery-agent',
    });
    // without the user-verified approval the second authenticator refuses and no nonce is used
    const s2 = SigningSession.open(S.share(1), S.pub, msg);
    expect(
      await codeOf(() =>
        s2.signShare(msg, [s2.commitment, sessions[1]!.commitment], (m) =>
          cosign({
            request: { kind: 'tagged', tag: 'legx/passport-presence/v1', parts },
            msg: m,
            deal: d.sealedDeal(d.seal),
            slot: 'A',
            role: 'second-authenticator',
          }),
        ),
      ),
    ).toBe('MESSAGE_REFUSED');
    // the gate accepts the recovered signature as A's presence
    const i = structuredClone(d.input);
    i.records.passport.A = await d.passport('A', { lawyer_nonce: nonce, presence_sig: hex(sig) });
    i.records.zkProof.A = d.releaseProof(nonce);
    expect(failing(i)).toEqual([]);
  });
});

describe('E2E-P1-07 repair: a new device for client A rebuilds a share', () => {
  it("two holders rebuild holder 1's share; every pair that includes it signs under xPubA", () => {
    const S = d.S.A;
    const shares = [0, 1, 2].map((k) => S.share(k));
    const helpers = [2, 3];
    const dealt = helpers.map((h) => ({
      from: h,
      ...repairDelta(S.pub, helpers, h === 2 ? shares[1]! : shares[2]!, 1),
    }));
    const contributions = helpers.map((j) => {
      for (const x of dealt) checkDelta(j, x.from, x.deltas.get(j)!, x.commitments);
      return {
        from: j,
        sigma: repairSigma(dealt.map((x) => x.deltas.get(j)!)),
        commitments: dealt.find((x) => x.from === j)!.commitments,
      };
    });
    const repaired = repairFinish(S.pub, 1, contributions);
    expect(hex(repaired.signingShare)).toBe(hex(shares[0]!.signingShare));
    const msg = enc('repaired device signs');
    for (const other of [shares[1]!, shares[2]!]) {
      const ses = [repaired, other].map((sh) => SigningSession.open(sh, S.pub, msg));
      const list = ses.map((x) => x.commitment);
      const sig = aggregateChecked(
        S.pub,
        list,
        msg,
        Object.fromEntries(
          ses.map((x, k) => [[repaired, other][k]!.identifier, x.signShare(msg, list, () => ({ ok: true }))]),
        ),
      );
      expect(verifyEd25519Strict(sig, msg, hexToBytes(d.data.xPubA))).toBe(true);
    }
  });
});
