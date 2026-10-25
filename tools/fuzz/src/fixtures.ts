// Fixtures the fuzz targets build once: lawyer enrollment keys, a deal, signed attestations, hybrid checkpoints and a
// real three-holder DKG (also with a bad share, so there is a complaint). Test helpers of @legx/core are read, not changed.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { PublicDealData } from '@legx/contracts/deal';
import type { KeyId } from '@legx/contracts/values';
import { presenceMsg } from '@legx/core/attest';
import { dealSeal, tupleHash } from '@legx/core/dealcore';
import { type Envelope, pae } from '@legx/core/evidence';
import {
  type Directory,
  type EnrollmentSigner,
  enrollmentSigned,
  type FrostMsg,
  type Role,
  scalarBytes,
  u32,
} from '@legx/core/frost';
import {
  type DkgState,
  dkgReceiveEcho,
  dkgReceiveRound1,
  dkgReceiveRound2,
  dkgStart,
  readRound1,
  type ShareCipher,
} from '@legx/core/frostDkg';
import type { KeyRegistry, RegisteredKey } from '@legx/core/hybridEnvelope';
import { nobleHybridSigner, pqKeygen, toBase64 } from '@legx/core/pq';
import { type CheckpointKeys, signCheckpoint } from '@legx/core/pqCheckpoint';
import { buildSignedContractSeal, type ContractTerms, signContract } from '@legx/core/signedContract';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { encodeAccountID } from 'xrpl';
import { xwing } from '../../../packages/core/test/helpers/frost.ts';

export const ATTEST_TYPE = 'application/vnd.legx.attest+json;v=1';
export const EVENT_TYPE = 'application/vnd.legx.event+json;v=1';
const h32 = (n: number) => bytesToHex(new Uint8Array(32).fill(n));
const addr = (n: number) => encodeAccountID(new Uint8Array(20).fill(n));
const up = (b: Uint8Array) => bytesToHex(b).toUpperCase();

// ---------- hybrid lawyer keys and the attestation deal ----------

function lawyer(tag: string, n: number) {
  const edSk = new Uint8Array(32).fill(n);
  const pq = pqKeygen(new Uint8Array(32).fill(n + 1));
  const ed = `enroll:${tag}:ed` as KeyId;
  const ml = `enroll:${tag}:pq` as KeyId;
  const signer = nobleHybridSigner(
    { keyId: ed, publicKey: ed25519.getPublicKey(edSk), sign: async (m) => ed25519.sign(m, edSk) },
    { keyId: ml, secretKey: pq.secretKey },
  );
  const keys: Record<string, RegisteredKey> = {
    [ed]: { alg: 'ed25519', publicKey: ed25519.getPublicKey(edSk), validFrom: 1, logged: true, pair: tag },
    [ml]: { alg: 'ml-dsa-65', publicKey: pq.publicKey, validFrom: 1, logged: true, pair: tag },
  };
  return { ids: [ed, ml] as const, signer, keys };
}
export const LAWYER = { A: lawyer('LA', 0x41), B: lawyer('LB', 0x51) };
export const registry: KeyRegistry = (id) => LAWYER.A.keys[id] ?? LAWYER.B.keys[id];
export const sealedKeys = { lawyerKeyIds: { A: LAWYER.A.ids, B: LAWYER.B.ids }, registry };

const clientSk = { A: new Uint8Array(32).fill(0xa1), B: new Uint8Array(32).fill(0xb1) };
const xPub = (s: 'A' | 'B') => `ED${up(ed25519.getPublicKey(clientSk[s]))}`;
export const DEAL_ID = '0192f1a0-7b3c-7d4e-8f00-0000000000a1';
export const DEAL_DATA = {
  contractRoot: h32(1),
  signedContractSeal: h32(2),
  walletAddress: addr(0x10),
  xPubA: xPub('A'),
  xPubB: xPub('B'),
  commitmentA: h32(5),
  commitmentB: h32(6),
  idMethodA: 'zkpassport',
  idMethodB: 'nfc-chip',
  identityPolicy: 'zk-or-chip',
  lawyerPubA: `ED${h32(7).toUpperCase()}`,
  lawyerPubB: `ED${h32(8).toUpperCase()}`,
  lawyerCommitmentA: h32(9),
  lawyerCommitmentB: h32(10),
  lawyerOpsA: addr(0x11),
  lawyerOpsB: addr(0x12),
  releaserAccount: addr(0x12),
  slotPolicyA: h32(11),
  slotPolicyLA: h32(12),
  slotPolicyB: h32(13),
  slotPolicyLB: h32(14),
  pqKeyHashA: h32(15),
  pqKeyHashLA: h32(16),
  pqKeyHashB: h32(17),
  pqKeyHashLB: h32(18),
  signerAccounts: [addr(0x24), addr(0x21), addr(0x23), addr(0x22)],
  quorum: 4,
  payoutA: `${addr(0x31)}:0`,
  payoutB: `${addr(0x32)}:7`,
} as unknown as PublicDealData;
export const DEAL = { id: DEAL_ID, data: DEAL_DATA };
const SEAL = dealSeal(DEAL_DATA);

export const NOW = 800_000_000;
export const ANCHOR = { ledger_index: 90_000_000, ledger_hash: h32(0x77).toUpperCase() };
const ledger = new Map([[ANCHOR.ledger_index, { hash: ANCHOR.ledger_hash, closeTime: NOW - 60 }]]);
export const ledgerLookup = (i: number) => ledger.get(i);

export const TRUST = {
  chain_id: 1,
  block_number: 21_000_000,
  block_hash: `0x${h32(0x0b)}`,
  registry_address: `0x${'ab'.repeat(20)}`,
  root: `0x${h32(0x0c)}`,
  circuit_manifest_version: '0.40.1',
  vkey_hashes: [`0x${h32(0x0d)}`],
  identifier_type: 'SALTED',
  dev_mode: false,
};
const NONCE = h32(0x33);
/**
 * Side A's stored release proof set as the gate reads it (core `checkProofBinding`): one bind disclosure proof whose
 * public inputs 2 and 3 are the scope hashes of `legx.app` and `legx/v1/<dealId>`, committing hex(presenceMsg).
 */
const scopeField = (s: string) => `00${bytesToHex(sha256(utf8ToBytes(s)).slice(0, 31))}`;
export const ZK_PROOF = utf8ToBytes(
  JSON.stringify([
    {
      name: 'bind',
      proof: [
        h32(1),
        h32(0),
        scopeField('legx.app'),
        scopeField(`legx/v1/${DEAL_ID}`),
        h32(2),
        h32(0),
        h32(3),
        h32(0),
      ].join(''),
      committedInputs: {
        bind: {
          data: { custom_data: bytesToHex(presenceMsg(SEAL, 'A', hexToBytes(ANCHOR.ledger_hash), hexToBytes(NONCE))) },
        },
      },
    },
  ]),
);

export type Side = 'A' | 'B';
/** A valid attestation payload for the side (zkpassport for A, nfc-chip for B). */
export function attestPayload(side: Side): Record<string, unknown> {
  const zk = side === 'A';
  return {
    deal_id: DEAL_ID,
    contract_root: DEAL_DATA.contractRoot,
    deal_seal: bytesToHex(SEAL),
    side,
    commitment: side === 'A' ? DEAL_DATA.commitmentA : DEAL_DATA.commitmentB,
    ledger_anchor: ANCHOR,
    method: zk ? 'zkpassport' : 'nfc-chip',
    checks: zk
      ? {
          proof_verified: true,
          identifier_matches: true,
          bound_value_is_presence_msg: true,
          document_not_expired: true,
          face_match_passed: true,
          proof_sha256: bytesToHex(sha256(ZK_PROOF)),
          trust: TRUST,
        }
      : {
          sod_signature_valid: true,
          ds_cert_chains_to_csca: true,
          dg1_hash_in_sod: true,
          document_not_expired: true,
          commitment_opens: true,
          chip_authentication: 'AA',
          chip_auth_available: true,
        },
    presence_sig: bytesToHex(
      ed25519.sign(presenceMsg(SEAL, side, hexToBytes(ANCHOR.ledger_hash), hexToBytes(NONCE)), clientSk[side]),
    ),
    lawyer_nonce: NONCE,
    checked_by_role: `lawyer${side}`,
    sig_algs: ['ed25519', 'ml-dsa-65'],
  };
}

/** Signs a body with a lawyer's hybrid key, without the `sig_algs` policy check of `signHybrid`. */
export async function signEnvelope(payloadType: string, body: Uint8Array, by: Side): Promise<Envelope> {
  const h = await LAWYER[by].signer.signHybrid(pae(payloadType, body), 'legx/dsse/v1');
  return {
    payloadType,
    payload: toBase64(body),
    signatures: [
      { keyid: h.keyIds.ed25519, sig: toBase64(h.ed25519) },
      { keyid: h.keyIds.mlDsa65, sig: toBase64(h.mlDsa65) },
    ],
  };
}

// ---------- hybrid checkpoints ----------

export const ORIGIN = 'legx.dev/log/test';
const edSeed = new Uint8Array(32).fill(21);
const pqKey = ml_dsa44.keygen(new Uint8Array(32).fill(22));
export const CHECKPOINT_KEYS: CheckpointKeys = {
  ed: { name: ORIGIN, publicKey: ed25519.getPublicKey(edSeed) },
  pq: { name: ORIGIN, publicKey: pqKey.publicKey },
};
export const CHECKPOINT_SIGNERS = {
  ed: { name: ORIGIN, seed: edSeed },
  pq: { name: ORIGIN, secretKey: pqKey.secretKey },
};
export const CHECKPOINT_BODY = { origin: ORIGIN, treeSize: 13, rootHash: sha256(utf8ToBytes('root')) };
export const CHECKPOINT_NOTE = signCheckpoint(
  CHECKPOINT_BODY,
  CHECKPOINT_SIGNERS.ed,
  CHECKPOINT_SIGNERS.pq,
  814_000_000,
);

// ---------- a signed contract ----------

const edPub = (seed: Uint8Array) => `ED${up(ed25519.getPublicKey(seed))}`;
export async function signedContract() {
  const seedA = new Uint8Array(32).fill(0xa1);
  const seedB = new Uint8Array(32).fill(0xb2);
  const terms: ContractTerms = {
    contractRoot: new Uint8Array(32).fill(0x11),
    walletAddress: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
    lawyerPubA: edPub(seedA),
    lawyerPubB: edPub(seedB),
  };
  const sigLA = await signContract(async (m) => ed25519.sign(m, seedA), terms, 'LA');
  const sigLB = await signContract(async (m) => ed25519.sign(m, seedB), terms, 'LB');
  return { terms, ...buildSignedContractSeal(terms, { sigLA, sigLB }) };
}

// ---------- a deterministic DKG, and a DKG with one bad share ----------
// Everything but the AEAD ciphertexts of round 2 is derived from a label, so a crash input saved to the corpus
// (which names the session and signatures) replays against the same fixture in a later process.

function detRng(label: string) {
  let n = 0;
  return (len = 32): Uint8Array => {
    const out = new Uint8Array(len);
    for (let off = 0; off < len; off += 32)
      out.set(sha256(utf8ToBytes(`${label}:${n++}`)).subarray(0, Math.min(32, len - off)), off);
    return out;
  };
}
const ROLES: Role[] = ['phone', 'second-authenticator', 'recovery-agent'];
function detSetup(label: string) {
  const holders = ROLES.map((role, i) => {
    const secret = sha256(utf8ToBytes(`${label}:holder:${i}`));
    const signer: EnrollmentSigner = { sign: (m) => ed25519.sign(m, secret) };
    return {
      key: {
        holder: `A/${role}`,
        role,
        edPub: new Uint8Array([0xed, ...ed25519.getPublicKey(secret)]),
        deviceId: `A/${role}`,
      },
      signer,
    };
  });
  const ctx = {
    sessionId: sha256(utf8ToBytes(`${label}:session`)),
    slot: 'A' as const,
    holders: holders.map((h) => h.key),
  };
  const rng = detRng(label);
  const cipher: ShareCipher = { ...xwing, keygen: () => ml_kem768_x25519.keygen(rng(32)) };
  return { ctx, holders, rng, cipher };
}

export interface DkgFixture {
  readonly ctx: ReturnType<typeof detSetup>['ctx'];
  readonly signers: readonly EnrollmentSigner[];
  readonly round1: FrostMsg[];
  readonly echoes: FrostMsg[];
  readonly r2: FrostMsg[];
  /** States after the whole DKG; noble advances a package once, so these serve the "wrong state" paths only. */
  readonly states: DkgState[];
}
const noPin = () => {};

async function runDkg(label: string, tamperR2?: (m: FrostMsg, round1: FrostMsg[]) => Promise<FrostMsg>) {
  const { ctx, holders, rng, cipher } = detSetup(label);
  const starts = holders.map((h, i) => dkgStart(ctx, i + 1, { signer: h.signer, cipher, pinned: noPin, rng }));
  const round1 = starts.flatMap((x) => x.out);
  const states = starts.map((x) => x.state);
  const echoes = states.map(
    (st) =>
      dkgReceiveRound1(
        st,
        round1.filter((m) => m.from !== st.me),
      ).out[0] as FrostMsg,
  );
  const r2: FrostMsg[] = [];
  for (const st of states)
    r2.push(
      ...(
        await dkgReceiveEcho(
          st,
          echoes.filter((e) => e.from !== st.me),
        )
      ).out,
    );
  const sent = tamperR2 ? await Promise.all(r2.map((m) => tamperR2(m, round1))) : r2;
  const results = [];
  for (const st of states)
    results.push(
      await dkgReceiveRound2(
        st,
        sent.filter((m) => m.to === st.me),
      ),
    );
  return { ctx, holders, round1, echoes, r2: sent, states, results };
}

export async function dkgFixture(): Promise<DkgFixture> {
  const run = await runDkg('legx-fuzz-dkg');
  return {
    ctx: run.ctx,
    signers: run.holders.map((h) => h.signer),
    round1: run.round1,
    echoes: run.echoes,
    r2: run.r2,
    states: run.states,
  };
}

export interface ComplaintFixture {
  readonly ctx: ReturnType<typeof detSetup>['ctx'];
  readonly round1: FrostMsg[];
  /** Holder 2's complaint against holder 1, who sent a share that fails the Feldman check. */
  readonly complaint: FrostMsg;
  readonly signer2: EnrollmentSigner;
}
const COMPLAINT_FILE = join(import.meta.dirname, '..', 'fixtures', 'complaint.json');
const wire = (m: FrostMsg) => ({
  session: hex(m.session),
  kind: m.kind,
  from: m.from,
  to: m.to,
  fields: m.fields.map(hex),
  sig: hex(m.sig),
});
const unwire = (j: ReturnType<typeof wire>): FrostMsg => ({
  session: unhex(j.session),
  kind: j.kind,
  from: j.from,
  to: j.to,
  fields: j.fields.map(unhex),
  sig: unhex(j.sig),
});
const hex = (b: Uint8Array) => bytesToHex(b);
const unhex = (h: string) => hexToBytes(h);

/**
 * The complaint is made once and kept in `tools/fuzz/fixtures/complaint.json`: its ciphertext is random, and the saved
 * crash inputs name that exact ciphertext and its signature.
 */
export async function complaintFixture(): Promise<ComplaintFixture> {
  const label = 'legx-fuzz-complaint';
  const saved = existsSync(COMPLAINT_FILE);
  // Without the saved file, holder 1 sends holder 2 a share that fails the Feldman check, and holder 2 complains.
  const run = await runDkg(label, async (m, round1) => {
    if (saved || m.from !== 1 || m.to !== 2) return m;
    const { ctx, holders } = detSetup(label);
    const kemPub2 = readRound1(
      ctx,
      1,
      round1.filter((x) => x.from !== 1),
    ).get(2)?.kemPub as Uint8Array;
    const ct = await xwing.seal(kemPub2, r2Aad(ctx, 1, 2), scalarBytes(42n));
    return enrollmentSigned((holders[0] as { signer: EnrollmentSigner }).signer, { ...m, fields: [ct] });
  });
  if (!saved) {
    mkdirSync(join(COMPLAINT_FILE, '..'), { recursive: true });
    writeFileSync(COMPLAINT_FILE, `${JSON.stringify(wire(run.results[1]?.out[0] as FrostMsg), null, 2)}\n`);
  }
  const complaint = unwire(JSON.parse(readFileSync(COMPLAINT_FILE, 'utf8')));
  return {
    ctx: run.ctx,
    round1: run.round1,
    complaint,
    signer2: (run.holders[1] as { signer: EnrollmentSigner }).signer,
  };
}

const r2Aad = (ctx: Directory, from: number, to: number) =>
  tupleHash('legx/frost-dkg-r2/v1', [ctx.sessionId, u32(from), u32(to)]);

export { u32, xwing };
