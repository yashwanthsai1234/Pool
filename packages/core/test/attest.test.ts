// Task 1.9: verifyAttestation and the onboarding attestation (DESIGN 6.15, 6.10, 6.17 ONBOARDING_OK).
// T-U-16f to l, P1.9-01, 02, 07 to 18, the replay, boundary and single-mutation properties.
import type { PublicDealData } from '@legx/contracts/deal';
import { IdentityOnboarded, PassportAttestation } from '@legx/contracts/records';
import type { KeyId } from '@legx/contracts/values';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import * as xrpl from 'xrpl';
import {
  type AttestationInput,
  attestConfig,
  checkFreshNonce,
  distinctTag,
  type OnboardingInput,
  presenceMsg,
  verifyAttestation,
  verifyOnboarding,
} from '../src/attest.ts';
import { dealSeal } from '../src/dealcore.ts';
import { type Envelope, pae } from '../src/evidence.ts';
import type { KeyRegistry, RegisteredKey } from '../src/hybridEnvelope.ts';
import { aaChallenge } from '../src/passport/activeAuth.ts';
import { nobleHybridSigner, pqKeygen, toBase64 } from '../src/pq.ts';
import { proofSet } from './helpers/gate.ts';
import { pyVector } from './helpers/pyref.ts';

const ATTEST = 'application/vnd.legx.attest+json;v=1';
const EVENT = 'application/vnd.legx.event+json;v=1';
const h32 = (n: number) => bytesToHex(new Uint8Array(32).fill(n));
const addr = (n: number) => xrpl.encodeAccountID(new Uint8Array(20).fill(n));
const fail = (code: string) => ({ ok: false, code });
type Side = 'A' | 'B';
type Json = Record<string, unknown>;

// ---------- the people: two clients (slot keys) and two lawyers (hybrid enrollment keys) ----------

const clientSk = { A: new Uint8Array(32).fill(0xa1), B: new Uint8Array(32).fill(0xb1) };
const xPub = (s: Side) => `ED${bytesToHex(ed25519.getPublicKey(clientSk[s])).toUpperCase()}`;

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
  return { ids: [ed, ml], signer, keys };
}
const LAWYER = { A: lawyer('LA', 0x41), B: lawyer('LB', 0x51) };
const registry: KeyRegistry = (id) => LAWYER.A.keys[id] ?? LAWYER.B.keys[id];
const sealedKeys = { lawyerKeyIds: { A: LAWYER.A.ids, B: LAWYER.B.ids }, registry };

// ---------- the deal ----------

const DEAL_ID = '0192f1a0-7b3c-7d4e-8f00-0000000000a1';
const OTHER_DEAL_ID = '0192f1a0-7b3c-7d4e-8f00-0000000000b2';
const DG1 = utf8ToBytes('P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<');
function dealData(over: Partial<PublicDealData> = {}): PublicDealData {
  return {
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
    ...over,
  } as unknown as PublicDealData;
}
const DEAL = { id: DEAL_ID, data: dealData() };
const SEAL = dealSeal(DEAL.data);

// ---------- the ledger ----------

const NOW = 800_000_000; // current validated close_time (Ripple epoch)
const ANCHOR = { ledger_index: 90_000_000, ledger_hash: h32(0x77).toUpperCase() };
const ledger = new Map([[ANCHOR.ledger_index, { hash: ANCHOR.ledger_hash, closeTime: NOW - 60 }]]);
const ledgerLookup = (i: number) => ledger.get(i);

// ---------- building attestations ----------

const NONCE = h32(0x33);
const TRUST = {
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
/** The stored release proof set a payload's own presenceMsg gives (I-S-G3); empty when the payload cannot give one. */
function proofFor(p: Json): Uint8Array {
  try {
    const a = p.ledger_anchor as { ledger_hash: string };
    const msg = presenceMsg(
      hexToBytes(String(p.deal_seal)),
      p.side as Side,
      hexToBytes(a.ledger_hash),
      hexToBytes(String(p.lawyer_nonce)),
    );
    return proofSet(String(p.deal_id), msg);
  } catch {
    return new Uint8Array();
  }
}
const AUTO = 'filled in by payload()';
const ZK_CHECKS = {
  proof_verified: true,
  identifier_matches: true,
  bound_value_is_presence_msg: true,
  document_not_expired: true,
  face_match_passed: true,
  proof_sha256: AUTO,
  trust: TRUST,
};
const CHIP_CHECKS = {
  sod_signature_valid: true,
  ds_cert_chains_to_csca: true,
  dg1_hash_in_sod: true,
  document_not_expired: true,
  commitment_opens: true,
  chip_authentication: 'AA',
  chip_auth_available: true,
};
const METHOD = { A: 'zkpassport', B: 'nfc-chip' } as const;

const presenceSig = (side: Side, nonce: string, anchorHash: string, seal = SEAL, sk = clientSk[side]) =>
  bytesToHex(ed25519.sign(presenceMsg(seal, side, hexToBytes(anchorHash), hexToBytes(nonce)), sk));

function payload(side: Side, over: Json = {}): Json {
  const method = METHOD[side];
  const p: Json = {
    deal_id: DEAL_ID,
    contract_root: DEAL.data.contractRoot,
    deal_seal: bytesToHex(SEAL),
    side,
    commitment: side === 'A' ? DEAL.data.commitmentA : DEAL.data.commitmentB,
    ledger_anchor: ANCHOR,
    method,
    checks: method === 'zkpassport' ? ZK_CHECKS : CHIP_CHECKS,
    presence_sig: presenceSig(side, NONCE, ANCHOR.ledger_hash),
    lawyer_nonce: NONCE,
    checked_by_role: `lawyer${side}`,
    sig_algs: ['ed25519', 'ml-dsa-65'],
    ...over,
  };
  const c = p.checks as Json;
  return c.proof_sha256 === AUTO ? { ...p, checks: { ...c, proof_sha256: bytesToHex(sha256(proofFor(p))) } } : p;
}
function signedPayload(env: Envelope): Json {
  try {
    return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(env.payload), (ch) => ch.charCodeAt(0))));
  } catch {
    return {}; // a hostile envelope: proofFor gives an empty set
  }
}

async function envelope(body: Json, by: Side, payloadType = ATTEST): Promise<Envelope> {
  const bytes = utf8ToBytes(JSON.stringify(body));
  const h = await LAWYER[by].signer.signHybrid(pae(payloadType, bytes), 'legx/dsse/v1');
  return {
    payloadType,
    payload: toBase64(bytes),
    signatures: [
      { keyid: h.keyIds.ed25519, sig: toBase64(h.ed25519) },
      { keyid: h.keyIds.mlDsa65, sig: toBase64(h.mlDsa65) },
    ],
  };
}

const input = (env: Envelope, side: Side, over: Partial<AttestationInput> = {}): AttestationInput => ({
  envelope: env,
  side,
  deal: DEAL,
  sealedKeys,
  ledgerLookup,
  now: NOW,
  zkProof: proofFor(signedPayload(env)),
  ...over,
});
const check = async (
  side: Side,
  over: Json = {},
  opts: { by?: Side; type?: string; input?: Partial<AttestationInput> } = {},
) => verifyAttestation(input(await envelope(payload(side, over), opts.by ?? side, opts.type), side, opts.input));

describe('the good attestations', () => {
  it('pass for both methods, and the payloads satisfy the contracts schema', async () => {
    for (const side of ['A', 'B'] as const) {
      expect(await check(side)).toEqual({ ok: true, method: METHOD[side] });
      expect(PassportAttestation.safeParse(payload(side)).success).toBe(true);
    }
  });
});

describe('T-U-16f to l: the shared rules', () => {
  it('T-U-16f: a commitment that is not the sealed C_side fails COMMITMENT_MISMATCH', async () => {
    expect(await check('B', { commitment: h32(0x99) })).toEqual(fail('COMMITMENT_MISMATCH'));
    expect(await check('B', { commitment: DEAL.data.commitmentA })).toEqual(fail('COMMITMENT_MISMATCH'));
  });

  it("T-U-16g: signed by the other side's lawyer fails WRONG_SIGNER", async () => {
    expect(await check('A', {}, { by: 'B' })).toEqual(fail('WRONG_SIGNER'));
    expect(await check('B', {}, { by: 'A' })).toEqual(fail('WRONG_SIGNER'));
    expect(await check('A', { checked_by_role: 'lawyerB' })).toEqual(fail('WRONG_SIGNER'));
    // Both signatures must be by one pair of the client's own lawyer: lawyer A's Ed25519 key with lawyer B's ML-DSA
    // key is refused by the envelope already (I-S-P1).
    const [edA] = (await envelope(payload('A'), 'A')).signatures;
    const [, mlB] = (await envelope(payload('A'), 'B')).signatures;
    const mixed = { ...(await envelope(payload('A'), 'A')), signatures: [edA, mlB] } as Envelope;
    expect(await verifyAttestation(input(mixed, 'A'))).toEqual(fail('ENVELOPE_INVALID:PAIR_MISMATCH'));
  });

  it('T-U-16h: a missing presence signature fails PRESENCE_MISSING', async () => {
    const body = payload('A');
    delete body.presence_sig;
    expect(await verifyAttestation(input(await envelope(body, 'A'), 'A'))).toEqual(fail('PRESENCE_MISSING'));
    expect(await check('A', { presence_sig: '' })).toEqual(fail('PRESENCE_MISSING'));
  });

  it('T-U-16i: a presence signature by a different key fails PRESENCE_INVALID', async () => {
    const other = presenceSig('A', NONCE, ANCHOR.ledger_hash, SEAL, new Uint8Array(32).fill(9));
    expect(await check('A', { presence_sig: other })).toEqual(fail('PRESENCE_INVALID'));
    const clientB = presenceSig('A', NONCE, ANCHOR.ledger_hash, SEAL, clientSk.B);
    expect(await check('A', { presence_sig: clientB })).toEqual(fail('PRESENCE_INVALID'));
    expect(await check('A', { presence_sig: 'zz'.repeat(64) })).toEqual(fail('PRESENCE_INVALID'));
  });

  it('T-U-16j: deal_id, contract_root or deal_seal of another deal fails WRONG_DEAL', async () => {
    expect(await check('A', { deal_id: OTHER_DEAL_ID })).toEqual(fail('WRONG_DEAL'));
    expect(await check('A', { contract_root: h32(0x42) })).toEqual(fail('WRONG_DEAL'));
    expect(await check('A', { deal_seal: h32(0x43) })).toEqual(fail('WRONG_DEAL'));
  });

  it('replay: an attestation from deal X presented in deal Y with the same people fails', async () => {
    const env = await envelope(payload('A'), 'A');
    const dealY = { id: OTHER_DEAL_ID, data: dealData({ contractRoot: h32(0x44) as never }) };
    expect(await verifyAttestation(input(env, 'A', { deal: dealY }))).toEqual(fail('WRONG_DEAL'));
    const sameRootOtherSeal = { id: DEAL_ID, data: dealData({ payoutB: `${addr(0x32)}:8` as never }) };
    expect(await verifyAttestation(input(env, 'A', { deal: sameRootOtherSeal }))).toEqual(fail('WRONG_DEAL'));
  });

  it('T-U-16k and P1.9-13: an anchor exactly 1 h old passes; 1 h + 1 s fails STALE', async () => {
    const env = await envelope(payload('A'), 'A');
    const at = (age: number) => () => ({ hash: ANCHOR.ledger_hash, closeTime: NOW - age });
    expect((await verifyAttestation(input(env, 'A', { ledgerLookup: at(3600) }))).ok).toBe(true);
    expect(await verifyAttestation(input(env, 'A', { ledgerLookup: at(3601) }))).toEqual(fail('STALE'));
    expect(await verifyAttestation(input(env, 'A', { ledgerLookup: at(-1) }))).toEqual(fail('STALE')); // after "now"
  });

  it('P1.9-13: a configured 24 h limit is accepted and applied; above 24 h is refused when built', async () => {
    const env = await envelope(payload('A'), 'A');
    const at = (age: number) => () => ({ hash: ANCHOR.ledger_hash, closeTime: NOW - age });
    const config = attestConfig({ maxAgeSeconds: 86_400 });
    expect((await verifyAttestation(input(env, 'A', { ledgerLookup: at(86_400), config }))).ok).toBe(true);
    expect(await verifyAttestation(input(env, 'A', { ledgerLookup: at(86_401), config }))).toEqual(fail('STALE'));
    expect(() => attestConfig({ maxAgeSeconds: 86_401 })).toThrow('FRESHNESS_LIMIT_TOO_HIGH');
    for (const bad of [0, -1, 1.5, Number.NaN]) {
      expect(() => attestConfig({ maxAgeSeconds: bad })).toThrow('FRESHNESS_LIMIT_INVALID');
    }
    expect(attestConfig().maxAgeSeconds).toBe(3600);
  });

  it('T-U-16l: an anchor hash that differs from the ledger at that index fails ANCHOR_MISMATCH', async () => {
    const hash = h32(0x78).toUpperCase(); // a valid presence signature, but over a ledger hash the ledger does not have
    const over = { ledger_anchor: { ...ANCHOR, ledger_hash: hash }, presence_sig: presenceSig('A', NONCE, hash) };
    expect(await check('A', over)).toEqual(fail('ANCHOR_MISMATCH'));
    const unknown = { ledger_index: ANCHOR.ledger_index + 1, ledger_hash: ANCHOR.ledger_hash };
    expect(await check('A', { ledger_anchor: unknown })).toEqual(fail('ANCHOR_UNKNOWN'));
  });

  it('a different side than the one the gate asks for fails WRONG_SIDE', async () => {
    // Signer and role fit side B (a key directory that lists lawyer A's keys for B), but the payload says side A.
    const env = await envelope(payload('A', { checked_by_role: 'lawyerB' }), 'A');
    const keys = { ...sealedKeys, lawyerKeyIds: { A: [], B: LAWYER.A.ids } };
    expect(await verifyAttestation(input(env, 'B', { sealedKeys: keys }))).toEqual(fail('WRONG_SIDE'));
  });
});

describe('P1.9-01, 02, 07 to 12, 17: envelope, method and checks', () => {
  it('P1.9-01: the event payloadType fails WRONG_PAYLOAD_TYPE', async () => {
    expect(await check('A', {}, { type: EVENT })).toEqual(fail('WRONG_PAYLOAD_TYPE'));
  });

  it('a stripped, swapped or forged envelope signature fails ENVELOPE_INVALID', async () => {
    const env = await envelope(payload('A'), 'A');
    const [ed, ml] = env.signatures;
    if (!ed || !ml) throw new Error('two signatures expected');
    expect(await verifyAttestation(input({ ...env, signatures: [ed] }, 'A'))).toEqual(
      fail('ENVELOPE_INVALID:PQ_SIGNATURE_MISSING'),
    );
    const body = toBase64(utf8ToBytes(JSON.stringify(payload('A', { side: 'A', lawyer_nonce: h32(0x34) }))));
    expect(await verifyAttestation(input({ ...env, payload: body }, 'A'))).toEqual(
      fail('ENVELOPE_INVALID:ED_SIGNATURE_INVALID'),
    );
  });

  it('P1.9-02: each check field set to false fails CHECK_FALSE:<name>', async () => {
    for (const name of [
      'proof_verified',
      'identifier_matches',
      'bound_value_is_presence_msg',
      'document_not_expired',
      'face_match_passed',
    ]) {
      expect(await check('A', { checks: { ...ZK_CHECKS, [name]: false } })).toEqual(fail(`CHECK_FALSE:${name}`));
    }
    for (const name of [
      'sod_signature_valid',
      'ds_cert_chains_to_csca',
      'dg1_hash_in_sod',
      'document_not_expired',
      'commitment_opens',
    ]) {
      expect(await check('B', { checks: { ...CHIP_CHECKS, [name]: false } })).toEqual(fail(`CHECK_FALSE:${name}`));
    }
    expect(await check('B', { checks: { ...CHIP_CHECKS, face_match: false } })).toEqual(fail('CHECK_FALSE:face_match'));
    expect((await check('B', { checks: { ...CHIP_CHECKS, face_match: true } })).ok).toBe(true);
  });

  it('P1.9-07: an unknown method fails METHOD_UNKNOWN', async () => {
    for (const method of ['chip', 'ZKPASSPORT', '', 7, null]) {
      expect(await check('A', { method })).toEqual(fail('METHOD_UNKNOWN'));
    }
  });

  it('P1.9-08: a method the sealed identityPolicy does not allow fails METHOD_NOT_ALLOWED', async () => {
    // The seal itself refuses an idMethod its policy does not allow (task 1.6), so the attestation's method differs.
    const zkOnly = { id: DEAL_ID, data: dealData({ identityPolicy: 'zk', idMethodB: 'zkpassport' }) };
    const chipOnly = { id: DEAL_ID, data: dealData({ identityPolicy: 'chip', idMethodA: 'nfc-chip' }) };
    const run = async (side: Side, deal: typeof DEAL) => {
      const seal = dealSeal(deal.data);
      const over = { deal_seal: bytesToHex(seal), presence_sig: presenceSig(side, NONCE, ANCHOR.ledger_hash, seal) };
      return verifyAttestation(input(await envelope(payload(side, over), side), side, { deal }));
    };
    expect(await run('B', zkOnly)).toEqual(fail('METHOD_NOT_ALLOWED'));
    expect(await run('A', chipOnly)).toEqual(fail('METHOD_NOT_ALLOWED'));
    const both = { id: DEAL_ID, data: dealData({ idMethodA: 'nfc-chip' }) };
    expect(await run('A', both)).toEqual(fail('METHOD_MISMATCH'));
  });

  it('P1.9-09: a method that differs from the sealed idMethod_side fails METHOD_MISMATCH', async () => {
    expect(await check('A', { method: 'nfc-chip', checks: CHIP_CHECKS })).toEqual(fail('METHOD_MISMATCH'));
    expect(await check('B', { method: 'zkpassport', checks: ZK_CHECKS })).toEqual(fail('METHOD_MISMATCH'));
  });

  it('P1.9-10: a checks object of the other shape fails CHECKS_SHAPE_WRONG', async () => {
    expect(await check('A', { checks: CHIP_CHECKS })).toEqual(fail('CHECKS_SHAPE_WRONG'));
    expect(await check('B', { checks: ZK_CHECKS })).toEqual(fail('CHECKS_SHAPE_WRONG'));
    expect(await check('B', { checks: { ...CHIP_CHECKS, proof_verified: true } })).toEqual(fail('CHECKS_SHAPE_WRONG'));
    expect(await check('B', { checks: { ...CHIP_CHECKS, chip_authentication: 'PACE' } })).toEqual(
      fail('CHECKS_SHAPE_WRONG'),
    );
    expect(await check('B', { checks: { ...CHIP_CHECKS, commitment_opens: 'true' } })).toEqual(
      fail('CHECKS_SHAPE_WRONG'),
    );
    expect(await check('B', { checks: [] })).toEqual(fail('CHECKS_SHAPE_WRONG'));
  });

  it('P1.9-11: a zkpassport attestation needs no chip field and is not held to the chip rules', async () => {
    const r = await check('A');
    expect(r).toEqual({ ok: true, method: 'zkpassport' });
    expect(Object.keys(ZK_CHECKS)).not.toContain('chip_authentication');
  });

  it('P1.9-12: the presence signature is checked strictly under the sealed client slot key, for both methods', async () => {
    for (const side of ['A', 'B'] as const) {
      expect((await check(side)).ok).toBe(true);
      const byLawyerKey = presenceSig(
        side,
        NONCE,
        ANCHOR.ledger_hash,
        SEAL,
        new Uint8Array(32).fill(side === 'A' ? 0x41 : 0x51),
      );
      expect(await check(side, { presence_sig: byLawyerKey })).toEqual(fail('PRESENCE_INVALID'));
    }
    // A ZIP-215-only signature (identity key forgery) is not an issue here: the key is the sealed slot key. A
    // non-canonical S (S + L) must still fail under the strict rule.
    const sig = hexToBytes(presenceSig('A', NONCE, ANCHOR.ledger_hash));
    const L = 2n ** 252n + 27742317777372353535851937790883648493n;
    const s = BigInt(`0x${bytesToHex(sig.slice(32).reverse())}`) + L;
    const sPlusL = hexToBytes(s.toString(16).padStart(64, '0')).reverse();
    expect(await check('A', { presence_sig: bytesToHex(new Uint8Array([...sig.slice(0, 32), ...sPlusL])) })).toEqual(
      fail('PRESENCE_INVALID'),
    );
  });

  it('P1.9-17: face_match_passed false or absent fails CHECK_FALSE:face_match_passed', async () => {
    const { face_match_passed: _, ...absent } = ZK_CHECKS;
    expect(await check('A', { checks: absent })).toEqual(fail('CHECK_FALSE:face_match_passed'));
    expect(await check('A', { checks: { ...ZK_CHECKS, face_match_passed: false } })).toEqual(
      fail('CHECK_FALSE:face_match_passed'),
    );
  });
});

describe('zkpassport: trust record and proof hash (the proof verification itself is task 1.17)', () => {
  it('production refuses Sepolia, a mock identifier type and dev_mode; demo accepts them', async () => {
    const cases = [
      [{ chain_id: 11155111 }, 'SEPOLIA_REFUSED'],
      [{ identifier_type: 'SALTED_MOCK' }, 'MOCK_IDENTIFIER_REFUSED'],
      [{ identifier_type: 'NON_SALTED_MOCK' }, 'MOCK_IDENTIFIER_REFUSED'],
      [{ dev_mode: true }, 'DEVMODE_REFUSED'],
    ] as const;
    for (const [t, code] of cases) {
      const over = { checks: { ...ZK_CHECKS, trust: { ...TRUST, ...t } } };
      expect(await check('A', over)).toEqual(fail(code));
      expect(await check('A', over, { input: { profile: 'production' } })).toEqual(fail(code));
      expect((await check('A', over, { input: { profile: 'demo' } })).ok).toBe(true);
    }
  });

  it('an incomplete or malformed trust record fails ZK_RECORD_INCOMPLETE', async () => {
    const bad: Json[] = [
      { chain_id: undefined },
      { block_hash: '0x12' },
      { registry_address: `0x${'AB'.repeat(20)}` },
      { root: '' },
      { circuit_manifest_version: 'v1' },
      { vkey_hashes: [] },
      { vkey_hashes: ['nothex'] },
      { identifier_type: 'OTHER' },
      { dev_mode: 'false' },
      { block_number: -1 },
      { extra: 1 },
    ];
    for (const t of bad) {
      const trust = JSON.parse(JSON.stringify({ ...TRUST, ...t }));
      expect(await check('A', { checks: { ...ZK_CHECKS, trust } }), JSON.stringify(t)).toEqual(
        fail('ZK_RECORD_INCOMPLETE'),
      );
    }
    const { trust: _, ...noTrust } = ZK_CHECKS;
    expect(await check('A', { checks: noTrust })).toEqual(fail('ZK_RECORD_INCOMPLETE'));
    expect(await check('A', { checks: { ...ZK_CHECKS, proof_sha256: 'abc' } })).toEqual(fail('ZK_RECORD_INCOMPLETE'));
  });

  it('an invalid sealed deal is refused, not trusted', async () => {
    const env = await envelope(payload('A'), 'A');
    const broken = { id: DEAL_ID, data: dealData({ releaserAccount: addr(0x13) as never }) };
    expect(await verifyAttestation(input(env, 'A', { deal: broken }))).toEqual(fail('DEAL_INVALID'));
  });

  it('proof_sha256 must equal SHA-256 of the proof stored in the evidence log', async () => {
    expect(await check('A', {}, { input: { zkProof: utf8ToBytes('another proof') } })).toEqual(
      fail('PROOF_HASH_MISMATCH'),
    );
    expect(await check('A', {}, { input: { zkProof: undefined } })).toEqual(fail('PROOF_MISSING'));
  });

  // OD-22 (I-S-G5): a chip with DG14 or DG15 must have run chip authentication.
  it('chip_auth_available is required, and "none" is refused when it is true', async () => {
    const chip = (c: Json) => check('B', { checks: { ...CHIP_CHECKS, ...c } });
    expect(await chip({ chip_authentication: 'none', chip_auth_available: true })).toEqual(fail('CHIP_AUTH_REQUIRED'));
    expect(await chip({ chip_authentication: 'none', chip_auth_available: false })).toEqual({
      ok: true,
      method: 'nfc-chip',
    });
    expect(await chip({ chip_authentication: 'CA', chip_auth_available: true })).toEqual({
      ok: true,
      method: 'nfc-chip',
    });
    expect(await chip({ chip_auth_available: 'yes' })).toEqual(fail('CHECKS_SHAPE_WRONG'));
    const { chip_auth_available: _, ...absent } = CHIP_CHECKS;
    expect(await check('B', { checks: absent })).toEqual(fail('CHECKS_SHAPE_WRONG'));
  });

  // I-S-G3: the stored set must be this deal's release proof for this presenceMsg.
  it('a proof set for another presenceMsg, another scope or domain, or an unreadable one is refused', async () => {
    const msg = presenceMsg(SEAL, 'A', hexToBytes(ANCHOR.ledger_hash), hexToBytes(NONCE));
    const withProof = async (proof: Uint8Array) =>
      check('A', { checks: { ...ZK_CHECKS, proof_sha256: bytesToHex(sha256(proof)) } }, { input: { zkProof: proof } });
    expect(await withProof(proofSet(DEAL_ID, msg))).toEqual({ ok: true, method: 'zkpassport' });
    const otherMsg = presenceMsg(SEAL, 'A', hexToBytes(ANCHOR.ledger_hash), hexToBytes(h32(0x34)));
    expect(await withProof(proofSet(DEAL_ID, otherMsg))).toEqual(fail('PROOF_NOT_BOUND'));
    expect(await withProof(proofSet(OTHER_DEAL_ID, msg))).toEqual(fail('PROOF_WRONG_SCOPE'));
    expect(await withProof(proofSet(DEAL_ID, msg, 'evil.example'))).toEqual(fail('PROOF_WRONG_SCOPE'));
    expect(await withProof(utf8ToBytes('{"not":"a list"}'))).toEqual(fail('PROOF_UNREADABLE'));
    expect(await withProof(utf8ToBytes('[]'))).toEqual(fail('PROOF_NOT_BOUND'));
    const short = utf8ToBytes(JSON.stringify([{ proof: 'ab', committedInputs: {} }]));
    expect(await withProof(short)).toEqual(fail('PROOF_UNREADABLE'));
    const set = JSON.parse(new TextDecoder().decode(proofSet(DEAL_ID, msg)));
    expect(await withProof(utf8ToBytes(JSON.stringify([...set, ...set])))).toEqual(fail('PROOF_NOT_BOUND'));
  });
});

describe('P1.9-14 to P1.9-16: presenceMsg, the single-use nonce and the AA challenge', () => {
  const v = pyVector('presence', 'presenceMsg');
  const args = [
    hexToBytes(v.inputs.dealSeal ?? ''),
    'B',
    hexToBytes(v.inputs.ledgerHash ?? ''),
    hexToBytes(v.inputs.nonce ?? ''),
  ] as const;

  it('P1.9-14: presenceMsg equals the Python golden vector', () => {
    expect(bytesToHex(presenceMsg(...args))).toBe(v.output);
  });

  it('P1.9-14: a lawyerNonce that is not 32 bytes is refused (NONCE_LENGTH)', async () => {
    for (const n of [31, 33, 0])
      expect(() => presenceMsg(args[0], 'B', args[2], new Uint8Array(n))).toThrow('NONCE_LENGTH');
    expect(await check('A', { lawyer_nonce: NONCE.slice(2) })).toEqual(fail('NONCE_LENGTH'));
    expect(await check('A', { lawyer_nonce: `${NONCE}00` })).toEqual(fail('NONCE_LENGTH'));
  });

  it('P1.9-14: a presence signature over a presenceMsg with another nonce fails PRESENCE_INVALID', async () => {
    expect(await check('A', { presence_sig: presenceSig('A', h32(0x34), ANCHOR.ledger_hash) })).toEqual(
      fail('PRESENCE_INVALID'),
    );
    expect(await check('A', { lawyer_nonce: h32(0x34) })).toEqual(fail('PRESENCE_INVALID'));
  });

  it('P1.9-15: checkFreshNonce refuses a nonce already used; a new one passes', () => {
    const used = new Set([NONCE]);
    expect(checkFreshNonce(hexToBytes(NONCE), used)).toEqual(fail('NONCE_REUSED'));
    expect(checkFreshNonce(hexToBytes(h32(0x34)), used)).toEqual({ ok: true });
    expect(checkFreshNonce(new Uint8Array(31), used)).toEqual(fail('NONCE_LENGTH'));
  });

  it('P1.9-16: the AA challenge is the first 8 bytes of presenceMsg', () => {
    expect(bytesToHex(aaChallenge(presenceMsg(...args)))).toBe(v.output.slice(0, 16));
  });
});

describe('P1.9-18: the onboarding attestation (identity.onboarded)', () => {
  const onboarding = (side: Side, over: Json = {}): Json => {
    const method = METHOD[side];
    return {
      deal_id: DEAL_ID,
      contract_root: DEAL.data.contractRoot,
      side,
      slot_pub: xPub(side),
      commitment: side === 'A' ? DEAL.data.commitmentA : DEAL.data.commitmentB,
      disclosure_box_sha256: h32(0x61),
      distinct_tag: bytesToHex(distinctTag(DEAL_ID, method === 'zkpassport' ? utf8ToBytes('123456789') : sha256(DG1))),
      checked_by_role: `lawyer${side}`,
      sig_algs: ['ed25519', 'ml-dsa-65'],
      method,
      checks:
        method === 'zkpassport'
          ? {
              proof_verified: true,
              bound_value_matches: true,
              expiry_after_cancel_plus_30d: true,
              age_over_18: true,
              scope: `legx/v1/${DEAL_ID}`,
              domain: 'legx.app',
              unique_identifier: '123456789',
              proof_sha256: h32(0x62),
              trust: TRUST,
            }
          : CHIP_CHECKS,
      ...over,
    };
  };
  const run = async (side: Side, over: Json = {}, by: Side = side, extra: Partial<OnboardingInput> = {}) =>
    verifyOnboarding({
      envelope: await envelope(onboarding(side, over), by),
      side,
      deal: DEAL,
      sealedKeys,
      now: NOW,
      ...extra,
    });

  it('good onboarding attestations pass for both methods and satisfy the contracts schema', async () => {
    for (const side of ['A', 'B'] as const) {
      expect(await run(side)).toEqual({ ok: true, method: METHOD[side] });
      expect(IdentityOnboarded.safeParse(onboarding(side)).success).toBe(true);
    }
  });

  // OD-29 (I-S-G1), I-S-G4: the tag is required and, for zkpassport, follows from the signed identifier; slot_pub is
  // the sealed client slot key.
  it('distinct_tag is required, and a zkpassport tag must follow from unique_identifier', async () => {
    const { distinct_tag: _, ...noTag } = onboarding('A');
    expect(
      await verifyOnboarding({ envelope: await envelope(noTag, 'A'), side: 'A', deal: DEAL, sealedKeys, now: NOW }),
    ).toEqual(fail('PAYLOAD_MALFORMED'));
    expect(await run('A', { distinct_tag: 'zz' })).toEqual(fail('PAYLOAD_MALFORMED'));
    expect(await run('A', { distinct_tag: h32(0x63) })).toEqual(fail('DISTINCT_TAG_MISMATCH'));
    expect(await run('B', { distinct_tag: h32(0x63) })).toEqual({ ok: true, method: 'nfc-chip' }); // trusted (OD-2)
  });
  it('the distinct_tag recipe matches the Python reference (OD-29)', () => {
    const v = pyVector<{ dealId: string; x: string }>('identity', 'distinctTag');
    expect(bytesToHex(distinctTag(v.inputs.dealId, hexToBytes(v.inputs.x)))).toBe(v.output);
  });
  it('a slot_pub other than the sealed xPub of the side fails SLOT_PUB_MISMATCH', async () => {
    expect(await run('A', { slot_pub: xPub('B') })).toEqual(fail('SLOT_PUB_MISMATCH'));
  });

  it("the other side's lawyer fails WRONG_SIGNER", async () => {
    expect(await run('A', {}, 'B')).toEqual(fail('WRONG_SIGNER'));
  });

  it('a deal field that differs fails WRONG_DEAL', async () => {
    expect(await run('A', { deal_id: OTHER_DEAL_ID })).toEqual(fail('WRONG_DEAL'));
    expect(await run('A', { contract_root: h32(0x45) })).toEqual(fail('WRONG_DEAL'));
  });

  it('a method that differs from the sealed idMethod_side fails METHOD_MISMATCH', async () => {
    expect(await run('A', { method: 'nfc-chip', checks: CHIP_CHECKS })).toEqual(fail('METHOD_MISMATCH'));
  });

  it('a commitment other than the sealed C_side, a false check, or a production-refused trust record fails', async () => {
    expect(await run('B', { commitment: h32(0x63) })).toEqual(fail('COMMITMENT_MISMATCH'));
    expect(await run('B', { checks: { ...CHIP_CHECKS, commitment_opens: false } })).toEqual(
      fail('CHECK_FALSE:commitment_opens'),
    );
    const sepolia = { ...(onboarding('A').checks as Json), trust: { ...TRUST, chain_id: 11155111 } };
    expect(await run('A', { checks: sepolia })).toEqual(fail('SEPOLIA_REFUSED'));
    expect((await run('A', { checks: sepolia }, 'A', { profile: 'demo' })).ok).toBe(true);
    expect(await run('A', { checks: { ...(onboarding('A').checks as Json), age_over_18: false } })).toEqual(
      fail('CHECK_FALSE:age_over_18'),
    );
  });
});

describe('property: random valid inputs pass; any single mutation fails with exactly its code', () => {
  /** `nowFor(anchorCloseTime)` replaces the current close_time for the freshness mutation. */
  type Mutation = { code: string; apply: (b: Json, side: Side) => Json; nowFor?: (anchorClose: number) => number };
  const MUTATIONS: Record<string, Mutation> = {
    deal_id: { code: 'WRONG_DEAL', apply: (b) => ({ ...b, deal_id: OTHER_DEAL_ID }) },
    contract_root: { code: 'WRONG_DEAL', apply: (b) => ({ ...b, contract_root: h32(0x46) }) },
    deal_seal: { code: 'WRONG_DEAL', apply: (b) => ({ ...b, deal_seal: h32(0x47) }) },
    side: { code: 'WRONG_SIDE', apply: (b, s) => ({ ...b, side: s === 'A' ? 'B' : 'A' }) },
    commitment: { code: 'COMMITMENT_MISMATCH', apply: (b) => ({ ...b, commitment: h32(0x48) }) },
    anchorHash: {
      code: 'ANCHOR_MISMATCH', // the client signed presence over a ledger hash the ledger does not have at that index
      apply: (b, s) => {
        const hash = h32(0x49).toUpperCase();
        const presence_sig = presenceSig(s, String(b.lawyer_nonce), hash);
        return { ...b, ledger_anchor: { ...(b.ledger_anchor as Json), ledger_hash: hash }, presence_sig };
      },
    },
    anchorIndex: {
      code: 'ANCHOR_UNKNOWN',
      apply: (b) => ({ ...b, ledger_anchor: { ...(b.ledger_anchor as Json), ledger_index: 1 } }),
    },
    nonce: { code: 'PRESENCE_INVALID', apply: (b) => ({ ...b, lawyer_nonce: h32(0x4a) }) },
    presence: { code: 'PRESENCE_MISSING', apply: ({ presence_sig: _, ...b }) => b },
    role: { code: 'WRONG_SIGNER', apply: (b, s) => ({ ...b, checked_by_role: s === 'A' ? 'lawyerB' : 'lawyerA' }) },
    method: { code: 'METHOD_UNKNOWN', apply: (b) => ({ ...b, method: 'passport' }) },
    extraField: { code: 'PAYLOAD_MALFORMED', apply: (b) => ({ ...b, note: 'x' }) },
    checkFalse: {
      code: 'CHECK_FALSE:document_not_expired',
      apply: (b) => ({ ...b, checks: { ...(b.checks as Json), document_not_expired: false } }),
    },
    stale: { code: 'STALE', apply: (b) => b, nowFor: (close) => close + 3601 },
  };

  it('holds for random nonces, sides and anchors', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom<Side>('A', 'B'),
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        fc.integer({ min: 2, max: 4_000_000_000 }),
        fc.integer({ min: 0, max: 3600 }),
        fc.constantFrom(...Object.keys(MUTATIONS)),
        async (side, nonceBytes, index, age, name) => {
          const nonce = bytesToHex(nonceBytes);
          const anchorHash = bytesToHex(sha256(nonceBytes)).toUpperCase();
          const lookup = (i: number) => (i === index ? { hash: anchorHash, closeTime: NOW - age } : undefined);
          const good = payload(side, {
            lawyer_nonce: nonce,
            ledger_anchor: { ledger_index: index, ledger_hash: anchorHash },
            presence_sig: presenceSig(side, nonce, anchorHash),
          });
          expect(PassportAttestation.safeParse(good).success).toBe(true); // differential with the contracts schema
          expect(await verifyAttestation(input(await envelope(good, side), side, { ledgerLookup: lookup }))).toEqual({
            ok: true,
            method: METHOD[side],
          });
          const m = MUTATIONS[name] as Mutation;
          const now = m.nowFor ? m.nowFor(NOW - age) : NOW;
          const bad = await envelope(m.apply(good, side), side);
          expect(await verifyAttestation(input(bad, side, { ledgerLookup: lookup, now }))).toEqual(fail(m.code));
        },
      ),
      { numRuns: 40 },
    );
  }, 60_000); // two ML-DSA-65 signatures per run

  it('hostile payloads never throw', async () => {
    await fc.assert(
      fc.asyncProperty(fc.jsonValue(), async (junk) => {
        const r = await verifyAttestation(input(await envelope({ junk } as Json, 'A'), 'A'));
        expect(r.ok).toBe(false);
      }),
      { numRuns: 30 },
    );
    const env = await envelope(payload('A'), 'A');
    for (const e of [null, {}, { ...env, signatures: 'x' }, { ...env, payload: '!!' }] as unknown as Envelope[]) {
      expect((await verifyAttestation(input(e, 'A'))).ok).toBe(false);
    }
  });
});
