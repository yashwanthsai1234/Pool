// Task 1.17: the zkpassport attestation path with recorded results, salt and disclosure boxes, identity changes and
// disputes (IMPLEMENTATION P1.17-02 to -07, -11 to -14, -19, -20; DESIGN 6.2, 6.10, 6.15). The attestation rules
// are task 1.9's verifyAttestation; these tests feed it the recorded trust records and proof sets.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { PublicDealData } from '@legx/contracts/deal';
import { PassportAttestation, type ZkVerification } from '@legx/contracts/records';
import type { KeyId } from '@legx/contracts/values';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { checkProofBinding, type Profile, presenceMsg, verifyAttestation } from '../src/attest.ts';
import { bytesToHex, dealSeal, passportCommitment } from '../src/dealcore.ts';
import { pae } from '../src/evidence.ts';
import type { RegisteredKey } from '../src/hybridEnvelope.ts';
import { nobleHybridSigner, PACKAGE_SUITES, pqKeygen, type SealedPackage, toBase64, XWING_SUITE } from '../src/pq.ts';
import {
  boxDigest,
  checkAgainstSeal,
  type Disclosure,
  disputeIdentity,
  identityChangeOutcome,
  identityChangePlan,
  openDisclosure,
  openSalt,
  publicProofSet,
  sealDisclosure,
  sealSalt,
  trustRecordOf,
  zkIdentityCommitment,
} from '../src/zkIdentity.ts';
import { proofSet } from './helpers/gate.ts';
import { zkSet } from './helpers/zkFixtures.ts';

type Json = Record<string, unknown>;
const EXAMPLES = join(import.meta.dirname, '../../contracts/examples');
const example = <T>(name: string): T[] => JSON.parse(readFileSync(join(EXAMPLES, `${name}.json`), 'utf8')) as T[];
const DEAL = example<PublicDealData>('PublicDealData')[0] as PublicDealData;

const release = zkSet('alice-release');
const onboarding = zkSet('alice-onboarding');
const SALT = new Uint8Array(32).fill(0x61);
const N = release.verification.uniqueIdentifier as string;
const C = bytesToHex(zkIdentityCommitment(SALT, N));
const STORED = utf8ToBytes(JSON.stringify(publicProofSet(release.proofs)));
const xwing = PACKAGE_SUITES[XWING_SUITE] as NonNullable<(typeof PACKAGE_SUITES)[string]>;
const code = (r: { ok: boolean; code?: string }) => (r.ok ? 'ok' : r.code);

// ---------- a side-A release attestation, signed the way task 1.9 verifies it ----------

const clientSk = new Uint8Array(32).fill(0xa1);
const edSk = new Uint8Array(32).fill(0x41);
const pq = pqKeygen(new Uint8Array(32).fill(0x42));
const KEY_IDS = ['enroll:LA:ed' as KeyId, 'enroll:LA:pq' as KeyId];
const signer = nobleHybridSigner(
  { keyId: KEY_IDS[0] as KeyId, publicKey: ed25519.getPublicKey(edSk), sign: async (m) => ed25519.sign(m, edSk) },
  { keyId: KEY_IDS[1] as KeyId, secretKey: pq.secretKey },
);
const KEYS: Record<string, RegisteredKey> = {
  [KEY_IDS[0] as string]: {
    alg: 'ed25519',
    publicKey: ed25519.getPublicKey(edSk),
    validFrom: 1,
    logged: true,
    pair: 'LA',
  },
  [KEY_IDS[1] as string]: { alg: 'ml-dsa-65', publicKey: pq.publicKey, validFrom: 1, logged: true, pair: 'LA' },
};
const NOW = 800_000_000;
const ANCHOR = { ledger_index: 90_000_000, ledger_hash: '77'.repeat(32).toUpperCase() };
const NONCE = onboarding.inputs.lawyerNonce;
const ZK_CHECKS = {
  proof_verified: true,
  identifier_matches: true,
  bound_value_is_presence_msg: true,
  document_not_expired: true,
  face_match_passed: true,
  proof_sha256: 'the bound set of this attestation',
  trust: trustRecordOf(release.verification),
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

const dealData = (over: Partial<PublicDealData> = {}): PublicDealData => ({
  ...DEAL,
  xPubA: `ED${bytesToHex(ed25519.getPublicKey(clientSk)).toUpperCase()}` as never,
  idMethodA: 'zkpassport',
  commitmentA: C as never,
  identityPolicy: 'zk-or-chip',
  ...over,
});

async function attest(
  o: { checks?: Json; method?: string; deal?: Partial<PublicDealData>; profile?: Profile; zkProof?: Uint8Array } = {},
) {
  const data = dealData(o.deal);
  const seal = dealSeal(data);
  const method = o.method ?? 'zkpassport';
  // The recorded proofs are bound to their fixture's seal, so the attestation stores a set bound to its own
  // presenceMsg (I-S-G3); the recorded set itself is checked against its own inputs below (checkProofBinding).
  const msg = presenceMsg(seal, 'A', hexToBytes(ANCHOR.ledger_hash), hexToBytes(NONCE));
  const bound = proofSet(onboarding.inputs.deal1, msg);
  const checks: Json = o.checks ?? (method === 'nfc-chip' ? CHIP_CHECKS : ZK_CHECKS);
  const body: Json = {
    deal_id: onboarding.inputs.deal1,
    contract_root: data.contractRoot,
    deal_seal: bytesToHex(seal),
    side: 'A',
    commitment: data.commitmentA,
    ledger_anchor: ANCHOR,
    method,
    checks:
      checks.proof_sha256 === ZK_CHECKS.proof_sha256 ? { ...checks, proof_sha256: bytesToHex(sha256(bound)) } : checks,
    presence_sig: bytesToHex(ed25519.sign(msg, clientSk)),
    lawyer_nonce: NONCE,
    checked_by_role: 'lawyerA',
    sig_algs: ['ed25519', 'ml-dsa-65'],
  };
  const bytes = utf8ToBytes(JSON.stringify(body));
  const payloadType = 'application/vnd.legx.attest+json;v=1';
  const h = await signer.signHybrid(pae(payloadType, bytes), 'legx/dsse/v1');
  const envelope = {
    payloadType,
    payload: toBase64(bytes),
    signatures: [
      { keyid: h.keyIds.ed25519, sig: toBase64(h.ed25519) },
      { keyid: h.keyIds.mlDsa65, sig: toBase64(h.mlDsa65) },
    ],
  };
  const result = verifyAttestation({
    envelope,
    side: 'A',
    deal: { id: onboarding.inputs.deal1, data },
    sealedKeys: { lawyerKeyIds: { A: KEY_IDS, B: [] }, registry: (id) => KEYS[id] },
    ledgerLookup: (i) => (i === ANCHOR.ledger_index ? { hash: ANCHOR.ledger_hash, closeTime: NOW - 60 } : undefined),
    now: NOW,
    profile: o.profile ?? 'demo',
    zkProof: 'zkProof' in o ? o.zkProof : bound,
  });
  return { body, result };
}

describe('P1.17-02 C_side in the deal seal', () => {
  const zkDeal = dealData();
  it('the seal input check passes with idMethod "zkpassport" and the zero-knowledge C_side', () => {
    expect(bytesToHex(dealSeal(zkDeal))).toMatch(/^[0-9a-f]{64}$/);
    expect(checkAgainstSeal(zkDeal, 'A', { method: 'zkpassport', commitment: C })).toEqual({ ok: true });
  });
  it('a chip attestation against a zero-knowledge C_side fails COMMITMENT_MISMATCH (the chip opening cannot give it)', async () => {
    const chipDeal = dealData({ idMethodA: 'nfc-chip' });
    const chipC = bytesToHex(passportCommitment(utf8ToBytes('DG1||SOD'), SALT));
    expect(chipC).not.toBe(C);
    expect(checkAgainstSeal(chipDeal, 'A', { method: 'nfc-chip', commitment: chipC })).toEqual({
      ok: false,
      code: 'COMMITMENT_MISMATCH',
    });
    // The chip path's commitment_opens is the lawyer's chipChecks result; it is false for a zero-knowledge C_side.
    const { result } = await attest({
      method: 'nfc-chip',
      deal: { idMethodA: 'nfc-chip' },
      checks: { ...CHIP_CHECKS, commitment_opens: false },
    });
    expect(code(result)).toBe('CHECK_FALSE:commitment_opens');
  });
});

describe('P1.17-03 to -06 the zkpassport path of verifyAttestation, on the recorded result', () => {
  it('P1.17-03 every check true passes, and the attestation parses under the contract', async () => {
    const { body, result } = await attest();
    expect(PassportAttestation.safeParse(body).success).toBe(true);
    expect(result).toEqual({ ok: true, method: 'zkpassport' });
    expect(bytesToHex(sha256(STORED))).toBe(release.verification.proofSha256);
  });

  it.each(['proof_verified', 'identifier_matches', 'bound_value_is_presence_msg', 'document_not_expired'])(
    'P1.17-04 %s false: CHECK_FALSE:<name>',
    async (name) => {
      expect(code((await attest({ checks: { ...ZK_CHECKS, [name]: false } })).result)).toBe(`CHECK_FALSE:${name}`);
    },
  );

  // OD-34: the honest result is recorded. Production needs true; the demo profile takes an explicit false of a dev-mode proof.
  it('P1.17-04 face_match_passed false (OD-34): refused in production, accepted in demo for a dev-mode record, never when absent', async () => {
    const checks = { ...ZK_CHECKS, face_match_passed: false };
    expect(code((await attest({ checks, profile: 'production' })).result)).toBe('CHECK_FALSE:face_match_passed');
    expect((await attest({ checks })).result).toEqual({ ok: true, method: 'zkpassport' });
    const real = { ...checks, trust: { ...(ZK_CHECKS.trust as object), dev_mode: false } };
    expect(code((await attest({ checks: real })).result)).toBe('CHECK_FALSE:face_match_passed');
    const { face_match_passed: _absent, ...gone } = ZK_CHECKS;
    expect(code((await attest({ checks: gone })).result)).toBe('CHECK_FALSE:face_match_passed');
  });

  // I-S-G3 on real recorded proofs: the scope sits in public input 3, the domain in 2, custom_data in the bind proof.
  it('a recorded release set is bound to its own deal and presenceMsg, and to nothing else', () => {
    const x = release.inputs;
    const msg = (seal: string) =>
      presenceMsg(hexToBytes(seal), 'A', hexToBytes(x.ledgerHash as string), hexToBytes(x.lawyerNonce as string));
    expect(checkProofBinding(STORED, x.deal1, msg(x.dealSeal1 as string))).toEqual({ ok: true });
    expect(checkProofBinding(STORED, x.deal1, msg('56'.repeat(32)))).toEqual({ ok: false, code: 'PROOF_NOT_BOUND' });
    expect(checkProofBinding(STORED, x.deal2 ?? 'another-deal', msg(x.dealSeal1 as string))).toEqual({
      ok: false,
      code: 'PROOF_WRONG_SCOPE',
    });
    const deal2 = zkSet('alice-deal2');
    const set2 = utf8ToBytes(JSON.stringify(publicProofSet(deal2.proofs)));
    const y = deal2.inputs;
    const msg2 = presenceMsg(
      hexToBytes(y.dealSeal2 as string),
      'A',
      hexToBytes(y.ledgerHash as string),
      hexToBytes(y.lawyerNonce as string),
    );
    expect(checkProofBinding(set2, y.deal2 as string, msg2)).toEqual({ ok: true });
    expect(checkProofBinding(set2, y.deal1 as string, msg2)).toEqual({ ok: false, code: 'PROOF_WRONG_SCOPE' });
    const other = zkSet('alice-other-domain');
    const setD = utf8ToBytes(JSON.stringify(publicProofSet(other.proofs)));
    expect(checkProofBinding(setD, other.request.scope.slice('legx/v1/'.length), new Uint8Array(32))).toEqual({
      ok: false,
      code: 'PROOF_WRONG_SCOPE',
    });
  });

  it('P1.17-05 proof_sha256 differs from the SHA-256 of the stored proof bytes: PROOF_HASH_MISMATCH', async () => {
    const other = utf8ToBytes(JSON.stringify(publicProofSet(zkSet('bob-release').proofs)));
    expect(code((await attest({ zkProof: other })).result)).toBe('PROOF_HASH_MISMATCH');
    expect(code((await attest({ zkProof: undefined })).result)).toBe('PROOF_MISSING');
  });

  const FIELDS = [
    'chain_id',
    'block_number',
    'block_hash',
    'registry_address',
    'root',
    'circuit_manifest_version',
    'vkey_hashes',
    'identifier_type',
    'dev_mode',
  ] as const;
  it.each(FIELDS)('P1.17-06 trust.%s missing, empty or not hex: ZK_RECORD_INCOMPLETE', async (f) => {
    for (const bad of [undefined, '', 'zz', []]) {
      const trust: Json = { ...ZK_CHECKS.trust, [f]: bad };
      if (bad === undefined) delete trust[f];
      const { result } = await attest({ checks: { ...ZK_CHECKS, trust } });
      expect(code(result), `${f}=${String(bad)}`).toBe('ZK_RECORD_INCOMPLETE');
    }
  });

  it('the recorded Sepolia dev-mode mock trust record is refused in production', async () => {
    expect(code((await attest({ profile: 'production' })).result)).toBe('DEVMODE_REFUSED');
  });
});

describe('P1.17-07 identity policy (with the sealed idMethod equal to the method)', () => {
  const table: [PublicDealData['identityPolicy'], string, string][] = [
    ['zk', 'zkpassport', 'ok'],
    ['zk', 'nfc-chip', 'METHOD_NOT_ALLOWED'],
    ['zk', 'face-scan', 'METHOD_UNKNOWN'],
    ['chip', 'zkpassport', 'METHOD_NOT_ALLOWED'],
    ['chip', 'nfc-chip', 'ok'],
    ['chip', 'face-scan', 'METHOD_UNKNOWN'],
    ['zk-or-chip', 'zkpassport', 'ok'],
    ['zk-or-chip', 'nfc-chip', 'ok'],
    ['zk-or-chip', 'face-scan', 'METHOD_UNKNOWN'],
  ];
  it.each(table)('%s with %s: %s', async (identityPolicy, method, expected) => {
    // dealSeal refuses a sealed idMethod the policy does not allow, so the seal holds an allowed one.
    const allowed = expected === 'ok';
    const sealed = allowed ? method : identityPolicy === 'chip' ? 'nfc-chip' : 'zkpassport';
    const idMethodB = identityPolicy === 'zk' ? 'zkpassport' : 'nfc-chip'; // side B's sealed method, also allowed
    const { result } = await attest({ method, deal: { identityPolicy, idMethodA: sealed as never, idMethodB } });
    expect(code(result)).toBe(expected);
  });
  it('"zk-or-chip" accepts a method only if it equals the sealed idMethod_side', async () => {
    expect(code((await attest({ method: 'nfc-chip' })).result)).toBe('METHOD_MISMATCH');
  });
});

describe('P1.17-12 a zero-knowledge attestation where the deal requires the chip', () => {
  it('fails METHOD_NOT_ALLOWED: only the chip path checks Active or Chip Authentication (DESIGN 10.1)', async () => {
    const { result } = await attest({ deal: { identityPolicy: 'chip', idMethodA: 'nfc-chip' } });
    expect(code(result)).toBe('METHOD_NOT_ALLOWED');
  });
});

describe("P1.17-13 the salt, sealed with X-Wing to the client's own lawyer", () => {
  const ctx = [onboarding.inputs.deal1, 'A'] as const;
  it('the lawyer opens it and recomputes C_side; another key, another deal or a flipped byte gives no output', async () => {
    const lawyer = await xwing.keygen();
    const other = await xwing.keygen();
    const box = await sealSalt(SALT, lawyer.publicKey, ...ctx);
    const opened = await openSalt(box, lawyer.secretKey, ...ctx);
    expect(opened.ok && bytesToHex(zkIdentityCommitment(opened.zkSalt32, N))).toBe(C);
    const fails: SealedPackage[] = [
      { ...box, ct: Uint8Array.from(box.ct, (b, i) => (i === 3 ? b ^ 1 : b)) },
      { ...box, enc: Uint8Array.from(box.enc, (b, i) => (i === 3 ? b ^ 1 : b)) },
      { ...box, suite: 'hpke-other-v1' },
    ];
    for (const f of fails)
      expect(await openSalt(f, lawyer.secretKey, ...ctx)).toEqual({ ok: false, code: 'OPEN_FAILED' });
    expect(await openSalt(box, other.secretKey, ...ctx)).toEqual({ ok: false, code: 'OPEN_FAILED' });
    expect(await openSalt(box, lawyer.secretKey, onboarding.inputs.deal2, 'A')).toEqual({
      ok: false,
      code: 'OPEN_FAILED',
    });
    expect(await openSalt(box, lawyer.secretKey, ctx[0], 'B')).toEqual({ ok: false, code: 'OPEN_FAILED' });
    await expect(sealSalt(SALT.slice(1), lawyer.publicKey, ...ctx)).rejects.toThrow(/32 bytes/);
  });

  it('a salt box never opens as a disclosure box', async () => {
    const lawyer = await xwing.keygen();
    const box = await sealSalt(SALT, lawyer.publicKey, ...ctx);
    expect(await openDisclosure(box, lawyer.secretKey, ...ctx)).toEqual({ ok: false, code: 'OPEN_FAILED' });
  });

  it('two clients with the same identifier in two deals get different C_side values (different salts)', () => {
    const other = new Uint8Array(32).fill(0x62);
    expect(bytesToHex(zkIdentityCommitment(other, N))).not.toBe(C);
  });
});

// The mock passport behind alice-onboarding (tools/record.ts): none of it may appear in a public record (I7).
const PII = ['ALICE', 'A1111111', '900101', '1990-01-01', 'ZKR'];
const ALICE_BYTES = [...utf8ToBytes('ALICE')].join(',');
const DISCLOSED: Disclosure = { firstname: 'ALICE', lastname: 'ONE', birthdate: '1990-01-01', nationality: 'ZKR' };

describe('P1.17-11 and P1.17-14 the raw passport never appears in a public record', () => {
  it("the disclosure opens for the client's own lawyer only", async () => {
    const lawyer = await xwing.keygen();
    const other = await xwing.keygen();
    const box = await sealDisclosure(DISCLOSED, lawyer.publicKey, onboarding.inputs.deal1, 'A');
    expect(await openDisclosure(box, lawyer.secretKey, onboarding.inputs.deal1, 'A')).toEqual({
      ok: true,
      facts: DISCLOSED,
    });
    expect(await openDisclosure(box, other.secretKey, onboarding.inputs.deal1, 'A')).toEqual({
      ok: false,
      code: 'OPEN_FAILED',
    });
  });

  it('the attestations, the identity.onboarded event, the stored results and the stored proof sets hold none of it', async () => {
    const lawyer = await xwing.keygen();
    const box = await sealDisclosure(DISCLOSED, lawyer.publicKey, onboarding.inputs.deal1, 'A');
    const onboarded = {
      ...(example<Record<string, unknown>>('IdentityOnboarded')[0] as Record<string, unknown>),
      commitment: C,
      disclosure_box_sha256: boxDigest(box),
      checks: {
        proof_verified: true,
        bound_value_matches: true,
        expiry_after_cancel_plus_30d: true,
        age_over_18: true,
        scope: onboarding.verification.scope,
        domain: onboarding.verification.domain,
        unique_identifier: onboarding.verification.uniqueIdentifier,
        proof_sha256: onboarding.verification.proofSha256,
        trust: trustRecordOf(onboarding.verification),
      },
    };
    const event = {
      type: 'identity.onboarded',
      data: { side: 'A', attestation: Buffer.from(JSON.stringify(onboarded)).toString('base64') },
    };
    const records: unknown[] = [
      (await attest()).body,
      onboarded,
      Buffer.from(event.data.attestation, 'base64').toString(),
      event,
    ];
    const sets = readdirSync(join(import.meta.dirname, '../../zk/fixtures/sets')).map((f) =>
      zkSet(f.replace('.json', '')),
    );
    for (const s of sets) records.push(s.verification, publicProofSet(s.proofs));
    for (const r of records) {
      const text = typeof r === 'string' ? r : JSON.stringify(r);
      for (const p of PII) expect(text, p).not.toContain(p);
      expect(text.replaceAll(' ', '')).not.toContain(ALICE_BYTES);
    }
  });

  it('the full onboarding proof set does hold the disclosed bytes, so publicProofSet is what gets stored', () => {
    expect(JSON.stringify(onboarding.proofs)).toContain(ALICE_BYTES);
    expect(publicProofSet(release.proofs)).toEqual(release.proofs);
  });
});

describe('P1.17-19 identity method changes mid-deal', () => {
  const zkDeal: PublicDealData = { ...DEAL, idMethodA: 'zkpassport', commitmentA: C as never };
  const renewedC = bytesToHex(zkIdentityCommitment(SALT, zkSet('bob-release').verification.uniqueIdentifier as string));
  const chipC = bytesToHex(passportCommitment(utf8ToBytes('DG1||SOD'), SALT));

  it.each([
    ['a renewed passport (new identifier)', 'zkpassport', renewedC, 'COMMITMENT_MISMATCH'],
    [
      'a circuit version that changes the identifier derivation',
      'zkpassport',
      bytesToHex(zkIdentityCommitment(SALT, `${N}0`)),
      'COMMITMENT_MISMATCH',
    ],
    ['a switch to the chip path', 'nfc-chip', chipC, 'METHOD_MISMATCH'],
  ] as const)(
    '%s is refused against the old seal and needs a 4-of-4 seal update',
    (_why, method, commitment, expected) => {
      expect(code(checkAgainstSeal(zkDeal, 'A', { method, commitment }))).toBe(expected);
      const plan = identityChangePlan(zkDeal, 'A', { method, commitment });
      expect(plan.changes).toEqual({ idMethodA: method, commitmentA: commitment });
      expect(plan.signers).toEqual(['A', 'LA', 'B', 'LB']);
      expect(plan.threshold).toBe(4);
      expect(plan.oldSeal).toBe(bytesToHex(dealSeal(zkDeal)));
      expect(plan.newSeal).not.toBe(plan.oldSeal);
      expect(checkAgainstSeal({ ...zkDeal, ...plan.changes }, 'A', { method, commitment })).toEqual({ ok: true });
    },
  );

  it('a switch the sealed policy does not allow cannot be planned', () => {
    expect(() =>
      identityChangePlan({ ...zkDeal, identityPolicy: 'zk' }, 'A', { method: 'nfc-chip', commitment: chipC }),
    ).toThrow(/not allowed/);
  });

  it('a slot that refuses to sign the update is recorded as a refusal (O9, a stall at release)', () => {
    expect(identityChangeOutcome({ A: 'signed', LA: 'signed', B: 'refused', LB: 'signed' })).toEqual({
      state: 'refused',
      refusedBy: ['B'],
      reason: 'O9',
    });
    expect(identityChangeOutcome({ A: 'signed', LA: 'signed' })).toEqual({ state: 'pending', waiting: ['B', 'LB'] });
    expect(identityChangeOutcome({ A: 'signed', LA: 'signed', B: 'signed', LB: 'signed' })).toEqual({
      state: 'applied',
    });
  });
});

describe('P1.17-20 disputes', () => {
  const ctx = { dealId: onboarding.inputs.deal1, side: 'A' as const };
  const bundle = async () => {
    const lawyer = await xwing.keygen();
    const disclosureBox = await sealDisclosure(DISCLOSED, lawyer.publicKey, ctx.dealId, ctx.side);
    const saltBox = await sealSalt(SALT, lawyer.publicKey, ctx.dealId, ctx.side);
    const onboardingRecord = {
      commitment: C,
      disclosure_box_sha256: boxDigest(disclosureBox),
      checks: { unique_identifier: N },
    };
    return { lawyer, b: { ...ctx, onboarding: onboardingRecord, disclosureBox, saltBox } };
  };

  it('an expired or renewed passport needs no new proof: the identity comes from the onboarding disclosure', async () => {
    const { lawyer, b } = await bundle();
    expect(await disputeIdentity(b, lawyer.secretKey)).toEqual({
      ok: true,
      identity: DISCLOSED,
      identifier: N,
      newProof: 'absent',
    });
  });

  it('a new proof with the same scope is optional extra evidence', async () => {
    const { lawyer, b } = await bundle();
    const same = await disputeIdentity({ ...b, newProof: release.verification }, lawyer.secretKey);
    const other = await disputeIdentity(
      { ...b, newProof: zkSet('alice-deal2').verification as ZkVerification },
      lawyer.secretKey,
    );
    expect([same.ok && same.newProof, other.ok && other.newProof]).toEqual(['matches', 'differs']);
  });

  it('a swapped disclosure box, a wrong key or a commitment that does not open fails', async () => {
    const { lawyer, b } = await bundle();
    const stranger = await xwing.keygen();
    const swapped = await sealDisclosure({ ...DISCLOSED, lastname: 'X' }, lawyer.publicKey, ctx.dealId, ctx.side);
    expect(await disputeIdentity({ ...b, disclosureBox: swapped }, lawyer.secretKey)).toEqual({
      ok: false,
      code: 'DISCLOSURE_HASH_MISMATCH',
    });
    expect(await disputeIdentity(b, stranger.secretKey)).toEqual({ ok: false, code: 'OPEN_FAILED' });
    const wrongC = { ...b, onboarding: { ...b.onboarding, commitment: '00'.repeat(32) } };
    expect(await disputeIdentity(wrongC, lawyer.secretKey)).toEqual({ ok: false, code: 'COMMITMENT_MISMATCH' });
  });
});

describe('core never loads the ZKPassport SDK', () => {
  it('no file in packages/core/src imports @zkpassport/*', () => {
    const src = join(import.meta.dirname, '../src');
    const files = readdirSync(src, { recursive: true, encoding: 'utf8' }).filter((f) => f.endsWith('.ts'));
    for (const f of files) expect(readFileSync(join(src, f), 'utf8'), f).not.toMatch(/from ['"]@zkpassport\//);
  });
});
