// Break-it (task 5.7): the release gate and the attestation binding (OD-21, OD-22, OD-29) and a ZK release proof
// that is not bound to the seal. Every test asserts the SECURE behaviour, so each one fails until its I-S-G* issue
// is fixed. They attack the real gate (`checkRelease`) on the complete valid world of task 1.12.
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ed25519 } from '../../../packages/core/node_modules/@noble/curves/ed25519.js';
import { sha256 } from '../../../packages/core/node_modules/@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '../../../packages/core/node_modules/@noble/hashes/utils.js';
import { verifyAttestation } from '../../../packages/core/src/attest.ts';
import { dealSeal, tupleHash } from '../../../packages/core/src/dealcore.ts';
import { frostMsgBytes } from '../../../packages/core/src/frost.ts';
import { nobleHybridSigner } from '../../../packages/core/src/pq.ts';
import { checkRelease, type ReleaseInput } from '../../../packages/core/src/releaseGate.ts';
import { CHIP_CHECKS, DEAL_ID, makeWorld, mutable, zkReleaseChecks } from '../../../packages/core/test/helpers/gate.ts';

const failing = (i: ReleaseInput) => checkRelease(i).filter((f) => !f.ok);
const finding = (i: ReleaseInput, code: string) => checkRelease(i).find((f) => f.code === code);

describe('I-S-G1 (OD-29 not implemented): IDS_DISTINCT ignores the deal-scoped distinct_tag', () => {
  // Source: build/DECISIONS.md OD-29; DESIGN.md 6.17 IDS_DISTINCT; IMPLEMENTATION 10.1 "one person on both sides"
  it('one chip passport on both sides (same DG1, two salts) is caught by distinct_tag', async () => {
    const w = await makeWorld({ methodA: 'nfc-chip', methodB: 'nfc-chip' });
    const dg1 = utf8ToBytes('P<UTOSAME<<PERSON<<<<<<<<<<<<<<<<<<<<<<<<<<<'); // one passport, both sides
    const tag = bytesToHex(tupleHash('legx/id-distinct/v1', [utf8ToBytes(DEAL_ID), sha256(dg1)]));
    const i = mutable(w.input);
    i.records.onboarding.A = await w.onboarding('A', { distinct_tag: tag });
    i.records.onboarding.B = await w.onboarding('B', { distinct_tag: tag });
    expect(finding(i, 'ONBOARDING_OK')?.ok).toBe(true); // OD-29 makes distinct_tag part of identity.onboarded
    expect(finding(i, 'IDS_DISTINCT')?.ok).toBe(false);
  });
});

describe('I-S-G2 (OD-21, confirms and widens I-E2): the Ed25519 half of a lawyer attestation is not bound', () => {
  // Source: build/DECISIONS.md OD-21; DESIGN.md 6.13 (hybrid: both halves must hold); RFC 9794 hybrid terminology
  // https://www.rfc-editor.org/rfc/rfc9794 ; draft-ietf-pquip-hybrid-signature-spectrums (non-separability)
  it('one ML-DSA key of slot LA plus a fresh attacker Ed25519 key passes PASSPORT_A_OK and the whole gate', async () => {
    const w = await makeWorld();
    const sk = new Uint8Array(32).fill(0xe7);
    const evilId = 'evil/LA/0/ed';
    const pq0 = w.S.LA.pq[0] as { secretKey: Uint8Array };
    const holder0 = w.S.LA.holders[0] as { ed25519: string; mlDsa65: string };
    w.lawyerSigner.A = nobleHybridSigner(
      { keyId: evilId as never, publicKey: ed25519.getPublicKey(sk), sign: async (m) => ed25519.sign(m, sk) },
      { keyId: holder0.mlDsa65 as never, secretKey: pq0.secretKey },
    );
    const i = mutable(w.input);
    i.records.keys.push({
      keyId: evilId,
      alg: 'ed25519',
      publicKey: ed25519.getPublicKey(sk),
      validFrom: 1,
      logged: true,
    });
    i.records.slotHolders.LA[0] = { ed25519: evilId, mlDsa65: holder0.mlDsa65 };
    // The attacker also echoes the DKG transcript with the fresh key, so SLOT_SETUP_OK agrees (I-E2).
    const dkg = structuredClone(w.S.LA.dkg) as { session_id: string; transcript_hash: string; holder_sigs: unknown[] };
    const echo = frostMsgBytes({
      session: hexToBytes(dkg.session_id),
      kind: 'dkg-echo',
      from: 1,
      to: 0,
      fields: [hexToBytes(dkg.transcript_hash)],
    });
    dkg.holder_sigs[0] = { key_id: evilId, sig: bytesToHex(ed25519.sign(echo, sk)) };
    i.records.dkgCompleted.LA = await w.event('frost.dkg.completed', dkg);
    i.records.passport.A = await w.passport('A');
    i.records.onboarding.A = await w.onboarding('A');
    expect(failing(i).map((f) => f.code)).toContain('PASSPORT_A_OK');
  });
});

describe('I-S-G3 (confirms I-2.9-e): the gate does not bind the stored ZK release proof to presenceMsg', () => {
  // Source: DESIGN.md 6.10 (release custom_data = hex(presenceMsg_side)), 6.15; IMPLEMENTATION SYS-A10, SYS-11
  it('a real recorded release proof of another deal (another presenceMsg) passes PASSPORT_A_OK', async () => {
    const w = await makeWorld();
    const replayed = readFileSync(new URL('../../../packages/zk/fixtures/sets/alice-deal2.json', import.meta.url));
    const i = mutable(w.input);
    i.records.zkProof.A = new Uint8Array(replayed);
    i.records.passport.A = await w.passport('A', {
      checks: { ...zkReleaseChecks('A'), proof_sha256: bytesToHex(sha256(replayed)) },
    });
    expect(finding(i, 'PASSPORT_A_OK')?.ok).toBe(false);
  });
});

describe('I-S-G4: ONBOARDING_OK never compares slot_pub with the sealed xPub of the side', () => {
  // Source: DESIGN.md 6.10 (onboarding custom_data binds slotPub_side), 6.17 ONBOARDING_OK
  it('an onboarding attestation for another slot key passes', async () => {
    const w = await makeWorld();
    const i = mutable(w.input);
    i.records.onboarding.A = await w.onboarding('A', { slot_pub: w.S.B.pubHex });
    expect(finding(i, 'ONBOARDING_OK')?.ok).toBe(false);
  });
});

describe('I-S-G5 (OD-22 not implemented): chip_auth_available is not part of the chip checks', () => {
  // Source: build/DECISIONS.md OD-22, OD-23; ICAO Doc 9303 Part 11 sections 6.1 (AA) and 6.2 (CA)
  // https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
  it('verifyAttestation reads chip_auth_available and refuses "none" when the chip supports AA or CA', async () => {
    const w = await makeWorld({ methodA: 'nfc-chip' });
    const run = async (checks: object) =>
      verifyAttestation({
        envelope: JSON.parse(new TextDecoder().decode(await w.passport('A', { checks }))),
        side: 'A',
        deal: { id: DEAL_ID, data: w.input.deal.data },
        sealedKeys: {
          lawyerKeyIds: {
            A: w.S.LA.holders.flatMap((h) => [h.ed25519, h.mlDsa65]),
            B: w.S.LB.holders.flatMap((h) => [h.ed25519, h.mlDsa65]),
          },
          registry: (id: string) => w.input.records.keys.find((k) => k.keyId === id),
        },
        ledgerLookup: (n: number) => [w.input.ledger, ...w.input.ledger.history].find((l) => l.index === n),
        now: w.input.ledger.closeTime,
        profile: 'production',
      } as never);
    expect(await run(CHIP_CHECKS)).toMatchObject({ ok: true }); // control: the harness accepts today's shape
    const honest = await run({ ...CHIP_CHECKS, chip_authentication: 'AA', chip_auth_available: true });
    expect(honest).toMatchObject({ ok: true });
    const cloned = await run({ ...CHIP_CHECKS, chip_authentication: 'none', chip_auth_available: true });
    expect(cloned.ok).toBe(false);
    expect(JSON.stringify(cloned)).toMatch(/CHIP_AUTH/);
  });
});

// Keeps the seal import honest: the world's seal is the one the gate recomputes.
it('control: the unmodified world passes every gate code', async () => {
  const w = await makeWorld();
  expect(bytesToHex(dealSeal(w.input.deal.data))).toBe(bytesToHex(w.seal));
  expect(failing(w.input)).toEqual([]);
});
