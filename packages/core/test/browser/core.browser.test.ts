// OD-27 / I-17: every @legx/core module loads in a real browser and the Node-free paths work: the FROST allow-list on a
// gate record, a WebAuthn approval, a transparency-log receipt, and passport Active Authentication (RSA) and passive auth.
// Source: https://vitest.dev/guide/browser/
import { ed25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { describe, expect, it } from 'vitest';
import { normalizeBarNumber } from '../../src/bar.ts';
import { createLog, verifyReceipt } from '../../src/checkpoint.ts';
import { mth, tupleHash } from '../../src/dealcore.ts';
import { escrowFinishFee } from '../../src/fees.ts';
import { type SlotName, slotPubkey } from '../../src/frost.ts';
import { approvalCheck, messageAllowed, type SealedDeal } from '../../src/frostRules.ts';
import { verifyConsistency } from '../../src/merkle.ts';
import { verifyActiveAuth } from '../../src/passport/activeAuth.ts';
import { passiveAuth } from '../../src/passport/passiveAuth.ts';
import type { CheckpointKeys } from '../../src/pqCheckpoint.ts';
import vectors from './passport-vector.json' with { type: 'json' };

// Vite's glob import (the vite/client types are not part of the core tsconfig).
declare global {
  interface ImportMeta {
    glob(pattern: string, options: { eager: true }): Record<string, unknown>;
  }
}
const modules = import.meta.glob('../../src/**/*.ts', { eager: true });
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const b64url = (b: Uint8Array) => b64(b).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');

describe('every core module loads in the browser', () => {
  it('imports without a Node global', () => {
    expect(Object.keys(modules).length).toBeGreaterThan(20);
    expect(typeof (globalThis as { Buffer?: unknown }).Buffer).toBe('undefined');
    expect(typeof (globalThis as { process?: unknown }).process).toBe('undefined');
  });
});

describe('small pure modules', () => {
  it('fees, bar, tuple hash, merkle', () => {
    expect(escrowFinishFee(10, 0, 2)).toBeGreaterThan(0);
    expect(normalizeBarNumber(' ab-12 ')).toBeTypeOf('string');
    expect(tupleHash('legx/test/v1', [utf8ToBytes('a')])).toHaveLength(32);
    const leaves = [1, 2, 3].map((i) => utf8ToBytes(`l${i}`));
    expect(mth(leaves)).toHaveLength(32);
    expect(verifyConsistency).toBeTypeOf('function');
  });
});

describe('FROST allow-list (frostRules)', () => {
  const slots: SlotName[] = ['A', 'B', 'LA', 'LB'];
  const slotPubs = Object.fromEntries(slots.map((s) => [s, ed25519.getPublicKey(randomBytes(32))])) as Record<
    SlotName,
    Uint8Array
  >;
  const deal: SealedDeal = {
    walletAddress: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
    contractRoot: randomBytes(32),
    dealSeal: randomBytes(32),
    payoutA: { account: 'rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY' },
    payoutB: { account: 'rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn' },
    exitAmountDrops: '1000000',
    maxFeeDrops: '250000',
    slotPubs,
  };
  const gate = (kind: string) => {
    const st = {
      subject: [{ name: 'deal:x', digest: { sha256: bytesToHex(deal.contractRoot) } }],
      predicate: { kind },
    };
    return utf8ToBytes(
      JSON.stringify({
        payloadType: 'application/vnd.legx.event+json;v=1',
        payload: b64(utf8ToBytes(JSON.stringify(st))),
        signatures: [],
      }),
    );
  };

  it('allows a gate record for this deal on slot LB, and refuses other kinds, slots and junk', () => {
    expect(slotPubkey).toBeTypeOf('function');
    const ok = gate('release.gate.passed');
    expect(messageAllowed({ kind: 'gate-record', envelope: ok }, sha256(ok), deal, 'LB')).toEqual({ ok: true });
    expect(messageAllowed({ kind: 'gate-record', envelope: ok }, sha256(ok), deal, 'LA').ok).toBe(false);
    const other = gate('release.performed');
    expect(messageAllowed({ kind: 'gate-record', envelope: other }, sha256(other), deal, 'LB').ok).toBe(false);
    const junk = utf8ToBytes('{');
    expect(messageAllowed({ kind: 'gate-record', envelope: junk }, sha256(junk), deal, 'LB').ok).toBe(false);
  });

  it('accepts a user-verified WebAuthn approval whose challenge is the base64url message hash', () => {
    const key = p256.utils.randomSecretKey();
    const approver = { p256Pub: p256.getPublicKey(key), rpId: 'legx.example' };
    const msg = sha256(utf8ToBytes('exit message'));
    const authenticatorData = new Uint8Array([...sha256(utf8ToBytes(approver.rpId)), 0x05, 0, 0, 0, 1]);
    const clientDataJSON = utf8ToBytes(
      JSON.stringify({ type: 'webauthn.get', challenge: b64url(msg), origin: 'https://legx.example' }),
    );
    const signature = p256.sign(new Uint8Array([...authenticatorData, ...sha256(clientDataJSON)]), key, {
      format: 'der',
    });
    expect(approvalCheck({ authenticatorData, clientDataJSON, signature }, msg, approver)).toEqual({ ok: true });
  });
});

describe('transparency-log receipt (checkpoint)', () => {
  it('verifies every leaf of a small log with the hex inclusion path', async () => {
    const origin = 'legx.dev/log/test';
    const edSeed = new Uint8Array(32).fill(31);
    const pq = ml_dsa44.keygen(new Uint8Array(32).fill(32));
    const log = createLog({
      origin,
      ed: { name: origin, seed: edSeed },
      pq: { name: origin, secretKey: pq.secretKey },
      closeTime: () => 814_000_000,
    });
    const keys: CheckpointKeys = {
      ed: { name: origin, publicKey: ed25519.getPublicKey(edSeed) },
      pq: { name: origin, publicKey: pq.publicKey },
    };
    const leaves = [0, 1, 2, 3, 4].map((i) => utf8ToBytes(`envelope-${i}`));
    for (const l of leaves) await log.add(l);
    const cp = await log.checkpoint();
    for (const [i, leaf] of leaves.entries()) {
      const path = await log.inclusionProof(i, leaves.length);
      expect(verifyReceipt({ leaf, index: i, path, note: cp.note }, origin, keys).ok).toBe(true);
    }
  });
});

describe('passport (RSA Active Authentication, passive authentication)', () => {
  const ripple = Date.parse('2027-06-01T12:00:00Z') / 1000 - 946_684_800;
  for (const [alg, v] of Object.entries(vectors)) {
    it(`${alg} PKI: passive auth passes and the RSA chip answer verifies`, async () => {
      const dg15 = hexToBytes(v.dg15);
      const challenge = hexToBytes(v.challenge);
      const signature = hexToBytes(v.signature);
      const dg14 = v.dg14 ? hexToBytes(v.dg14) : undefined;
      const pa = await passiveAuth({
        dg1: hexToBytes(v.dg1),
        sod: hexToBytes(v.sod),
        dg14,
        dg15,
        trustList: [hexToBytes(v.csca)],
        atTime: ripple,
      });
      expect(pa.ok).toBe(true);
      expect(verifyActiveAuth({ dg15, ...(dg14 && { dg14 }), challenge, signature }).ok).toBe(true);
      const bad = signature.slice();
      bad[0] = (bad[0] ?? 0) ^ 1;
      expect(verifyActiveAuth({ dg15, ...(dg14 && { dg14 }), challenge, signature: bad }).ok).toBe(false);
    });
  }
});
