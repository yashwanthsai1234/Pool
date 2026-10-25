// The one SignerPort contract suite (P3.6-01). Every implementation runs it; nothing in it knows which one it is.
import type { MlDsaContext, SignerPort } from '@legx/contracts/ports';
import { pae } from '@legx/core/evidence';
import { signHybrid as signEnvelope, verifyHybrid } from '@legx/core/hybridEnvelope';
import { mldsaVerify } from '@legx/core/pq';
import { verifyXrplKeySig } from '@legx/core/verify';
import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';

const CONTEXTS: MlDsaContext[] = ['legx/dsse/v1', 'legx/pq-binding/v1', 'legx/checkpoint/v1'];
// The DSSE context the core envelope signer uses (core keeps its constant private).
const DSSE_CONTEXT = 'legx/dsse/v1' satisfies MlDsaContext;
const enc = new TextEncoder();

export function signerContract(name: string, make: () => SignerPort | Promise<SignerPort>): void {
  describe(`SignerPort contract: ${name}`, () => {
    it('publishes keys of the documented sizes, stable across calls', async () => {
      const s = await make();
      const a = await s.publicKeys();
      expect(a.ed25519).toHaveLength(32);
      expect(a.mlDsa65).toHaveLength(1952);
      expect(await s.publicKeys()).toEqual(a);
    });

    it('returns both halves; the Ed25519 one verifies with verifyXrplKeySig, the ML-DSA-65 one under its context', async () => {
      const s = await make();
      const pub = await s.publicKeys();
      const msg = enc.encode('the same bytes for both halves');
      for (const ctx of CONTEXTS) {
        const sig = await s.signHybrid(msg, ctx);
        expect(sig.ed25519).toHaveLength(64);
        expect(sig.mlDsa65).toHaveLength(3309);
        expect(sig.keyIds).toEqual(pub.keyIds);
        expect(verifyXrplKeySig(`ED${bytesToHex(pub.ed25519).toUpperCase()}`, msg, bytesToHex(sig.ed25519))).toBe(true);
        expect(mldsaVerify('ml-dsa-65', pub.mlDsa65, msg, sig.mlDsa65, ctx)).toBe(true);
      }
    });

    it('binds the ML-DSA signature to the context: any other context, and the empty one, fail', async () => {
      const s = await make();
      const pub = await s.publicKeys();
      const msg = enc.encode('context binding');
      const sig = await s.signHybrid(msg, 'legx/dsse/v1');
      for (const other of ['legx/pq-binding/v1', 'legx/checkpoint/v1', ''] as const) {
        expect(mldsaVerify('ml-dsa-65', pub.mlDsa65, msg, sig.mlDsa65, other)).toBe(false);
      }
    });

    it('binds both signatures to the message: a one-bit change fails both', async () => {
      const s = await make();
      const pub = await s.publicKeys();
      const msg = enc.encode('message');
      const sig = await s.signHybrid(msg, 'legx/dsse/v1');
      const other = Uint8Array.from(msg);
      other[0] = (other[0] ?? 0) ^ 1;
      expect(verifyXrplKeySig(`ED${bytesToHex(pub.ed25519)}`, other, bytesToHex(sig.ed25519))).toBe(false);
      expect(mldsaVerify('ml-dsa-65', pub.mlDsa65, other, sig.mlDsa65, 'legx/dsse/v1')).toBe(false);
    });

    it('signs the empty message and a 4096-byte message (the KMS RAW limit)', async () => {
      const s = await make();
      const pub = await s.publicKeys();
      for (const msg of [new Uint8Array(0), new Uint8Array(4096).fill(7)]) {
        const sig = await s.signHybrid(msg, 'legx/dsse/v1');
        expect(verifyXrplKeySig(`ED${bytesToHex(pub.ed25519)}`, msg, bytesToHex(sig.ed25519))).toBe(true);
        expect(mldsaVerify('ml-dsa-65', pub.mlDsa65, msg, sig.mlDsa65, 'legx/dsse/v1')).toBe(true);
      }
    });

    it('handles concurrent requests', async () => {
      const s = await make();
      const pub = await s.publicKeys();
      const sigs = await Promise.all(
        Array.from({ length: 20 }, (_, i) => s.signHybrid(enc.encode(`m${i}`), 'legx/dsse/v1')),
      );
      sigs.forEach((sig, i) => {
        expect(mldsaVerify('ml-dsa-65', pub.mlDsa65, enc.encode(`m${i}`), sig.mlDsa65, 'legx/dsse/v1')).toBe(true);
      });
    });

    it('signs DSSE PAE bytes so that the core hybrid verifier accepts the envelope', async () => {
      const s = await make();
      const pub = await s.publicKeys();
      const body = enc.encode(JSON.stringify({ predicate: { sig_algs: ['ed25519', 'ml-dsa-65'] } }));
      const type = 'application/vnd.legx.event+json;v=1';
      const env = await signEnvelope(type, body, s);
      const registry = (id: string) =>
        id === pub.keyIds.ed25519
          ? { alg: 'ed25519' as const, publicKey: pub.ed25519, validFrom: 0, logged: true, pair: 'service' }
          : id === pub.keyIds.mlDsa65
            ? { alg: 'ml-dsa-65' as const, publicKey: pub.mlDsa65, validFrom: 0, logged: true, pair: 'service' }
            : undefined;
      expect(verifyHybrid(env, registry, 1)).toMatchObject({ ok: true });
      // The signed bytes are the PAE, not the body: verifying the body directly must fail.
      const direct = await s.signHybrid(pae(type, body), DSSE_CONTEXT);
      expect(mldsaVerify('ml-dsa-65', pub.mlDsa65, body, direct.mlDsa65, DSSE_CONTEXT)).toBe(false);
    });
  });
}
