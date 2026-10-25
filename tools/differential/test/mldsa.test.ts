// P5.3-06, P5.3-07 and P5.3-10: ML-DSA-65 in noble against Node's built-in (OpenSSL), in both directions, on random
// messages and contexts; the pqBindMsg of a slot signed by two holders; the EXTERNAL_MU message representative.
import { createPrivateKey, createPublicKey, type KeyObject, sign as nodeSign, verify as nodeVerify } from 'node:crypto';
import { muFor, pqBindMsg, pqKeyHash } from '@legx/core/pq';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { hex, Prng, PyRef, seedsToRun } from '../src/index.ts';

const jwk = (o: object) => o as unknown as import('node:crypto').JsonWebKeyInput['key'];
const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
const ctxOpt = (ctx: Uint8Array) => ({ context: Buffer.from(ctx) });

function nodeKeys(seed: Uint8Array, pub: Uint8Array): { priv: KeyObject; pub: KeyObject } {
  const priv = createPrivateKey({
    key: jwk({ kty: 'AKP', alg: 'ML-DSA-65', pub: b64u(pub), priv: b64u(seed) }),
    format: 'jwk',
  });
  return { priv, pub: createPublicKey({ key: jwk({ kty: 'AKP', alg: 'ML-DSA-65', pub: b64u(pub) }), format: 'jwk' }) };
}
const nodeSignCtx = (k: KeyObject, msg: Uint8Array, ctx: Uint8Array) =>
  new Uint8Array(nodeSign(null, msg, { key: k, ...ctxOpt(ctx) }));
const nodeVerifyCtx = (k: KeyObject, msg: Uint8Array, sig: Uint8Array, ctx: Uint8Array) =>
  nodeVerify(null, msg, { key: k, ...ctxOpt(ctx) }, sig);

let py: PyRef;
beforeAll(() => {
  py = new PyRef();
});
afterAll(() => py.close());

describe('P5.3-06 noble against Node ML-DSA-65', () => {
  for (const seed of seedsToRun()) {
    it(`seed ${seed}: 200 random messages and contexts, both directions`, () => {
      const r = new Prng(seed);
      for (let i = 0; i < 200; i++) {
        const kseed = r.bytes(32);
        const { publicKey, secretKey } = ml_dsa65.keygen(kseed);
        const node = nodeKeys(kseed, publicKey);
        // Node derives the same public key from the same seed.
        expect(
          new Uint8Array(
            Buffer.from((node.pub.export({ format: 'jwk' }) as unknown as { pub: string }).pub, 'base64url'),
          ),
        ).toEqual(publicKey);
        const msg = r.bytes(r.int(2000));
        const ctx = r.bytes(r.chance(0.2) ? 0 : r.int(256));
        const nobleSig = ml_dsa65.sign(msg, secretKey, { context: ctx });
        const nodeSig = nodeSignCtx(node.priv, msg, ctx);
        expect(nodeVerifyCtx(node.pub, msg, nobleSig, ctx)).toBe(true);
        expect(ml_dsa65.verify(nodeSig, msg, publicKey, { context: ctx })).toBe(true);
        // A different context or a changed message is refused by both.
        const other = ctx.length === 255 ? ctx.map((b, k) => (k === 0 ? b ^ 1 : b)) : new Uint8Array([...ctx, 1]);
        const changed = new Uint8Array([...msg, 0]);
        expect(nodeVerifyCtx(node.pub, msg, nobleSig, other)).toBe(false);
        expect(ml_dsa65.verify(nobleSig, msg, publicKey, { context: other })).toBe(false);
        expect(nodeVerifyCtx(node.pub, changed, nobleSig, ctx)).toBe(false);
        expect(ml_dsa65.verify(nodeSig, changed, publicKey, { context: ctx })).toBe(false);
      }
    }, 300_000);
  }
});

describe('P5.3-07 pqBindMsg signed by two holders', () => {
  it('noble signatures verify in Node, under the context legx/pq-binding/v1 and no other', () => {
    const r = new Prng(57);
    const ctx = new TextEncoder().encode('legx/pq-binding/v1');
    const holders = [0, 1, 2].map(() => {
      const kseed = r.bytes(32);
      const kp = ml_dsa65.keygen(kseed);
      return { ...kp, node: nodeKeys(kseed, kp.publicKey) };
    });
    const keyHash = pqKeyHash(holders.map((h) => h.publicKey) as [Uint8Array, Uint8Array, Uint8Array]);
    const msg = pqBindMsg(r.bytes(32), new Uint8Array([0xed, ...r.bytes(32)]), keyHash);
    for (const h of [holders[0], holders[2]]) {
      const sig = ml_dsa65.sign(msg, (h as (typeof holders)[0]).secretKey, { context: ctx });
      const node = (h as (typeof holders)[0]).node.pub;
      expect(nodeVerifyCtx(node, msg, sig, ctx)).toBe(true);
      expect(nodeVerifyCtx(node, msg, sig, new Uint8Array())).toBe(false);
      expect(nodeVerifyCtx((holders[1] as (typeof holders)[0]).node.pub, msg, sig, ctx)).toBe(false);
    }
  });
});

describe('P5.3-10 EXTERNAL_MU', () => {
  for (const seed of seedsToRun()) {
    it(`seed ${seed}: Python mu equals muFor; a signature over it verifies in Node with the context`, async () => {
      const r = new Prng(seed);
      const ctxs = ['legx/dsse/v1', 'legx/pq-binding/v1', 'legx/checkpoint/v1'] as const;
      const cases = Array.from({ length: 50 }, () => {
        const kseed = r.bytes(32);
        const kp = ml_dsa65.keygen(kseed);
        const ctx = r.pick(ctxs);
        return { kseed, kp, ctx, msg: r.bytes(r.int(500)) };
      });
      const pyMu = await py.call<string>(
        'ref',
        cases.map((c) => ({
          fn: 'mu',
          args: { pub: hex(c.kp.publicKey), ctx: hex(new TextEncoder().encode(c.ctx)), msg: hex(c.msg) },
        })),
      );
      cases.forEach((c, i) => {
        expect(pyMu[i]).toBe(hex(muFor(c.kp.publicKey, c.ctx, c.msg)));
        const sig = ml_dsa65.internal.sign(Uint8Array.from(Buffer.from(pyMu[i] as string, 'hex')), c.kp.secretKey, {
          externalMu: true,
        });
        const ctxBytes = new TextEncoder().encode(c.ctx);
        expect(nodeVerifyCtx(nodeKeys(c.kseed, c.kp.publicKey).pub, c.msg, sig, ctxBytes)).toBe(true);
        expect(ml_dsa65.verify(sig, c.msg, c.kp.publicKey, { context: ctxBytes })).toBe(true);
      });
    }, 300_000);
  }
});
