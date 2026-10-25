// Post-quantum primitives (DESIGN 6.13; IMPLEMENTATION 1.16): FIPS 203 and 204 vectors (T-U-27a), the 2-of-3
// post-quantum binding (T-U-25, P1.16-14), the KMS mu helper (P1.16-03), noble against Node (P1.16-04), hedged signing
// (P1.16-12) and the context discipline (P1.16-02, P1.16-15).
// The binding proves consent if Ed25519 breaks later. It does NOT protect the money on the ledger (DESIGN 6.13, O17).
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ml_dsa44, ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  type HolderKey,
  type HolderSig,
  muFor,
  nobleMlDsaSigner,
  pqBindMsg,
  pqKeygen,
  pqKeyHash,
  signPqBinding,
  verifyPqBinding,
} from '../src/pq.ts';
import { readJson, VECTORS } from './helpers/vectors.ts';

const seed = (n: number) => new Uint8Array(32).fill(n);
const hex = (h: string) => hexToBytes(h.toLowerCase());

// ---------- T-U-27a: FIPS 203 and 204 ACVP vectors ----------
// Source: https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files
type Tc = Record<string, string | number | boolean>;
interface Acvp {
  testGroups: (Record<string, string | number | boolean> & { tgId: number; tests: Tc[] })[];
}
const s = (t: Tc, k: string) => hex(String(t[k]));
const dsa = (p: unknown) => (p === 'ML-DSA-44' ? ml_dsa44 : ml_dsa65);

describe('T-U-27a FIPS 204 ML-DSA (ACVP)', () => {
  const keyGen = readJson<Acvp>('pq', 'acvp', 'ml-dsa-keygen.json');
  const sigVer = readJson<Acvp>('pq', 'acvp', 'ml-dsa-sigver.json');
  const sigGen = readJson<Acvp>('pq', 'acvp', 'ml-dsa-siggen.json');

  it('keyGen: keys from the seed equal the vectors (ML-DSA-44 and -65)', () => {
    let n = 0;
    for (const g of keyGen.testGroups)
      for (const t of g.tests) {
        const k = dsa(g.parameterSet).keygen(s(t, 'seed'));
        expect(bytesToHex(k.publicKey)).toBe(String(t.pk).toLowerCase());
        expect(bytesToHex(k.secretKey)).toBe(String(t.sk).toLowerCase());
        n++;
      }
    expect(n).toBe(15);
  });

  it('sigVer: external pure with a context, and internal with external mu, match testPassed', () => {
    let pass = 0;
    let fail = 0;
    for (const g of sigVer.testGroups)
      for (const t of g.tests) {
        const alg = dsa(g.parameterSet);
        const ok = g.externalMu
          ? alg.internal.verify(s(t, 'signature'), s(t, 'mu'), s(t, 'pk'), { externalMu: true })
          : alg.verify(s(t, 'signature'), s(t, 'message'), s(t, 'pk'), { context: s(t, 'context') });
        expect(ok, `tcId ${t.tcId} (${t.reason})`).toBe(t.testPassed);
        if (ok) pass++;
        else fail++;
      }
    expect(pass).toBeGreaterThan(0);
    expect(fail).toBeGreaterThan(0);
  });

  it('sigGen (deterministic ML-DSA-65): pure with a context, and over an external mu', () => {
    for (const g of sigGen.testGroups)
      for (const t of g.tests) {
        const sig = g.externalMu
          ? ml_dsa65.internal.sign(s(t, 'mu'), s(t, 'sk'), { externalMu: true, extraEntropy: false })
          : ml_dsa65.sign(s(t, 'message'), s(t, 'sk'), { context: s(t, 'context'), extraEntropy: false });
        expect(bytesToHex(sig), `tcId ${t.tcId}`).toBe(String(t.signature).toLowerCase());
      }
  });
});

describe('T-U-27a FIPS 203 ML-KEM-768 (ACVP)', () => {
  const keyGen = readJson<Acvp>('pq', 'acvp', 'ml-kem-keygen.json');
  const encDec = readJson<Acvp>('pq', 'acvp', 'ml-kem-encapdecap.json');

  it('keyGen from d || z', () => {
    for (const t of keyGen.testGroups.flatMap((g) => g.tests)) {
      const k = ml_kem768.keygen(concatBytes(s(t, 'd'), s(t, 'z')));
      expect(bytesToHex(k.publicKey)).toBe(String(t.ek).toLowerCase());
      expect(bytesToHex(k.secretKey)).toBe(String(t.dk).toLowerCase());
    }
  });

  it('encapsulation with fixed m, and decapsulation (including implicit rejection)', () => {
    for (const g of encDec.testGroups)
      for (const t of g.tests) {
        if (g.function === 'encapsulation') {
          const r = ml_kem768.encapsulate(s(t, 'ek'), s(t, 'm'));
          expect(bytesToHex(r.cipherText)).toBe(String(t.c).toLowerCase());
          expect(bytesToHex(r.sharedSecret)).toBe(String(t.k).toLowerCase());
        } else {
          expect(bytesToHex(ml_kem768.decapsulate(s(t, 'c'), s(t, 'dk'))), `tcId ${t.tcId}`).toBe(
            String(t.k).toLowerCase(),
          );
        }
      }
  });
});

// ---------- T-U-25, P1.16-14: the 2-of-3 post-quantum binding ----------
// Golden values from the independent Python reference (tools/py-ref/vectors/pq.json, written from DESIGN alone).
interface PyVec {
  fn: string;
  inputs: Record<string, string | string[]>;
  output: string;
}
const pyRef = JSON.parse(readFileSync(join(VECTORS, '../../../tools/py-ref/vectors/pq.json'), 'utf8')) as PyVec[];

describe('P1.16-14 binding golden vectors (Python reference)', () => {
  const kh = pyRef.find((v) => v.fn === 'pqKeyHash') as PyVec;
  const bm = pyRef.find((v) => v.fn === 'pqBindMsg') as PyVec;
  const pubs = (kh.inputs.pubs as string[]).map(hex) as [Uint8Array, Uint8Array, Uint8Array];

  it('pqKeyHash and pqBindMsg equal the committed hex', () => {
    expect(bytesToHex(pqKeyHash(pubs))).toBe(kh.output);
    const msg = pqBindMsg(hex(bm.inputs.dealSeal as string), hex(bm.inputs.slotPub as string), pqKeyHash(pubs));
    expect(bytesToHex(msg)).toBe(bm.output);
  });

  it('changing any one of the three keys changes both values; the order matters', () => {
    const seal = hex(bm.inputs.dealSeal as string);
    const slot = hex(bm.inputs.slotPub as string);
    for (let i = 0; i < 3; i++) {
      const changed = pubs.map((p, j) => (j === i ? Uint8Array.from(p, (b, k) => (k === 0 ? b ^ 1 : b)) : p));
      const h = pqKeyHash(changed as [Uint8Array, Uint8Array, Uint8Array]);
      expect(bytesToHex(h)).not.toBe(kh.output);
      expect(bytesToHex(pqBindMsg(seal, slot, h))).not.toBe(bm.output);
    }
    expect(bytesToHex(pqKeyHash([pubs[1], pubs[0], pubs[2]]))).not.toBe(kh.output);
  });

  it('refuses inputs of the wrong length (33-byte slot key, 32-byte hashes, 1,952-byte ML-DSA-65 keys)', () => {
    const seal = hex(bm.inputs.dealSeal as string);
    expect(() => pqBindMsg(seal, seal, seal)).toThrow(/slotPub/);
    expect(() => pqBindMsg(seal.subarray(1), hex(bm.inputs.slotPub as string), seal)).toThrow(/dealSeal/);
    expect(() => pqKeyHash([pubs[0], pubs[1], pubs[2].subarray(1)])).toThrow(/1952/);
  });
});

describe('T-U-25 binding: two of three holders plus the slot key cross-signature (consent proof, not ledger protection)', () => {
  const holderKeys = [1, 2, 3].map((n) => pqKeygen(seed(n)));
  const holders = holderKeys.map((k, i) => ({ keyId: `h${i}`, mlDsa65: k.publicKey })) as unknown as readonly [
    HolderKey,
    HolderKey,
    HolderKey,
  ];
  const signers = holderKeys.map((k, i) => nobleMlDsaSigner(`h${i}`, k.secretKey));
  const slotSk = seed(9);
  const slotPub = concatBytes(Uint8Array.of(0xed), ed25519.getPublicKey(slotSk));
  const otherSlotSk = seed(10);
  const dealSeal = seed(0x5e);
  const keyHash = pqKeyHash(holders.map((h) => h.mlDsa65) as [Uint8Array, Uint8Array, Uint8Array]);
  const msg = pqBindMsg(dealSeal, slotPub, keyHash);
  const verifySlotSig = (pub: Uint8Array, m: Uint8Array, sig: Uint8Array) =>
    ed25519.verify(sig, m, pub.subarray(1), { zip215: false });
  const expected = { dealSeal, slotPub, pqKeyHash: keyHash };
  const crossSig = ed25519.sign(msg, slotSk);

  const binding = (holderSigs: readonly HolderSig[], over: Partial<typeof expected> = {}) => ({
    ...expected,
    ...over,
    holderSigs,
    crossSig,
  });
  let sigs: HolderSig[] = [];
  it('each holder signs pqBindMsg with ML-DSA-65', async () => {
    sigs = await Promise.all(signers.map((sg) => signPqBinding(msg, sg)));
    expect(sigs.map((x) => x.sig.length)).toEqual([3309, 3309, 3309]);
  });

  it('T-U-25a: all three holder pairs verify, and pqKeyHash equals the sealed value', () => {
    for (const [a, b] of [
      [0, 1],
      [0, 2],
      [1, 2],
    ] as const) {
      const sel = [sigs[a], sigs[b]] as HolderSig[];
      expect(verifyPqBinding(binding(sel), expected, holders, verifySlotSig)).toEqual({ ok: true });
      expect(verifyPqBinding(binding(sel.toReversed()), expected, holders, verifySlotSig)).toEqual({ ok: true });
    }
  });

  it('T-U-25b: one holder alone, the same holder twice, an unknown key', async () => {
    const v = (hs: HolderSig[]) => verifyPqBinding(binding(hs), expected, holders, verifySlotSig);
    const [s0, s1] = sigs as [HolderSig, HolderSig];
    expect(v([s0])).toEqual({ ok: false, code: 'BELOW_TWO_HOLDERS' });
    expect(v([s0, s0])).toEqual({ ok: false, code: 'DUPLICATE_HOLDER' });
    const resigned = await signPqBinding(msg, signers[0] as never);
    expect(v([s0, resigned])).toEqual({ ok: false, code: 'DUPLICATE_HOLDER' });
    const stranger = await signPqBinding(msg, nobleMlDsaSigner('x', pqKeygen(seed(4)).secretKey));
    expect(v([s0, stranger])).toEqual({ ok: false, code: 'HOLDER_KEY_UNKNOWN' });
    const stolenId = { keyId: 'h1', sig: stranger.sig };
    expect(v([s0, stolenId])).toEqual({ ok: false, code: 'HOLDER_SIG_INVALID' });
    expect(v([s0, s1, sigs[2] as HolderSig])).toEqual({ ok: false, code: 'TOO_MANY_HOLDERS' });
  });

  it('T-U-25c: a wrong seal, slot key or key hash in the record, or keys hashed in another order', async () => {
    const two = [sigs[0], sigs[1]] as HolderSig[];
    const v = (over: Partial<typeof expected>) => verifyPqBinding(binding(two, over), expected, holders, verifySlotSig);
    expect(v({ dealSeal: seed(1) })).toEqual({ ok: false, code: 'SEAL_MISMATCH' });
    expect(v({ slotPub: concatBytes(Uint8Array.of(0xed), seed(1)) })).toEqual({ ok: false, code: 'SLOT_PUB_MISMATCH' });
    expect(v({ pqKeyHash: seed(1) })).toEqual({ ok: false, code: 'PQ_KEY_HASH_MISMATCH' });
    const reordered = [holders[1], holders[0], holders[2]] as unknown as typeof holders;
    expect(verifyPqBinding(binding(two), expected, reordered, verifySlotSig)).toEqual({
      ok: false,
      code: 'PQ_KEY_HASH_MISMATCH',
    });
    // Holders who signed a message with another seal: the record claims the right seal, the signatures do not match.
    const wrongMsg = pqBindMsg(seed(1), slotPub, keyHash);
    const bad = await Promise.all(signers.slice(0, 2).map((sg) => signPqBinding(wrongMsg, sg)));
    expect(verifyPqBinding(binding(bad), expected, holders, verifySlotSig)).toEqual({
      ok: false,
      code: 'HOLDER_SIG_INVALID',
    });
  });

  it('T-U-25d: the cross-signature missing, or made by another slot key', () => {
    const two = [sigs[0], sigs[1]] as HolderSig[];
    const { crossSig: _drop, ...noCross } = binding(two);
    expect(verifyPqBinding(noCross, expected, holders, verifySlotSig)).toEqual({
      ok: false,
      code: 'CROSS_SIG_MISSING',
    });
    const other = { ...binding(two), crossSig: ed25519.sign(msg, otherSlotSk) };
    expect(verifyPqBinding(other, expected, holders, verifySlotSig)).toEqual({ ok: false, code: 'CROSS_SIG_INVALID' });
  });

  it('P1.16-02: a holder signature under the envelope context (legx/dsse/v1) is not a binding signature', () => {
    const asEnvelope = ml_dsa65.sign(msg, holderKeys[1]?.secretKey as Uint8Array, {
      context: utf8ToBytes('legx/dsse/v1'),
    });
    const r = verifyPqBinding(
      binding([sigs[0] as HolderSig, { keyId: 'h1', sig: asEnvelope }]),
      expected,
      holders,
      verifySlotSig,
    );
    expect(r).toEqual({ ok: false, code: 'HOLDER_SIG_INVALID' });
    const emptyCtx = ml_dsa65.sign(msg, holderKeys[1]?.secretKey as Uint8Array);
    const r2 = verifyPqBinding(
      binding([sigs[0] as HolderSig, { keyId: 'h1', sig: emptyCtx }]),
      expected,
      holders,
      verifySlotSig,
    );
    expect(r2).toEqual({ ok: false, code: 'HOLDER_SIG_INVALID' });
  });

  it('hostile lengths return a typed error and never throw', () => {
    const two = [sigs[0] as HolderSig, { keyId: 'h1', sig: new Uint8Array(3308) }];
    expect(verifyPqBinding(binding(two), expected, holders, verifySlotSig)).toEqual({
      ok: false,
      code: 'HOLDER_SIG_INVALID',
    });
    const shortKey = [
      holders[0],
      { keyId: 'h1', mlDsa65: new Uint8Array(1951) },
      holders[2],
    ] as unknown as typeof holders;
    expect(
      verifyPqBinding(binding([sigs[0] as HolderSig, sigs[1] as HolderSig]), expected, shortKey, verifySlotSig),
    ).toEqual({
      ok: false,
      code: 'MALFORMED',
    });
    expect(
      verifyPqBinding(
        binding([sigs[0] as HolderSig, sigs[1] as HolderSig], { dealSeal: new Uint8Array(31) }),
        expected,
        holders,
        verifySlotSig,
      ),
    ).toEqual({
      ok: false,
      code: 'MALFORMED',
    });
  });
});

// ---------- P1.16-03: KMS EXTERNAL_MU equivalence ----------
// Source: https://csrc.nist.gov/pubs/fips/204/final (Algorithm 7, line 6; section 5.2 external mu)
// Source: https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html (ML_DSA_SHAKE_256, EXTERNAL_MU)
describe('P1.16-03 muFor (the KMS EXTERNAL_MU path)', () => {
  const { publicKey, secretKey } = pqKeygen(seed(7));
  // A stub KMS: holds a noble key, signs a given mu, never sees the message.
  const kmsSignMu = (mu: Uint8Array) => ml_dsa65.internal.sign(mu, secretKey, { externalMu: true });
  const ctx = utf8ToBytes('legx/dsse/v1');

  it('a signature over a locally computed mu verifies over the original 10 KB message with the same context', () => {
    const msg = crypto.randomBytes(10 * 1024);
    const sig = kmsSignMu(muFor(publicKey, 'legx/dsse/v1', msg));
    expect(ml_dsa65.verify(sig, msg, publicKey, { context: ctx })).toBe(true);
    expect(ml_dsa65.verify(sig, msg, publicKey)).toBe(false);
    expect(ml_dsa65.verify(sig, msg, publicKey, { context: utf8ToBytes('legx/pq-binding/v1') })).toBe(false);
  });

  it('RAW (3 KB) and EXTERNAL_MU signatures over the same message both verify', () => {
    const msg = crypto.randomBytes(3 * 1024);
    const raw = ml_dsa65.sign(msg, secretKey, { context: ctx });
    const viaMu = kmsSignMu(muFor(publicKey, 'legx/dsse/v1', msg));
    expect(ml_dsa65.verify(raw, msg, publicKey, { context: ctx })).toBe(true);
    expect(ml_dsa65.verify(viaMu, msg, publicKey, { context: ctx })).toBe(true);
    expect(ml_dsa65.internal.verify(raw, muFor(publicKey, 'legx/dsse/v1', msg), publicKey, { externalMu: true })).toBe(
      true,
    );
  });

  it('is 64 bytes and refuses a public key of the wrong length', () => {
    expect(muFor(publicKey, 'legx/checkpoint/v1', new Uint8Array(0))).toHaveLength(64);
    expect(() => muFor(publicKey.subarray(1), 'legx/dsse/v1', new Uint8Array(1))).toThrow(/1952/);
  });
});

// ---------- P1.16-04: Node's built-in ML-DSA against noble ----------
// Source: https://nodejs.org/api/crypto.html#cryptosignalgorithm-data-key-callback (context option, raw-public format)
const nodeHasMlDsa = (() => {
  try {
    crypto.generateKeyPairSync('ml-dsa-65');
    return true;
  } catch {
    return false;
  }
})();
if (!nodeHasMlDsa) console.warn('P1.16-04 SKIPPED: this Node has no built-in ML-DSA (needs Node 24.7 or later)');

describe.skipIf(!nodeHasMlDsa)('P1.16-04 / T-U-27d noble and Node built-in ML-DSA-65 agree', () => {
  const nodeKeys = crypto.generateKeyPairSync('ml-dsa-65');
  const nodeSeed = new Uint8Array(nodeKeys.privateKey.export({ format: 'raw-seed' }));
  const nodePub = new Uint8Array(nodeKeys.publicKey.export({ format: 'raw-public' }));
  const noble = pqKeygen(seed(11));
  const nobleInNode = crypto.createPublicKey({
    key: Buffer.from(noble.publicKey),
    format: 'raw-public',
    asymmetricKeyType: 'ml-dsa-65',
  });

  it('the same seed gives the same public key in both', () => {
    expect(bytesToHex(pqKeygen(nodeSeed).publicKey)).toBe(bytesToHex(nodePub));
  });

  const sizes = [0, 200, 10 * 1024];
  const contexts = [undefined, 'legx/dsse/v1'] as const;
  for (const size of sizes)
    for (const c of contexts) {
      it(`${size} B, context ${c ?? '(empty)'}: Node signs, noble verifies; noble signs, Node verifies`, () => {
        const msg = crypto.randomBytes(size);
        const ctxBytes = c ? Buffer.from(c) : undefined;
        const nodeSig = crypto.sign(null, msg, { key: nodeKeys.privateKey, context: ctxBytes });
        expect(ml_dsa65.verify(nodeSig, msg, nodePub, ctxBytes ? { context: ctxBytes } : {})).toBe(true);
        const nobleSig = ml_dsa65.sign(msg, noble.secretKey, ctxBytes ? { context: ctxBytes } : {});
        expect(crypto.verify(null, msg, { key: nobleInNode, context: ctxBytes }, nobleSig)).toBe(true);
        if (c) {
          // Node's default is the EMPTY context: forgetting the option fails, so every side passes it explicitly.
          expect(crypto.verify(null, msg, nobleInNode, nobleSig)).toBe(false);
        }
      });
    }

  it('a Node signature over a mu-signed message: Node verifies a noble external-mu signature', () => {
    const msg = crypto.randomBytes(5000);
    const sig = ml_dsa65.internal.sign(muFor(noble.publicKey, 'legx/dsse/v1', msg), noble.secretKey, {
      externalMu: true,
    });
    expect(crypto.verify(null, msg, { key: nobleInNode, context: Buffer.from('legx/dsse/v1') }, sig)).toBe(true);
  });
});

// ---------- P1.16-12: hedged signing ----------
describe('P1.16-12 ML-DSA signing is hedged', () => {
  it('two signatures over one message differ and both verify (dedupe by payload hash, never signature bytes)', async () => {
    const k = pqKeygen(seed(12));
    const sg = nobleMlDsaSigner('k', k.secretKey);
    const msg = utf8ToBytes('same bytes');
    const [a, b] = [await sg.sign(msg, 'legx/dsse/v1'), await sg.sign(msg, 'legx/dsse/v1')];
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
    const ctx = { context: utf8ToBytes('legx/dsse/v1') };
    expect(ml_dsa65.verify(a, msg, k.publicKey, ctx) && ml_dsa65.verify(b, msg, k.publicKey, ctx)).toBe(true);
  });
});

describe('property: pqBindMsg is injective over its three fields', () => {
  it('different inputs give different messages', () => {
    const b32 = fc.uint8Array({ minLength: 32, maxLength: 32 });
    fc.assert(
      fc.property(b32, b32, b32, b32, (a, b, c, d) => {
        const slot = concatBytes(Uint8Array.of(0xed), b);
        fc.pre(bytesToHex(a) !== bytesToHex(d));
        return bytesToHex(pqBindMsg(a, slot, c)) !== bytesToHex(pqBindMsg(d, slot, c));
      }),
      { numRuns: 100 },
    );
  });
});
