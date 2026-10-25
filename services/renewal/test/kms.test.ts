// P3.12-01, 02, 03, 11 and the A/B test: the KMS EXTERNAL_MU path end to end with KmsSigner (3.6's emulator), against
// Node 24's built-in ML-DSA and noble (through core's context wrapper). All three must agree.
// The emulator is built from the AWS docs, not recorded from real KMS (task 3.6 known gap; no AWS credentials here).
// Source: https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html (MessageType EXTERNAL_MU, 64-byte mu)
// Source: https://csrc.nist.gov/pubs/fips/204/final (Algorithm 2 line 10: mu = H(H(pk) || M'), M' = 0 || |ctx| || ctx || M)
import {
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
  sign as nodeSign,
  verify as nodeVerify,
} from 'node:crypto';
import { SignCommand } from '@aws-sdk/client-kms';
import type { MlDsaContext } from '@legx/contracts/ports';
import { KeyId } from '@legx/contracts/values';
import { pae } from '@legx/core/evidence';
import { mldsaSign, mldsaVerify, muFor, pqKeygen } from '@legx/core/pq';
import { generateNodeSignerKeys, KMS_RAW_LIMIT, kmsSigner, nodeSigner } from '@legx/signer';
import { shake256 } from '@noble/hashes/sha3.js';
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { createFakeKms, FAKE_ED_KEY, FAKE_PQ_KEY } from '../../../packages/signer/test/helpers/fakeKms.ts';

const CTXS: MlDsaContext[] = ['legx/dsse/v1', 'legx/pq-binding/v1', 'legx/checkpoint/v1'];
const MLDSA65_SPKI = Buffer.from('308207b2300b0609608648016503040312038207a100', 'hex');
const nodePub = (raw: Uint8Array): KeyObject =>
  createPublicKey({ key: Buffer.concat([MLDSA65_SPKI, raw]), format: 'der', type: 'spki' });
const nodeVerifyCtx = (pub: Uint8Array, msg: Uint8Array, sig: Uint8Array, ctx: string | undefined) =>
  nodeVerify(null, msg, { key: nodePub(pub), ...(ctx === undefined ? {} : { context: Buffer.from(ctx) }) }, sig);

const kmsPair = () => {
  const kms = createFakeKms();
  const signer = kmsSigner({
    client: kms,
    kmsKeys: { ed25519: FAKE_ED_KEY, mlDsa65: FAKE_PQ_KEY },
    keyIds: { ed25519: KeyId.parse('kms-ed'), mlDsa65: KeyId.parse('kms-pq') },
  });
  return { kms, signer };
};
const signRequests = (kms: ReturnType<typeof createFakeKms>) =>
  kms.calls.filter((c) => c.type === 'Sign').map((c) => c.input);

describe('P3.12-01 KmsSigner with ML_DSA_65 and EXTERNAL_MU', () => {
  it('the signature verifies with the noble wrapper and with Node, under the context', async () => {
    const { signer } = kmsPair();
    const pub = (await signer.publicKeys()).mlDsa65;
    const msg = pae('application/vnd.legx.event+json;v=1', utf8ToBytes('{"a":1}'));
    const sig = (await signer.signHybrid(msg, 'legx/dsse/v1')).mlDsa65;
    expect(sig).toHaveLength(3309);
    expect(mldsaVerify('ml-dsa-65', pub, msg, sig, 'legx/dsse/v1')).toBe(true);
    expect(nodeVerifyCtx(pub, msg, sig, 'legx/dsse/v1')).toBe(true);
  });

  it('a PAE over 4 KB: the ML-DSA half goes through EXTERNAL_MU (mu is 64 bytes whatever the size); the hybrid refuses it as a whole', async () => {
    const { kms, signer } = kmsPair();
    const pub = (await signer.publicKeys()).mlDsa65;
    const big = pae('application/vnd.legx.event+json;v=1', new Uint8Array(100_000).fill(7));
    expect(big.length).toBeGreaterThan(KMS_RAW_LIMIT);
    const mu = muFor(pub, 'legx/dsse/v1', big);
    const out = await kms.send(
      new SignCommand({
        KeyId: FAKE_PQ_KEY,
        Message: mu,
        MessageType: 'EXTERNAL_MU',
        SigningAlgorithm: 'ML_DSA_SHAKE_256',
      }),
    );
    expect(mldsaVerify('ml-dsa-65', pub, big, out.Signature as Uint8Array, 'legx/dsse/v1')).toBe(true);
    // OD-14: the Ed25519 half (RAW only, 4096 bytes) cannot sign it, so no half is made and nothing is sent.
    const before = signRequests(kms).length;
    await expect(signer.signHybrid(big, 'legx/dsse/v1')).rejects.toThrow(/at most 4096 bytes/);
    expect(signRequests(kms)).toHaveLength(before);
  });
});

describe('P3.12-02 mu is ours: the KMS request carries only mu', () => {
  // An independent implementation of FIPS 204 Algorithm 2 line 10 and Algorithm 3: mu = SHAKE256(tr || M', 64).
  const independentMu = (pk: Uint8Array, ctx: string, msg: Uint8Array) => {
    const tr = shake256(pk, { dkLen: 64 });
    const c = utf8ToBytes(ctx);
    return shake256(concatBytes(tr, Uint8Array.of(0, c.length), c, msg), { dkLen: 64 });
  };

  it('the recorded request is EXTERNAL_MU with a 64-byte mu equal to the independent computation', async () => {
    const { kms, signer } = kmsPair();
    const pub = (await signer.publicKeys()).mlDsa65;
    const msg = utf8ToBytes('a message that must not reach the ML-DSA key');
    await signer.signHybrid(msg, 'legx/dsse/v1');
    const pq = signRequests(kms).find((i) => i.KeyId === FAKE_PQ_KEY);
    expect(pq).toMatchObject({ MessageType: 'EXTERNAL_MU', SigningAlgorithm: 'ML_DSA_SHAKE_256' });
    const sent = pq?.Message as Uint8Array;
    expect(sent).toHaveLength(64);
    expect(Buffer.from(sent)).toEqual(Buffer.from(independentMu(pub, 'legx/dsse/v1', msg)));
    expect(Buffer.from(sent)).not.toEqual(Buffer.from(msg));
  });

  it('mu depends on the key, the context and the message', async () => {
    const a = pqKeygen().publicKey;
    const b = pqKeygen().publicKey;
    const m = utf8ToBytes('m');
    const base = muFor(a, 'legx/dsse/v1', m);
    expect(muFor(b, 'legx/dsse/v1', m)).not.toEqual(base);
    expect(muFor(a, 'legx/checkpoint/v1', m)).not.toEqual(base);
    expect(muFor(a, 'legx/dsse/v1', utf8ToBytes('n'))).not.toEqual(base);
  });

  it('the signature KMS makes is an ordinary one that includes the context: only that context verifies', async () => {
    const { signer } = kmsPair();
    const pub = (await signer.publicKeys()).mlDsa65;
    const msg = utf8ToBytes('ordinary');
    const sig = (await signer.signHybrid(msg, 'legx/pq-binding/v1')).mlDsa65;
    expect(mldsaVerify('ml-dsa-65', pub, msg, sig, 'legx/pq-binding/v1')).toBe(true);
    expect(mldsaVerify('ml-dsa-65', pub, msg, sig, 'legx/dsse/v1')).toBe(false);
  });
});

describe('P3.12-03 Node 24 built-in ML-DSA and noble agree', () => {
  it('same seed gives the same key; sizes are 1,952 B and 3,309 B; each verifies the other, with a context', () => {
    const node = generateKeyPairSync('ml-dsa-65');
    const seed = new Uint8Array(node.privateKey.export({ format: 'raw-seed' }));
    const noble = pqKeygen(seed);
    const nodeRaw = new Uint8Array(
      node.publicKey.export({ format: 'der', type: 'spki' }).subarray(MLDSA65_SPKI.length),
    );
    expect(nodeRaw).toHaveLength(1952);
    expect(Buffer.from(noble.publicKey)).toEqual(Buffer.from(nodeRaw));
    const msg = utf8ToBytes('cross');
    const ctx = Buffer.from('legx/dsse/v1');
    const fromNode = new Uint8Array(nodeSign(null, msg, { key: node.privateKey, context: ctx }));
    const fromNoble = mldsaSign('ml-dsa-65', noble.secretKey, msg, 'legx/dsse/v1');
    expect(fromNode).toHaveLength(3309);
    expect(fromNoble).toHaveLength(3309);
    expect(mldsaVerify('ml-dsa-65', noble.publicKey, msg, fromNode, 'legx/dsse/v1')).toBe(true);
    expect(nodeVerify(null, msg, { key: node.publicKey, context: ctx }, fromNoble)).toBe(true);
  });

  it('property: random messages and contexts, every pair of signer and verifier (Node, noble, KMS)', async () => {
    const { signer: kms } = kmsPair();
    const nodeKeys = generateNodeSignerKeys(KeyId.parse('n-ed'), KeyId.parse('n-pq'));
    const node = nodeSigner(nodeKeys);
    const nodePk = (await node.publicKeys()).mlDsa65;
    const kmsPk = (await kms.publicKeys()).mlDsa65;
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ maxLength: 4000 }), fc.constantFrom(...CTXS), async (msg, ctx) => {
        const a = (await node.signHybrid(msg, ctx)).mlDsa65;
        const b = (await kms.signHybrid(msg, ctx)).mlDsa65;
        return (
          mldsaVerify('ml-dsa-65', nodePk, msg, a, ctx) &&
          nodeVerifyCtx(nodePk, msg, a, ctx) &&
          mldsaVerify('ml-dsa-65', kmsPk, msg, b, ctx) &&
          nodeVerifyCtx(kmsPk, msg, b, ctx)
        );
      }),
      { numRuns: 25 },
    );
  });
});

describe('A/B: KmsSigner (EXTERNAL_MU) against NodeSigner on the same message and context', () => {
  it('each half verifies in the other implementation; neither verifies under another context', async () => {
    const { signer: kms } = kmsPair();
    const node = nodeSigner(generateNodeSignerKeys(KeyId.parse('ab-ed'), KeyId.parse('ab-pq')));
    for (const ctx of CTXS) {
      const msg = pae('application/vnd.legx.attest+json;v=1', utf8ToBytes(`message for ${ctx}`));
      for (const s of [kms, node]) {
        const pk = (await s.publicKeys()).mlDsa65;
        const sig = (await s.signHybrid(msg, ctx)).mlDsa65;
        expect(mldsaVerify('ml-dsa-65', pk, msg, sig, ctx)).toBe(true);
        expect(nodeVerifyCtx(pk, msg, sig, ctx)).toBe(true);
        for (const other of CTXS.filter((c) => c !== ctx))
          expect(mldsaVerify('ml-dsa-65', pk, msg, sig, other)).toBe(false);
      }
    }
  });
});

describe('P3.12-11 the context is explicit on every side', () => {
  it('KMS, noble and Node sign under legx/dsse/v1: that context verifies; the empty one and no argument fail', async () => {
    const msg = utf8ToBytes('explicit context');
    const { signer: kms } = kmsPair();
    const node = generateKeyPairSync('ml-dsa-65');
    const nodePk = new Uint8Array(node.publicKey.export({ format: 'der', type: 'spki' }).subarray(MLDSA65_SPKI.length));
    const noble = pqKeygen();
    const cases = [
      { pk: (await kms.publicKeys()).mlDsa65, sig: (await kms.signHybrid(msg, 'legx/dsse/v1')).mlDsa65 },
      { pk: noble.publicKey, sig: mldsaSign('ml-dsa-65', noble.secretKey, msg, 'legx/dsse/v1') },
      {
        pk: nodePk,
        sig: new Uint8Array(nodeSign(null, msg, { key: node.privateKey, context: Buffer.from('legx/dsse/v1') })),
      },
    ];
    for (const { pk, sig } of cases) {
      expect(mldsaVerify('ml-dsa-65', pk, msg, sig, 'legx/dsse/v1')).toBe(true);
      expect(nodeVerifyCtx(pk, msg, sig, 'legx/dsse/v1')).toBe(true);
      expect(mldsaVerify('ml-dsa-65', pk, msg, sig, '')).toBe(false);
      expect(nodeVerifyCtx(pk, msg, sig, '')).toBe(false);
      expect(nodeVerifyCtx(pk, msg, sig, undefined)).toBe(false); // Node's default is the empty context
    }
  });

  it('Node signs with no context option = empty context: our verifiers refuse it under every legx context', () => {
    const k = generateKeyPairSync('ml-dsa-65');
    const msg = utf8ToBytes('forgotten option');
    const sig = new Uint8Array(nodeSign(null, msg, k.privateKey));
    const pk = new Uint8Array(k.publicKey.export({ format: 'der', type: 'spki' }).subarray(MLDSA65_SPKI.length));
    for (const ctx of CTXS) expect(mldsaVerify('ml-dsa-65', pk, msg, sig, ctx)).toBe(false);
    expect(mldsaVerify('ml-dsa-65', pk, msg, sig, '')).toBe(true);
  });
});
