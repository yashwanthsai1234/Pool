// P4.9-01, 02, 08 and the X-Wing package keys (share and backup kinds), on Chromium and WebKit.
import { mldsaVerify, openPackage, sealPackage, XWING_SUITE } from '@legx/core/pq';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import keyGenVectors from '../../../core/vectors/pq/acvp/ml-dsa-keygen.json';
import sigGenVectors from '../../../core/vectors/pq/acvp/ml-dsa-siggen.json';
import xwingVectors from '../../../core/vectors/pq/xwing-draft-11.json';
import { pqKeys } from '../../src/pq/keys.ts';
import { containsSecret, dealId, freshDb, isZero, rawRows } from '../helpers.ts';
import { captureSeeds, tamperRow } from './support.ts';

afterEach(() => {
  vi.restoreAllMocks();
});

const setup = (role: 'alice' | 'lawyerA' = 'alice') => {
  const dbName = freshDb();
  return { dbName, id: dealId(), keys: pqKeys({ role, dbName }) };
};

describe('P4.9-01 key creation', () => {
  it('makes a 1,952-byte ML-DSA-65 key and a 1,216-byte X-Wing key; IndexedDB holds seed ciphertexts only', async () => {
    const seeds = captureSeeds();
    const s = setup();
    const pub = await s.keys.create(s.id);
    expect(pub.mlDsa65).toHaveLength(1952);
    expect(pub.xwing).toHaveLength(1216);
    const [mlSeed, xwSeed] = seeds.copies;
    if (!mlSeed || !xwSeed) throw new Error('no seeds captured');
    // The public keys come from exactly these seeds, and the seed buffers were zeroed after sealing.
    expect(bytesToHex(ml_dsa65.keygen(mlSeed).publicKey)).toBe(bytesToHex(pub.mlDsa65));
    expect(bytesToHex(ml_kem768_x25519.getPublicKey(xwSeed))).toBe(bytesToHex(pub.xwing));
    expect(seeds.buffers.every(isZero)).toBe(true);
    const rows = await rawRows(s.dbName);
    const expanded = ml_dsa65.keygen(mlSeed).secretKey;
    expect(containsSecret(rows, [mlSeed, xwSeed, expanded])).toBe(false);
    expect(containsSecret(rows, [pub.mlDsa65])).toBe(true);
  });

  it('is idempotent: a second create returns the same keys', async () => {
    const s = setup();
    const a = await s.keys.create(s.id);
    const b = await s.keys.create(s.id);
    expect(bytesToHex(b.mlDsa65)).toBe(bytesToHex(a.mlDsa65));
  });

  it('refuses a malformed deal id and an unknown deal', async () => {
    const s = setup();
    await expect(s.keys.create('not-a-deal')).rejects.toMatchObject({ code: 'INPUT_INVALID' });
    await expect(s.keys.publicKeys(s.id)).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });
});

describe('P4.9-02 reload and sign', () => {
  it('a new handle on the same database signs; the seed is zeroed (the expanded key: zeroize.browser.test.ts)', async () => {
    const s = setup();
    const pub = await s.keys.create(s.id);
    const again = pqKeys({ role: 'alice', dbName: s.dbName });
    const decrypted: Uint8Array[] = [];
    const real = crypto.subtle.decrypt.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, 'decrypt').mockImplementation(async (...a) => {
      const out = await real(...a);
      decrypted.push(new Uint8Array(out));
      return out;
    });
    const half = await again.half(s.id, 'pair-1#ml-dsa-65');
    const msg = randomBytes(100);
    const sig = await half.sign(msg, 'legx/dsse/v1');
    expect(sig).toHaveLength(3309);
    expect(mldsaVerify('ml-dsa-65', pub.mlDsa65, msg, sig, 'legx/dsse/v1')).toBe(true);
    expect(mldsaVerify('ml-dsa-65', pub.mlDsa65, msg, sig, 'legx/pq-binding/v1')).toBe(false);
    // decrypt's own ArrayBuffer is what the vault wraps and zeroes.
    expect(decrypted).toHaveLength(1);
    expect(decrypted.every(isZero)).toBe(true);
  });

  it('a corrupted seed ciphertext gives DECRYPT_FAILED and no signature', async () => {
    const s = setup();
    await s.keys.create(s.id);
    await tamperRow(s.dbName, `${s.id}:alice:pq`, (row) => {
      const r = row as { mlDsaSeed: { ct: Uint8Array } };
      r.mlDsaSeed.ct[0] = (r.mlDsaSeed.ct[0] ?? 0) ^ 1;
    });
    const half = await s.keys.half(s.id, 'k#ml-dsa-65');
    await expect(half.sign(randomBytes(8), 'legx/dsse/v1')).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });
  });

  it('a seed ciphertext moved to another field does not open (AAD names the field)', async () => {
    const s = setup();
    await s.keys.create(s.id);
    await tamperRow(s.dbName, `${s.id}:alice:pq`, (row) => {
      const r = row as { mlDsaSeed: unknown; xwingSeed: unknown };
      r.mlDsaSeed = r.xwingSeed;
    });
    const half = await s.keys.half(s.id, 'k#ml-dsa-65');
    await expect(half.sign(randomBytes(8), 'legx/dsse/v1')).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });
  });

  it('roles are separate: a lawyer handle on the same database cannot see the client key', async () => {
    const s = setup();
    await s.keys.create(s.id);
    await expect(pqKeys({ role: 'lawyerA', dbName: s.dbName }).publicKeys(s.id)).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
  });

  it('concurrent signatures all verify', async () => {
    const s = setup();
    const pub = await s.keys.create(s.id);
    const half = await s.keys.half(s.id, 'k#ml-dsa-65');
    const msgs = [1, 2, 3, 4].map(() => randomBytes(64));
    const sigs = await Promise.all(msgs.map((m) => half.sign(m, 'legx/dsse/v1')));
    sigs.forEach((sig, i) => {
      expect(mldsaVerify('ml-dsa-65', pub.mlDsa65, msgs[i] as Uint8Array, sig, 'legx/dsse/v1')).toBe(true);
    });
  });
});

describe('hybrid signer (Ed25519 from task 4.2 plus ML-DSA-65)', () => {
  it('signs both halves under the pair key ids the coordinator expects', async () => {
    const s = setup();
    const pub = await s.keys.create(s.id);
    const signer = await s.keys.hybridSigner(s.id, 'pair-7');
    const keys = await signer.publicKeys();
    expect(keys.keyIds).toEqual({ ed25519: 'pair-7#ed25519', mlDsa65: 'pair-7#ml-dsa-65' });
    expect(bytesToHex(keys.mlDsa65)).toBe(bytesToHex(pub.mlDsa65));
    const msg = randomBytes(40);
    const sig = await signer.signHybrid(msg, 'legx/dsse/v1');
    expect(ed25519.verify(sig.ed25519, msg, keys.ed25519, { zip215: false })).toBe(true);
    expect(mldsaVerify('ml-dsa-65', keys.mlDsa65, msg, sig.mlDsa65, 'legx/dsse/v1')).toBe(true);
  });
});

describe('X-Wing packages (share and backup kinds)', () => {
  it('opens a package sealed by core to this key, for each kind, and zeroes the seed', async () => {
    const s = setup();
    const pub = await s.keys.create(s.id);
    for (const kind of ['share', 'backup'] as const) {
      const pt = randomBytes(32);
      const ad = randomBytes(16);
      const pkg = await sealPackage(kind, pub.xwing, pt, ad);
      expect(pkg.suite).toBe(XWING_SUITE);
      expect(bytesToHex(await s.keys.open(s.id, kind, pkg, ad))).toBe(bytesToHex(pt));
    }
  });

  it('refuses another kind, a tampered ciphertext, other AAD and an unknown suite', async () => {
    const s = setup();
    const pub = await s.keys.create(s.id);
    const ad = randomBytes(8);
    const pkg = await sealPackage('share', pub.xwing, randomBytes(32), ad);
    await expect(s.keys.open(s.id, 'backup', pkg, ad)).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });
    await expect(s.keys.open(s.id, 'share', pkg, randomBytes(8))).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });
    const ct = pkg.ct.slice();
    ct[0] = (ct[0] ?? 0) ^ 1;
    await expect(s.keys.open(s.id, 'share', { ...pkg, ct }, ad)).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });
    await expect(s.keys.open(s.id, 'share', { ...pkg, suite: 'x' }, ad)).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    });
    // @ts-expect-error: only the share and backup kinds open inside the vault.
    await expect(s.keys.open(s.id, 'zk-salt', pkg, ad)).rejects.toMatchObject({ code: 'INPUT_INVALID' });
  });

  it('the vault key interoperates with core openPackage given the same seed', async () => {
    const seeds = captureSeeds();
    const s = setup();
    const pub = await s.keys.create(s.id);
    const xwSeed = seeds.copies[1] as Uint8Array;
    const ad = randomBytes(4);
    const pkg = await sealPackage('backup', pub.xwing, randomBytes(32), ad);
    expect((await openPackage('backup', pkg, xwSeed, ad)).ok).toBe(true);
  });
});

type Tc = Record<string, string | number | boolean>;
type Acvp = { testGroups: (Record<string, unknown> & { tests: Tc[] })[] };
const h = (t: Tc, k: string) => hexToBytes(String(t[k]));

describe('P4.9-08 known-answer vectors in the browser (T-U-27 inputs)', () => {
  it('ML-DSA-65 keyGen from the seed equals the ACVP vectors', () => {
    let n = 0;
    for (const g of (keyGenVectors as Acvp).testGroups.filter((g) => g.parameterSet === 'ML-DSA-65'))
      for (const t of g.tests) {
        const k = ml_dsa65.keygen(h(t, 'seed'));
        expect(bytesToHex(k.publicKey)).toBe(String(t.pk).toLowerCase());
        expect(bytesToHex(k.secretKey)).toBe(String(t.sk).toLowerCase());
        n++;
      }
    expect(n).toBeGreaterThan(0);
  });

  it('deterministic ML-DSA-65 sigGen with a context equals the ACVP vectors', () => {
    let n = 0;
    for (const g of (sigGenVectors as Acvp).testGroups.filter((g) => !g.externalMu))
      for (const t of g.tests) {
        const sig = ml_dsa65.sign(h(t, 'message'), h(t, 'sk'), { context: h(t, 'context'), extraEntropy: false });
        expect(bytesToHex(sig)).toBe(String(t.signature).toLowerCase());
        n++;
      }
    expect(n).toBeGreaterThan(0);
  });

  it('X-Wing draft-11 vectors: keys and shared secrets', () => {
    expect(xwingVectors).toHaveLength(3);
    for (const v of xwingVectors) {
      const sk = hexToBytes(v.sk);
      expect(bytesToHex(ml_kem768_x25519.getPublicKey(sk))).toBe(v.pk);
      expect(bytesToHex(ml_kem768_x25519.decapsulate(hexToBytes(v.ct), sk))).toBe(v.ss);
    }
  });
});
