// X-Wing HPKE packages for backups and share transport (DESIGN 6.13): T-U-27b, T-U-27c, P1.16-07, P1.16-08.
// Source: https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/ (draft-11, Appendix C test vectors)
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core';
import { XWing } from '@hpke/hybridkem-x-wing';
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { hpkeSuite, openPackage, PACKAGE_SUITES, type SealedPackage, sealPackage, XWING_SUITE } from '../src/pq.ts';
import { readJson } from './helpers/vectors.ts';

const xwing = PACKAGE_SUITES[XWING_SUITE] as NonNullable<(typeof PACKAGE_SUITES)[string]>;
const aad = utf8ToBytes('deal:0192f6a0-0000-7000-8000-000000000000');

describe('T-U-27b X-Wing round trip', () => {
  it('a backup and a share-transport package open to the input', async () => {
    const { publicKey, secretKey } = await xwing.keygen();
    expect([publicKey.length, secretKey.length]).toEqual([1216, 32]);
    const share = randomBytes(32);
    const pkg = await sealPackage('share', publicKey, share, aad);
    expect(pkg.suite).toBe('hpke-xwing-v1');
    expect(pkg.enc.length + pkg.ct.length).toBe(1168); // DESIGN 6.13: a 32-byte share encrypts to 1,168 bytes
    expect(await openPackage('share', pkg, secretKey, aad)).toEqual({ ok: true, plaintext: share });
    const backup = randomBytes(5000);
    const b = await sealPackage('backup', publicKey, backup, aad);
    expect(await openPackage('backup', b, secretKey, aad)).toEqual({ ok: true, plaintext: backup });
  });

  it('a backup package never opens as a share-transport package (the info is fixed per kind)', async () => {
    const { publicKey, secretKey } = await xwing.keygen();
    const pkg = await sealPackage('backup', publicKey, randomBytes(32), aad);
    expect(await openPackage('share', pkg, secretKey, aad)).toEqual({ ok: false, code: 'OPEN_FAILED' });
  });
});

describe('package kinds: identity boxes (1.17), the release-code handover (OD-28) and chip-link (4.6)', () => {
  it('each kind round trips, and no kind opens as another', async () => {
    const { publicKey, secretKey } = await xwing.keygen();
    const kinds = ['backup', 'share', 'zk-salt', 'zk-disclosure', 'release-code-handover', 'chip-link'] as const;
    for (const kind of kinds) {
      const pt = randomBytes(32);
      const pkg = await sealPackage(kind, publicKey, pt, aad);
      expect(await openPackage(kind, pkg, secretKey, aad)).toEqual({ ok: true, plaintext: pt });
      for (const other of kinds.filter((k) => k !== kind)) {
        expect(await openPackage(other, pkg, secretKey, aad), `${kind} as ${other}`).toEqual({
          ok: false,
          code: 'OPEN_FAILED',
        });
      }
    }
  });

  it('uses the info strings already in use (zkIdentity.ts, OD-28 console and test, chip-link), so existing boxes open', async () => {
    const { publicKey, secretKey } = await xwing.keygen();
    const pt = randomBytes(32);
    for (const [kind, info] of [
      ['zk-salt', 'legx/hpke/zk-salt/v1'],
      ['zk-disclosure', 'legx/hpke/zk-disclosure/v1'],
      ['release-code-handover', 'legx/hpke/release-code-handover/v1'],
      ['chip-link', 'legx/chip-link/v1'],
    ] as const) {
      const raw = await xwing.seal(publicKey, pt, utf8ToBytes(info), aad);
      expect(await openPackage(kind, { suite: XWING_SUITE, ...raw }, secretKey, aad)).toEqual({
        ok: true,
        plaintext: pt,
      });
    }
  });
});

describe('T-U-27c X-Wing tamper: open fails as a whole, with no partial output', () => {
  const flip = (b: Uint8Array, i: number) => Uint8Array.from(b, (x, j) => (j === i ? x ^ 1 : x));
  it('one flipped byte in the encapsulated key, the ciphertext, the tag or the associated data', async () => {
    const { publicKey, secretKey } = await xwing.keygen();
    const pkg = await sealPackage('share', publicKey, randomBytes(64), aad);
    const cases: [string, SealedPackage, Uint8Array][] = [
      ['enc (ML-KEM part)', { ...pkg, enc: flip(pkg.enc, 7) }, aad],
      ['enc (X25519 part)', { ...pkg, enc: flip(pkg.enc, pkg.enc.length - 1) }, aad],
      ['ciphertext', { ...pkg, ct: flip(pkg.ct, 0) }, aad],
      ['tag', { ...pkg, ct: flip(pkg.ct, pkg.ct.length - 1) }, aad],
      ['aad', pkg, flip(aad, 3)],
      ['truncated', { ...pkg, ct: pkg.ct.subarray(0, 10) }, aad],
      ['empty enc', { ...pkg, enc: new Uint8Array(0) }, aad],
    ];
    for (const [name, p, a] of cases) {
      expect(await openPackage('share', p, secretKey, a), name).toEqual({ ok: false, code: 'OPEN_FAILED' });
    }
    const other = await xwing.keygen();
    expect(await openPackage('share', pkg, other.secretKey, aad)).toEqual({ ok: false, code: 'OPEN_FAILED' });
  });

  it('property: any single flipped bit of enc or ct fails', async () => {
    const { publicKey, secretKey } = await xwing.keygen();
    const pkg = await sealPackage('share', publicKey, randomBytes(32), aad);
    await fc.assert(
      fc.asyncProperty(fc.boolean(), fc.nat(), fc.integer({ min: 0, max: 7 }), async (inEnc, at, bit) => {
        const field = inEnc ? pkg.enc : pkg.ct;
        const i = at % field.length;
        const bad = Uint8Array.from(field, (x, j) => (j === i ? x ^ (1 << bit) : x));
        const r = await openPackage('share', inEnc ? { ...pkg, enc: bad } : { ...pkg, ct: bad }, secretKey, aad);
        return !r.ok && r.code === 'OPEN_FAILED';
      }),
      { numRuns: 40 },
    );
  }, 60_000); // X-Wing runs are slower under coverage
});

describe('P1.16-07 suite tag', () => {
  it('a package with an unknown tag is refused with SUITE_UNKNOWN, including prototype names', async () => {
    const { publicKey, secretKey } = await xwing.keygen();
    const pkg = await sealPackage('share', publicKey, randomBytes(32), aad);
    for (const suite of ['hpke-xwing-v2', '', '__proto__', 'constructor', 'toString']) {
      expect(await openPackage('share', { ...pkg, suite }, secretKey, aad)).toEqual({
        ok: false,
        code: 'SUITE_UNKNOWN',
      });
    }
    await expect(sealPackage('share', publicKey, randomBytes(32), aad, 'hpke-xwing-v2')).rejects.toThrow(
      'SUITE_UNKNOWN',
    );
  });

  it('a second registered suite: a swap is a data change, and each package opens with its own suite', async () => {
    const classical = hpkeSuite(
      new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() }),
    );
    const suites = { ...PACKAGE_SUITES, 'hpke-x25519-test': classical };
    const ck = await classical.keygen();
    const xk = await xwing.keygen();
    const pt = randomBytes(32);
    const old = await sealPackage('backup', ck.publicKey, pt, aad, 'hpke-x25519-test', suites);
    const now = await sealPackage('backup', xk.publicKey, pt, aad, XWING_SUITE, suites);
    expect(await openPackage('backup', old, ck.secretKey, aad, suites)).toEqual({ ok: true, plaintext: pt });
    expect(await openPackage('backup', now, xk.secretKey, aad, suites)).toEqual({ ok: true, plaintext: pt });
    expect(await openPackage('backup', old, ck.secretKey, aad)).toEqual({ ok: false, code: 'SUITE_UNKNOWN' });
  });
});

describe('P1.16-08 @hpke/hybridkem-x-wing against noble ml_kem768_x25519', () => {
  const vectors = readJson<{ seed: string; eseed: string; ss: string; sk: string; pk: string; ct: string }[]>(
    'pq',
    'xwing-draft-11.json',
  );
  const kem = new XWing();

  it('both libraries reproduce the draft-11 vectors (keys, ciphertext, shared secret, decapsulation)', async () => {
    expect(vectors).toHaveLength(3);
    expect(kem.id).toBe(0x647a);
    for (const v of vectors) {
      const n = ml_kem768_x25519.keygen(hexToBytes(v.seed));
      expect(bytesToHex(n.publicKey)).toBe(v.pk);
      expect(bytesToHex(n.secretKey)).toBe(v.sk);
      const ne = ml_kem768_x25519.encapsulate(hexToBytes(v.pk), hexToBytes(v.eseed));
      expect([bytesToHex(ne.cipherText), bytesToHex(ne.sharedSecret)]).toEqual([v.ct, v.ss]);
      expect(bytesToHex(ml_kem768_x25519.decapsulate(hexToBytes(v.ct), hexToBytes(v.sk)))).toBe(v.ss);

      const kp = await kem.generateKeyPairDerand(hexToBytes(v.seed));
      expect(bytesToHex(new Uint8Array(await kem.serializePublicKey(kp.publicKey)))).toBe(v.pk);
      const he = await kem.encap({ recipientPublicKey: kp.publicKey, ekm: hexToBytes(v.eseed).buffer as ArrayBuffer });
      expect([bytesToHex(new Uint8Array(he.enc)), bytesToHex(new Uint8Array(he.sharedSecret))]).toEqual([v.ct, v.ss]);
      const hd = await kem.decap({ recipientKey: kp.privateKey, enc: hexToBytes(v.ct) });
      expect(bytesToHex(new Uint8Array(hd))).toBe(v.ss);
    }
  });

  it('a package sealed by @hpke to a noble key opens with the noble secret key, and noble decapsulates its enc', async () => {
    const n = ml_kem768_x25519.keygen();
    const pt = randomBytes(32);
    const pkg = await sealPackage('share', n.publicKey, pt, aad);
    expect(await openPackage('share', pkg, n.secretKey, aad)).toEqual({ ok: true, plaintext: pt });
    const viaNoble = ml_kem768_x25519.decapsulate(pkg.enc, n.secretKey);
    const viaHpke = await kem.decap({ recipientKey: await kem.deserializePrivateKey(n.secretKey), enc: pkg.enc });
    expect(bytesToHex(viaNoble)).toBe(bytesToHex(new Uint8Array(viaHpke)));
  });
});
