// T-U-12 (P1.3-03): every vendored vector file runs through our functions and a second implementation.
// Vector sources and licences: packages/core/vectors/README.md.
import { createHash, createPublicKey, hkdfSync, verify as nodeVerify } from 'node:crypto';
import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { ed25519 } from '@noble/curves/ed25519.js';
import { extract, hkdf } from '@noble/hashes/hkdf.js';
import { sha1 } from '@noble/hashes/legacy.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';
import {
  bytesToHex,
  hexToBytes,
  inclusionPath,
  makeCondition,
  mth,
  randomBytes,
  verifyBinding,
  verifyInclusion,
} from '../src/dealcore.ts';
import { listFiles, readJson, VECTORS } from './helpers/vectors.ts';

const b64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));
const b64url = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));

// Our strict Ed25519 verifier: verifyBinding uses `zip215: false` (RFC 8032 strict). It takes a hex key with a 2 byte prefix.
function strict(pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  try {
    return verifyBinding(`ED${bytesToHex(pk)}`, msg, sig);
  } catch {
    return false;
  }
}
// Second implementation: OpenSSL through Node crypto. SPKI prefix for Ed25519: RFC 8410 section 4.
function nodeEd25519(pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  try {
    const key = createPublicKey({
      key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pk]),
      format: 'der',
      type: 'spki',
    });
    return nodeVerify(null, msg, key, sig);
  } catch {
    return false;
  }
}

describe('T-U-12 Wycheproof Ed25519 (strict, zip215:false)', () => {
  type Test = { tcId: number; comment: string; flags: string[]; msg: string; sig: string; result: string };
  type File = { testGroups: { publicKey: { pk: string }; tests: Test[] }[] };
  const cases = readJson<File>('wycheproof', 'ed25519_test.json').testGroups.flatMap((g) =>
    g.tests.map((t) => ({ ...t, pk: g.publicKey.pk })),
  );
  const ours = (t: (typeof cases)[number]) => strict(hexToBytes(t.pk), hexToBytes(t.msg), hexToBytes(t.sig));
  const zip215 = (t: (typeof cases)[number]) => {
    try {
      return ed25519.verify(hexToBytes(t.sig), hexToBytes(t.msg), hexToBytes(t.pk), { zip215: true });
    } catch {
      return false;
    }
  };
  const ids = (from: number, to: number) => Array.from({ length: to - from + 1 }, (_, i) => from + i);

  it('has 210 vectors: 117 valid, 64 invalid, 29 acceptable', () => {
    const n = (r: string) => cases.filter((t) => t.result === r).length;
    expect([cases.length, n('valid'), n('invalid'), n('acceptable')]).toEqual([210, 117, 64, 29]);
  });

  it('disagreements with Wycheproof "result" on valid and invalid cases: none', () => {
    // A disagreement is a "valid" case we reject or an "invalid" case we accept. Run on 24 Oct 2026, noble 2.4.0:
    // there are none. If a library upgrade changes this, every tcId needs a written reason here, so the list is pinned.
    const disagreements = cases.filter((t) => (t.result === 'valid' ? !ours(t) : t.result === 'invalid' && ours(t)));
    expect(disagreements.map((t) => t.tcId)).toEqual([]);
  });

  it('"acceptable" cases: strict rejects small-order keys (152 to 159) and accepts mixed-order keys (160 to 180)', () => {
    // Wycheproof allows both answers for these. Our rule (RFC 8032 section 5.1.7 with noble zip215:false) is pinned:
    // 152 to 159 are the eight small-order (torsion) public keys, including the identity (the universal forgery key):
    // noble rejects a small-order A in strict mode. 160 to 180 are a prime-order point plus a torsion point: the
    // cofactorless check passes them and noble does not reject mixed-order keys, so a signer who made the key could
    // use them. The deal never accepts a key that a party did not derive itself, so this is not a gap for the design.
    const acceptable = cases.filter((t) => t.result === 'acceptable');
    expect(acceptable.map((t) => t.tcId)).toEqual(ids(152, 180));
    expect(acceptable.filter((t) => !ours(t)).map((t) => t.tcId)).toEqual(ids(152, 159));
    expect(acceptable.filter(ours).map((t) => t.tcId)).toEqual(ids(160, 180));
  });

  it('ZIP-215 (the noble default) accepts case 151, which Wycheproof marks invalid, and 152 to 180; strict rejects 151', () => {
    // This is why `zip215: false` is a hard rule (DESIGN 0, IMPLEMENTATION 1.3 rule 4): the default verifier
    // accepts tcId 151 (a non-canonical encoding), the reason strict mode exists.
    const lenient = cases.filter((t) => t.result !== 'valid' && zip215(t));
    expect(lenient.map((t) => t.tcId)).toEqual(ids(151, 180));
    expect(ours(cases.find((t) => t.tcId === 151) as (typeof cases)[number])).toBe(false);
  });

  it('second implementation (Node crypto, OpenSSL) gives the same verdict as ours on all 210 cases except 160 to 180', () => {
    // OpenSSL also accepts mixed-order keys (160 to 180 verdict true), so the two agree everywhere; it additionally
    // rejects 152 to 159 like ours. Any difference at all fails this test.
    const diff = cases
      .filter((t) => nodeEd25519(hexToBytes(t.pk), hexToBytes(t.msg), hexToBytes(t.sig)) !== ours(t))
      .map((t) => t.tcId);
    expect(diff).toEqual([]);
  });
});

describe('T-U-12 Ed25519 edge cases: ed25519-speccheck and noble zip215.json', () => {
  type Spec = { message: string; pub_key: string; signature: string };
  const spec = readJson<Spec[]>('ed25519', 'speccheck-cases.json');
  const run = (c: Spec) => strict(hexToBytes(c.pub_key), hexToBytes(c.message), hexToBytes(c.signature));
  const node = (c: Spec) => nodeEd25519(hexToBytes(c.pub_key), hexToBytes(c.message), hexToBytes(c.signature));

  it('speccheck: strict rejects 0, 1, 6 to 11 and accepts 2 to 5', () => {
    // Case table: https://github.com/novifinancial/ed25519-speccheck#condition-table
    // 0 and 1: small-order A. 6 and 7: S >= L. 8 and 9: non-canonical R. 10 and 11: non-canonical A.
    // 2 to 5 are valid under both the cofactored and the cofactorless equation.
    expect(spec).toHaveLength(12);
    expect(spec.map(run)).toEqual([false, false, true, true, true, true, false, false, false, false, false, false]);
  });

  it('speccheck: ZIP-215 accepts 0 to 5 and 9 to 11, so strict differs on exactly 0, 1, 9, 10, 11', () => {
    const zip = spec.map((c) => ed25519.verify(hexToBytes(c.signature), hexToBytes(c.message), hexToBytes(c.pub_key)));
    expect(zip).toEqual([true, true, true, true, true, true, false, false, false, true, true, true]);
    expect(spec.flatMap((c, i) => (zip[i] !== run(c) ? [i] : []))).toEqual([0, 1, 9, 10, 11]);
  });

  it('speccheck: second implementation (Node crypto) accepts only case 3, so it is stricter than ours on 2, 4 and 5', () => {
    // OpenSSL rejects 2 (small-order R), 4 and 5 (the cofactored cases). It never accepts a case we reject.
    expect(spec.map(node)).toEqual([false, false, false, true, false, false, false, false, false, false, false, false]);
    expect(spec.every((c) => !node(c) || run(c))).toBe(true);
  });

  it('noble zip215.json: strict rejects all 196 entries that ZIP-215 accepts', () => {
    type Z = { vk_bytes: string; sig_bytes: string; valid_legacy: boolean; valid_zip215: boolean };
    const zs = readJson<Z[]>('ed25519', 'noble-zip215.json');
    const msg = new TextEncoder().encode('Zcash');
    expect(zs).toHaveLength(196);
    for (const [i, z] of zs.entries()) {
      const pk = hexToBytes(z.vk_bytes);
      const sig = hexToBytes(z.sig_bytes);
      expect(ed25519.verify(sig, msg, pk, { zip215: true }), `zip215 entry ${i}`).toBe(z.valid_zip215);
      expect(strict(pk, msg, sig), `strict entry ${i}`).toBe(false);
      expect(nodeEd25519(pk, msg, sig), `node entry ${i}`).toBe(false);
    }
  });
});

describe('T-U-12 HKDF: Wycheproof hkdf_sha256 and RFC 5869 Appendix A', () => {
  type Test = { tcId: number; ikm: string; salt: string; info: string; size: number; okm: string; result: string };
  const tests = readJson<{ testGroups: { tests: Test[] }[] }>('wycheproof', 'hkdf_sha256_test.json').testGroups.flatMap(
    (g) => g.tests,
  );
  // Our HKDF is noble `hkdf`, the function dealcore.ts calls for the deal stamp and the x-key. Second implementation: Node crypto.
  const nodeHkdf = (algo: string, t: { ikm: string; salt: string; info: string; size: number }) =>
    Buffer.from(hkdfSync(algo, hexToBytes(t.ikm), hexToBytes(t.salt), hexToBytes(t.info), t.size)).toString('hex');

  it('has 86 vectors', () => expect(tests).toHaveLength(86));

  it('valid cases: noble and Node crypto both give the expected OKM', () => {
    const valid = tests.filter((t) => t.result === 'valid');
    expect(valid.length).toBeGreaterThan(0);
    for (const t of valid) {
      const out = bytesToHex(hkdf(sha256, hexToBytes(t.ikm), hexToBytes(t.salt), hexToBytes(t.info), t.size));
      expect(out, `tcId ${t.tcId}`).toBe(t.okm);
      expect(nodeHkdf('sha256', t), `node tcId ${t.tcId}`).toBe(t.okm);
    }
  });

  it('invalid cases (output longer than 255 blocks): both implementations throw', () => {
    const invalid = tests.filter((t) => t.result === 'invalid');
    expect(invalid.length).toBeGreaterThan(0);
    for (const t of invalid) {
      expect(
        () => hkdf(sha256, hexToBytes(t.ikm), hexToBytes(t.salt), hexToBytes(t.info), t.size),
        `${t.tcId}`,
      ).toThrow();
      expect(() => nodeHkdf('sha256', t), `node ${t.tcId}`).toThrow();
    }
  });

  it('RFC 5869 A.1 to A.7 (SHA-256 and SHA-1), including the PRK', () => {
    type Rfc = {
      name: string;
      hash: string;
      ikm: string;
      salt: string;
      info: string;
      length: number;
      prk: string;
      okm: string;
    };
    const rfc = readJson<Rfc[]>('hkdf', 'rfc5869-appendix-a.json');
    expect(rfc.map((r) => r.name)).toEqual(['A.1', 'A.2', 'A.3', 'A.4', 'A.5', 'A.6', 'A.7']);
    for (const r of rfc) {
      const fn = r.hash === 'SHA-256' ? sha256 : sha1;
      const ikm = hexToBytes(r.ikm);
      expect(bytesToHex(extract(fn, ikm, hexToBytes(r.salt))), `${r.name} prk`).toBe(r.prk);
      expect(bytesToHex(hkdf(fn, ikm, hexToBytes(r.salt), hexToBytes(r.info), r.length)), r.name).toBe(r.okm);
      expect(nodeHkdf(r.hash === 'SHA-256' ? 'sha256' : 'sha1', { ...r, size: r.length }), `node ${r.name}`).toBe(
        r.okm,
      );
    }
  });

  it('Wycheproof tcIds 1 to 3 are the SHA-256 cases of RFC 5869 (A.1 to A.3, in the order A.1, A.3, A.2)', () => {
    const rfc = readJson<{ okm: string }[]>('hkdf', 'rfc5869-appendix-a.json');
    expect(tests.slice(0, 3).map((t) => t.okm)).toEqual([0, 2, 1].map((i) => rfc[i]?.okm));
  });
});

describe('T-U-12 Merkle: transparency-dev/merkle testdata', () => {
  // The testdata trees are prefixes of the eight RFC 6962 reference leaves (transparency-dev/merkle testonly).
  const LEAVES = [
    '',
    '00',
    '10',
    '2021',
    '3031',
    '40414243',
    '5051525354555657',
    '606162636465666768696a6b6c6d6e6f',
  ].map(hexToBytes);
  const leafAt = (i: number): Uint8Array => LEAVES[i] ?? new Uint8Array();
  const leafHash = (d: Uint8Array) =>
    createHash('sha256')
      .update(Buffer.from([0]))
      .update(d)
      .digest('hex');

  type Inc = {
    leafIdx: number;
    treeSize: number;
    root: string;
    leafHash: string;
    proof: string[] | null;
    wantErr: boolean;
  };
  const files: string[] = [];
  for (const dir of listFiles('merkle', 'inclusion')) {
    const sub = join('inclusion', dir);
    for (const f of readdirSync(join(VECTORS, 'merkle', sub), { recursive: true, encoding: 'utf8' }))
      if (f.endsWith('.json')) files.push(join(sub, f));
  }
  const cases = files.map((f) => ({ f, ...readJson<Inc>('merkle', f) }));
  const RUNNABLE = 62;

  it('has the 98 inclusion vectors', () => expect(cases.length).toBe(98));

  // The "single-entry" vectors use a leaf of unknown data, so only their hashes are available.
  const onReferenceLeaves = cases.filter((c) => {
    const data = LEAVES[c.leafIdx];
    return data !== undefined && Buffer.from(b64(c.leafHash)).toString('hex') === leafHash(data);
  });

  it('our tree matches the roots and proofs of every happy-path vector', () => {
    const happy = onReferenceLeaves.filter((c) => !c.wantErr);
    expect(happy.length).toBeGreaterThan(0);
    for (const c of happy) {
      const tree = LEAVES.slice(0, c.treeSize);
      expect(bytesToHex(mth(tree)), c.f).toBe(Buffer.from(b64(c.root)).toString('hex'));
      expect(bytesToHex(mth([leafAt(c.leafIdx)])), c.f).toBe(Buffer.from(b64(c.leafHash)).toString('hex'));
      expect(inclusionPath(c.leafIdx, tree).map(bytesToHex), c.f).toEqual(
        (c.proof ?? []).map((p) => Buffer.from(b64(p)).toString('hex')),
      );
    }
  });

  it('verifyInclusion accepts the happy path and rejects every wantErr case it can express', () => {
    // verifyInclusion takes leaf data, not a leaf hash. A vector is runnable when its leafHash is the hash of the
    // reference leaf at leafIdx. The others carry a hash we cannot invert (wrong-leaf, random-leaf, empty leaf and the
    // single-entry set) and stay unrun. The count is pinned so a silent drop shows up.
    for (const c of onReferenceLeaves) {
      const ok = verifyInclusion(leafAt(c.leafIdx), c.leafIdx, c.treeSize, (c.proof ?? []).map(b64), b64(c.root));
      expect(ok, c.f).toBe(!c.wantErr);
    }
    expect(onReferenceLeaves.length).toBe(RUNNABLE);
    expect(cases.length - onReferenceLeaves.length).toBe(98 - RUNNABLE);
  });
});

describe('T-U-12 crypto-conditions valid vectors 0000 to 0017', () => {
  type Vec = {
    json: { type: string; preimage?: string; publicKey?: string; signature?: string };
    fulfillment: string;
    conditionBinary: string;
    fingerprintContents: string;
    message: string;
  };
  const files = listFiles('crypto-conditions');
  const vecs = files.map((f) => ({ f, ...readJson<Vec>('crypto-conditions', f) }));

  it('has the 18 valid vectors', () => expect(files).toHaveLength(18));

  it('every condition binary carries SHA-256(fingerprint contents) (second implementation: Node crypto)', () => {
    // conditionBinary = <type tag> <len> 80 20 <fingerprint> 81 .. <cost>. Source: draft-thomas-crypto-conditions-04 section 7.
    for (const v of vecs) {
      const fp = createHash('sha256').update(Buffer.from(v.fingerprintContents, 'hex')).digest('hex').toUpperCase();
      expect(v.conditionBinary, v.f).toContain(`8020${fp}`);
    }
  });

  it('our 32 byte preimage condition has the same layout as the preimage vectors', () => {
    // makeCondition accepts 32 byte preimages only, and the two vendored preimage vectors have 0 and 3 bytes
    // (0000 and 0005). They cannot go through makeCondition as is. So we check the layout the vectors show,
    // A0 25 80 20 <sha256(preimage)> 81 01 <cost> and fulfillment A0 <len> 80 <len> <preimage>, against the vectors
    // and then check that our function produces the same layout for a 32 byte preimage.
    const pre = vecs.filter((v) => v.json.type === 'preimage-sha-256');
    expect(pre.map((v) => v.f.slice(0, 4))).toEqual(['0000', '0005']);
    for (const v of pre) {
      const p = Buffer.from(v.json.preimage ?? '', 'base64');
      const fp = createHash('sha256').update(p).digest('hex').toUpperCase();
      expect(v.conditionBinary.startsWith(`A0258020${fp}8101`), v.f).toBe(true);
      expect(v.fulfillment, v.f).toBe(
        `A0${(p.length + 2).toString(16).padStart(2, '0')}80${p.length.toString(16).padStart(2, '0')}${p.toString('hex').toUpperCase()}`,
      );
    }
    const preimage = randomBytes(32);
    const { condition, fulfillment } = makeCondition(preimage);
    const fp = createHash('sha256').update(preimage).digest('hex').toUpperCase();
    expect(condition).toBe(`A0258020${fp}810120`);
    expect(fulfillment).toBe(`A0228020${Buffer.from(preimage).toString('hex').toUpperCase()}`);
    expect(() => makeCondition(new Uint8Array(3))).toThrow();
  });

  it('ed25519-sha-256 vectors: the fulfillment signature verifies under strict Ed25519 and Node crypto', () => {
    const ed = vecs.filter((v) => v.json.type === 'ed25519-sha-256');
    expect(ed.map((v) => v.f.slice(0, 4))).toEqual(['0004', '0015']);
    for (const v of ed) {
      const pk = b64url(v.json.publicKey ?? '');
      const sig = b64url(v.json.signature ?? '');
      const msg = hexToBytes(v.message);
      expect(strict(pk, msg, sig), v.f).toBe(true);
      expect(nodeEd25519(pk, msg, sig), `node ${v.f}`).toBe(true);
    }
  });

  it('the other types (prefix, threshold, rsa) are outside our code and stay as files', () => {
    expect(vecs.filter((v) => !['preimage-sha-256', 'ed25519-sha-256'].includes(v.json.type))).toHaveLength(14);
  });
});
