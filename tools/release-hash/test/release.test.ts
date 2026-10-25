import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KeyId } from '@legx/contracts/values';
import { generateNodeSignerKeys, nodeSigner } from '@legx/signer';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { hashDir } from '../src/build.ts';
import { cspHash, injectSri, manifestHash } from '../src/manifest.ts';
import { compareVersions, type ReleaseBody, ReleaseError, signRelease, verifyRelease } from '../src/release.ts';

const keys = generateNodeSignerKeys(KeyId.parse('release-ed'), KeyId.parse('release-ml'));
const signer = nodeSigner(keys);
const pub = async () => {
  const p = await signer.publicKeys();
  return { ed25519: p.ed25519, mlDsa65: p.mlDsa65 };
};
const body = (files: Record<string, string>): ReleaseBody => ({
  schema: 'legx/release/v1',
  version: '1.2.0',
  minVersion: '1.0.0',
  appOrigin: 'https://app.example',
  files,
  manifestHash: manifestHash(files),
});
const hex = (s: string) => bytesToHex(sha256(new TextEncoder().encode(s)));

describe('manifest', () => {
  it('P4.10-02 the hash does not depend on file order and changes with any byte, name or extra file', () => {
    fc.assert(
      fc.property(
        fc.dictionary(fc.stringMatching(/^[a-z]{1,6}\.js$/), fc.string({ minLength: 1 }), { minKeys: 1, maxKeys: 5 }),
        fc.string({ minLength: 1 }),
        (raw, other) => {
          const files = Object.fromEntries(Object.entries(raw).map(([k, v]) => [k, hex(v)]));
          const reversed = Object.fromEntries(Object.entries(files).reverse());
          expect(manifestHash(reversed)).toBe(manifestHash(files));
          const [first] = Object.keys(files) as [string];
          expect(manifestHash({ ...files, [first]: hex(`${raw[first]}${other}`) })).not.toBe(manifestHash(files));
          expect(manifestHash({ ...files, 'extra.js': hex(other) })).not.toBe(manifestHash(files));
          const { [first]: moved, ...rest } = files;
          expect(manifestHash({ ...rest, [`x${first}`]: moved as string })).not.toBe(manifestHash(files));
        },
      ),
    );
  });

  it('hashDir lists every file with a relative path, sorted, and skips the release files', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'rh-'));
    mkdirSync(join(dir, 'assets'));
    writeFileSync(join(dir, 'index.html'), 'h');
    writeFileSync(join(dir, 'assets', 'a.js'), 'a');
    writeFileSync(join(dir, 'release.json'), '{}');
    writeFileSync(join(dir, '_headers'), 'x');
    const files = await hashDir(dir);
    expect(Object.keys(files)).toEqual(['assets/a.js', 'index.html']);
    expect(files['index.html']).toBe(hex('h'));
  });

  it('injectSri adds a sha256 integrity to each local script and stylesheet, and CSP hashes match', () => {
    const html =
      '<script type="module" crossorigin src="./assets/a.js"></script><link rel="stylesheet" href="./assets/b.css">';
    const bytes: Record<string, Uint8Array> = {
      'assets/a.js': new TextEncoder().encode('a'),
      'assets/b.css': new TextEncoder().encode('b'),
    };
    const out = injectSri(html, (p) => bytes[p]);
    expect(out).toContain(`integrity="${cspHash(hex('a'))}"`);
    expect(out).toContain(`integrity="${cspHash(hex('b'))}"`);
    expect(cspHash(hex('a'))).toMatch(/^sha256-[A-Za-z0-9+/]{43}=$/);
  });

  it('injectSri refuses a foreign script or stylesheet', () => {
    expect(() => injectSri('<script src="https://evil.example/x.js"></script>', () => undefined)).toThrow();
    expect(() => injectSri('<script>alert(1)</script>', () => undefined)).toThrow();
  });
});

describe('release.json', () => {
  const files = { 'index.html': hex('h'), 'assets/a.js': hex('a') };

  it('P4.10-02 a signed release verifies; the manifest hash is bound', async () => {
    const rel = await signRelease(signer, body(files));
    expect(verifyRelease(rel, await pub()).version).toBe('1.2.0');
    const swapped = { ...rel, body: { ...rel.body, files: { ...files, 'assets/a.js': hex('evil') } } };
    const p = await pub();
    expect(() => verifyRelease(swapped, p)).toThrow(ReleaseError);
  });

  it('refuses a changed field, a missing half, a wrong key, and a signature from another context', async () => {
    const rel = await signRelease(signer, body(files));
    const p = await pub();
    const codeOf = (fn: () => unknown) => {
      try {
        fn();
      } catch (e) {
        return e instanceof ReleaseError ? e.code : 'OTHER';
      }
      return 'NONE';
    };
    expect(codeOf(() => verifyRelease({ ...rel, body: { ...rel.body, version: '9.9.9' } }, p))).toBe('SIGNATURE');
    expect(codeOf(() => verifyRelease({ ...rel, body: { ...rel.body, appOrigin: 'https://evil.example' } }, p))).toBe(
      'SIGNATURE',
    );
    expect(codeOf(() => verifyRelease({ ...rel, mlDsa65: '' }, p))).toBe('FORMAT');
    expect(codeOf(() => verifyRelease(rel, { ...p, ed25519: new Uint8Array(32).fill(1) }))).toBe('SIGNATURE');
    expect(codeOf(() => verifyRelease(rel, { ...p, mlDsa65: new Uint8Array(1952).fill(1) }))).toBe('SIGNATURE');
    expect(codeOf(() => verifyRelease({ ...rel, extra: 1 }, p))).toBe('FORMAT');
    const wrongHash = { ...rel, body: { ...rel.body, manifestHash: '0'.repeat(64) } };
    expect(codeOf(() => verifyRelease(wrongHash, p))).toBe('MANIFEST');
  });

  it('refuses a minVersion above the version', async () => {
    const rel = await signRelease(signer, { ...body(files), version: '1.0.0', minVersion: '2.0.0' });
    expect(() => verifyRelease(rel, { ed25519: new Uint8Array(), mlDsa65: new Uint8Array() })).toThrow(
      expect.objectContaining({ code: 'VERSION' }),
    );
  });

  it('compares versions numerically', () => {
    expect(compareVersions('1.10.0', '1.9.0')).toBeGreaterThan(0);
    expect(compareVersions('1.0.0', '1.0.0')).toBe(0);
    expect(compareVersions('0.9.9', '1.0.0')).toBeLessThan(0);
  });
});
