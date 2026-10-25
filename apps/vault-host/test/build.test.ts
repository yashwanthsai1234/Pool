import { execFileSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { cspHash, manifestHash, verifyRelease } from '@legx/release-hash';
import { hashDir } from '@legx/release-hash/build';
import { hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { buildBundle, writeHeaders } from '../scripts/build.ts';
import { vaultHostCsp } from '../src/headers.ts';

const cli = new URL('../../../tools/release-hash/src/cli.ts', import.meta.url).pathname;
const tmp = mkdtempSync(join(tmpdir(), 'vault-host-build-'));
const keysDir = join(tmp, 'keys');
execFileSync('node', [cli, 'keygen', '--out', keysDir]);
const keys = JSON.parse(readFileSync(join(keysDir, 'public.json'), 'utf8')) as { ed25519: string; mlDsa65: string };
const releaseUrl = 'https://releases.example/vault/release.json';
const APP = 'https://app.example';

const entry = (files: Record<string, string>) => Object.keys(files).find((p) => p.endsWith('.js')) as string;

describe('the build', () => {
  it('P4.10-01 two builds from different output directories, working directory, time zone and clock give the same bytes', async () => {
    const a = join(tmp, 'a');
    const b = join(tmp, 'b');
    await buildBundle({ outDir: a, releaseUrl, keys });
    const cwd = process.cwd();
    process.chdir(tmp);
    process.env.TZ = 'Pacific/Auckland';
    process.env.SOURCE_DATE_EPOCH = '1';
    try {
      await buildBundle({ outDir: b, releaseUrl, keys });
    } finally {
      process.chdir(cwd);
      delete process.env.TZ;
      delete process.env.SOURCE_DATE_EPOCH;
    }
    const fa = await hashDir(a);
    const fb = await hashDir(b);
    expect(fb).toEqual(fa);
    expect(manifestHash(fb)).toBe(manifestHash(fa));
    for (const p of Object.keys(fa)) expect(readFileSync(join(b, p)).equals(readFileSync(join(a, p)))).toBe(true);
    expect(Object.keys(fa).sort()).toEqual([
      expect.stringMatching(/^assets\/index-.*\.js$/),
      expect.stringMatching(/^assets\/style-.*\.css$/),
      'index.html',
    ]);
    // I-20: xrpl's optional 2.1 MB confidential-transfer WASM is not part of the vault (it only encodes and signs).
    expect(readdirSync(join(a, 'assets')).filter((f) => f.endsWith('.wasm'))).toEqual([]);
  });

  it('P4.10-01 a different release key gives a different bundle (the key is part of the hashed bytes)', async () => {
    const c = join(tmp, 'c');
    await buildBundle({ outDir: c, releaseUrl, keys: { ...keys, ed25519: '00'.repeat(32) } });
    expect(manifestHash(await hashDir(c))).not.toBe(manifestHash(await hashDir(join(tmp, 'a'))));
  });

  it('P4.10-08 the page has no inline script, no foreign URL, and an integrity on every script and stylesheet', async () => {
    const html = readFileSync(join(tmp, 'a', 'index.html'), 'utf8');
    const tags = html.match(/<(script|link)\b[^>]*>/g) ?? [];
    expect(tags.length).toBe(2);
    for (const t of tags) {
      expect(t).toMatch(/integrity="sha256-[A-Za-z0-9+/]{43}="/);
      expect(t).not.toMatch(/(src|href)="(https?:)?\/\//);
    }
    expect(html).not.toMatch(/<script(?![^>]*src=)/);
    expect(html).not.toMatch(/\son[a-z]+=|javascript:/i);
    const css = readFileSync(
      join(tmp, 'a', 'assets', readdirSync(join(tmp, 'a', 'assets')).find((f) => f.endsWith('.css')) as string),
      'utf8',
    );
    expect(css).not.toMatch(/url\(|@import/);
    const files = await hashDir(join(tmp, 'a'));
    for (const t of tags) {
      const ref = /(?:src|href)="\.\/([^"]+)"/.exec(t)?.[1] as string;
      expect(t).toContain(cspHash(files[ref] as string));
    }
  });

  it('P4.10-08 every dependency of the host is pinned to an exact version', () => {
    for (const pkg of ['apps/vault-host', 'tools/release-hash']) {
      const json = JSON.parse(readFileSync(new URL(`../../../${pkg}/package.json`, import.meta.url), 'utf8')) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };
      for (const [name, v] of Object.entries({ ...json.dependencies, ...json.devDependencies })) {
        expect(v, `${pkg} ${name}`).toMatch(/^(workspace:\*|\d+\.\d+\.\d+)$/);
      }
    }
  });
});

describe('P4.10-06 the response headers', () => {
  it('hold the policy of the vault page with the script hash and frame-ancestors for the app origin only', async () => {
    const a = join(tmp, 'a');
    await writeHeaders(a, APP, releaseUrl);
    const file = readFileSync(join(a, '_headers'), 'utf8');
    const csp = /Content-Security-Policy: (.*)/.exec(file)?.[1] as string;
    const files = await hashDir(a);
    const d = Object.fromEntries(csp.split('; ').map((x) => [x.split(' ')[0], x.split(' ').slice(1).join(' ')]));
    expect(d['default-src']).toBe("'none'");
    expect(d['script-src']).toBe(`'${cspHash(files[entry(files)] as string)}'`);
    expect(csp).not.toMatch(/unsafe-inline|unsafe-eval|strict-dynamic/);
    expect(d['require-trusted-types-for']).toBe("'script'");
    expect(d['trusted-types']).toBe("'none'");
    expect(d['base-uri']).toBe("'none'");
    expect(d['frame-ancestors']).toBe(APP);
    expect(d['connect-src']).toBe("'self' https://releases.example");
    expect(d['object-src']).toBe("'none'");
    expect(d['form-action']).toBe("'none'");
    expect(file).toMatch(/Cache-Control: no-store/);
    expect(file).toMatch(/X-Content-Type-Options: nosniff/);
    // the policy is a pure function of the manifest: the same inputs give the same header
    expect(
      vaultHostCsp({
        appOrigin: APP,
        releaseOrigin: 'https://releases.example',
        scriptHashes: [cspHash(files[entry(files)] as string)],
      }),
    ).toBe(csp);
  });
});

describe('P4.10-02 the published release', () => {
  it('release.json from the CLI names the hash of every built file and verifies with the published keys', async () => {
    const a = join(tmp, 'a');
    const out = execFileSync(
      'node',
      [cli, 'sign', '--dir', a, '--keys', keysDir, '--version', '1.0.0', '--app-origin', APP],
      { encoding: 'utf8' },
    ).trim();
    const release = JSON.parse(readFileSync(join(a, 'release.json'), 'utf8'));
    const body = verifyRelease(release, { ed25519: hexToBytes(keys.ed25519), mlDsa65: hexToBytes(keys.mlDsa65) });
    expect(body.files).toEqual(await hashDir(a));
    expect(body.manifestHash).toBe(out);
  });
});
