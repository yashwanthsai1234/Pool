// Builds the vault-host bundle and finishes the release: SRI on the page, then `release.json` (signed) and `_headers`.
//   node scripts/build.ts --out dist --release-url https://releases.example/vault/release.json \
//     --app-origin https://app.example --keys <dir with release keys> [--version x.y.z] [--min-version x.y.z]
// `buildBundle` is the reproducible half (no keys, no signing); tests call it twice and compare the bytes.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cspHash, injectSri, manifestHash } from '@legx/release-hash';
import { hashDir } from '@legx/release-hash/build';
import { build } from 'vite';
import { headersFile } from '../src/headers.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

export interface BundleOptions {
  outDir: string;
  releaseUrl: string;
  /** Release public keys, hex. */
  keys: { ed25519: string; mlDsa65: string };
  version?: string;
}

/** Vite build, then `integrity` on every script and stylesheet of the page. Same inputs give the same bytes. */
export async function buildBundle(o: BundleOptions): Promise<void> {
  process.env.LEGX_RELEASE_URL = o.releaseUrl;
  process.env.LEGX_RELEASE_KEYS = JSON.stringify(o.keys);
  if (o.version) process.env.LEGX_VAULT_VERSION = o.version;
  await build({ root, configFile: join(root, 'vite.config.ts'), logLevel: 'silent', build: { outDir: o.outDir } });
  const page = join(o.outDir, 'index.html');
  const html = injectSri(readFileSync(page, 'utf8'), (p) => {
    try {
      return new Uint8Array(readFileSync(join(o.outDir, p)));
    } catch {
      return undefined;
    }
  });
  writeFileSync(page, html);
}

/** The `_headers` file for a built directory, with the script hash taken from the page's own script tag. */
export async function writeHeaders(dir: string, appOrigin: string, releaseUrl: string): Promise<void> {
  const files = await hashDir(dir);
  const entry = Object.keys(files).filter((p) => /^assets\/.*\.js$/.test(p));
  if (entry.length !== 1) throw new Error(`expected one script, found ${entry.length}`);
  writeFileSync(
    join(dir, '_headers'),
    headersFile({
      appOrigin,
      releaseOrigin: new URL(releaseUrl).origin,
      scriptHashes: [cspHash(files[entry[0] as string] as string)],
    }),
  );
}

export { manifestHash };
