// Node side of the release step: hash a build directory, write `release.json` and `_headers` next to it.
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import type { SignerPort } from '@legx/contracts/ports';
import { type FileHashes, manifestHash, RELEASE_FILES, sha256Hex } from './manifest.ts';
import { RELEASE_CONTEXT, type Release, signRelease } from './release.ts';

/** Hashes every file under `dir` (sorted, `/` separated). `release.json` and `_headers` are not part of a release. */
export async function hashDir(dir: string): Promise<FileHashes> {
  const out: Record<string, string> = {};
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const full = join(d, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile()) {
        const path = relative(dir, full).split(sep).join('/');
        if (!RELEASE_FILES.includes(path)) out[path] = sha256Hex(new Uint8Array(readFileSync(full)));
      } else throw new Error(`release-hash: ${full} is not a regular file`);
    }
  };
  walk(dir);
  return out;
}

export interface ReleaseInput {
  dir: string;
  version: string;
  minVersion: string;
  appOrigin: string;
  signer: SignerPort;
}

/** Hashes `dir`, signs the result and writes `release.json` into it. Returns the release. */
export async function writeRelease(i: ReleaseInput): Promise<Release> {
  const files = await hashDir(i.dir);
  const release = await signRelease(i.signer, {
    schema: RELEASE_CONTEXT,
    version: i.version,
    minVersion: i.minVersion,
    appOrigin: i.appOrigin,
    files,
    manifestHash: manifestHash(files),
  });
  writeFileSync(join(i.dir, 'release.json'), `${JSON.stringify(release)}\n`);
  return release;
}
