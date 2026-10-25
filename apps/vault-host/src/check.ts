// The vault frame's self-check (DESIGN 6.4 "Code integrity"): before any key call, fetch the signed release.json from
// its published place, verify both signatures with the release public keys baked into this bundle, then fetch every
// file of the release from this origin and compare its SHA-256. Any difference, a missing file, an unreadable file or
// a version below the signed `minVersion` ends in `CodeMismatch`.
//
// Honest limit: this check runs inside the code it checks. A party that controls THIS ORIGIN can replace the check
// too. What protects is the combination of a reproducible build (anyone can rebuild and compare with the published
// hash), a vault origin the coordinator cannot write to, and the first-use screen where the user compares the hash.
// Source: https://fetch.spec.whatwg.org/#concept-request-cache-mode (`no-store`: never answered from a cache)
import {
  compareVersions,
  type FileHashes,
  type ReleaseBody,
  ReleaseError,
  sha256Hex,
  verifyRelease,
} from '@legx/release-hash';
import { hexToBytes } from '@noble/hashes/utils.js';

export class CodeMismatch extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super('Code does not match the published release');
    this.name = 'CodeMismatch';
    this.reason = reason;
  }
}

export interface CheckDeps {
  releaseUrl: string;
  keys: { ed25519: string; mlDsa65: string };
  version: string;
  fetch?: typeof fetch;
  /** Base URL of the files of this bundle (default: the page). */
  base?: string;
}

const MAX_FILES = 64;

async function body(res: Response): Promise<Uint8Array> {
  if (!res.ok) throw new CodeMismatch(`HTTP ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

/** Resolves with the verified release body; rejects with `CodeMismatch`. */
export async function selfCheck(deps: CheckDeps): Promise<ReleaseBody> {
  const get = deps.fetch ?? fetch;
  const fresh = { cache: 'no-store', credentials: 'omit', redirect: 'error' } as const;
  try {
    const raw = await body(await get(deps.releaseUrl, fresh));
    const release = verifyRelease(JSON.parse(new TextDecoder().decode(raw)), {
      ed25519: hexToBytes(deps.keys.ed25519),
      mlDsa65: hexToBytes(deps.keys.mlDsa65),
    });
    if (compareVersions(deps.version, release.minVersion) < 0) throw new CodeMismatch('rollback');
    const files: FileHashes = release.files;
    const paths = Object.keys(files);
    if (paths.length === 0 || paths.length > MAX_FILES) throw new CodeMismatch('file list');
    const base = deps.base ?? location.href;
    await Promise.all(
      paths.map(async (path) => {
        const bytes = await body(await get(new URL(path, base), fresh));
        if (sha256Hex(bytes) !== files[path]) throw new CodeMismatch(`hash of ${path}`);
      }),
    );
    return release;
  } catch (err) {
    if (err instanceof CodeMismatch) throw err;
    throw new CodeMismatch(err instanceof ReleaseError ? err.code : 'unreadable');
  }
}
