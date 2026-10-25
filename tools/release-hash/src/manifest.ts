// The manifest of a built bundle: the SHA-256 of every file, and one hash over the sorted list (DESIGN 6.4 "Code
// integrity"). Browser-safe: the vault frame runs the same functions to check what it was served.
// Source: https://www.w3.org/TR/SRI/#the-integrity-attribute (sha256-<base64> metadata)
// Source: https://www.w3.org/TR/CSP3/#grammardef-hash-source (the CSP hash uses the same encoding)
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';

/** Path (relative, `/` separated) to lower-case hex SHA-256. */
export type FileHashes = Readonly<Record<string, string>>;

export const sha256Hex = (bytes: Uint8Array): string => bytesToHex(sha256(bytes));

/** Files that describe a release rather than belong to it: they are not part of the manifest. */
export const RELEASE_FILES: readonly string[] = ['release.json', '_headers'];

/** SHA-256 over the sorted `path NUL hash LF` lines: the same set of files gives the same hash in any order. */
export function manifestHash(files: FileHashes): string {
  const lines = Object.keys(files)
    .sort()
    .map((p) => `${p}\0${files[p]}\n`);
  return sha256Hex(utf8ToBytes(lines.join('')));
}

const b64 = (b: Uint8Array): string => {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
};

/** `sha256-<base64>` for a file's hex hash: the value of an `integrity` attribute and of a CSP hash source. */
export const cspHash = (hex: string): string => `sha256-${b64(hexToBytes(hex))}`;

// The only shapes the build emits. Anything else in the page (inline script, foreign URL) is refused, not skipped.
const SCRIPT = /<script\b([^>]*)>\s*<\/script>/g;
const LINK = /<link\b([^>]*)>/g;
const attr = (attrs: string, name: string): string | undefined => new RegExp(`\\s${name}="([^"]*)"`).exec(attrs)?.[1];

/**
 * Adds `integrity="sha256-..."` to every `<script src>` and `<link rel=stylesheet href>` of `html`.
 * `bytesOf(path)` returns a file of the build by its path relative to the page. Throws on an inline script or a
 * reference that is not a local file (P4.10-08).
 */
export function injectSri(html: string, bytesOf: (path: string) => Uint8Array | undefined): string {
  const local = (url: string | undefined): Uint8Array => {
    const path = url?.replace(/^\.?\//, '');
    const bytes = path && !/^[a-z][a-z0-9+.-]*:|^\/\//i.test(url ?? '') ? bytesOf(path) : undefined;
    if (!bytes) throw new Error(`release-hash: not a local file of the build: ${url}`);
    return bytes;
  };
  if (/<script\b(?![^>]*\ssrc=)/i.test(html)) throw new Error('release-hash: inline script in the page');
  const withHash = (tag: string, attrs: string, url: string | undefined) =>
    tag.replace(attrs, `${attrs} integrity="${cspHash(sha256Hex(local(url)))}"`);
  return html
    .replace(SCRIPT, (tag, attrs: string) => withHash(tag, attrs, attr(attrs, 'src')))
    .replace(LINK, (tag, attrs: string) =>
      /rel="stylesheet"/.test(attrs) ? withHash(tag, attrs, attr(attrs, 'href')) : tag,
    );
}
