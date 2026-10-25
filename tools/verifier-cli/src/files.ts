// The bundle as a map of path to bytes, read from a ZIP file or from an unzipped folder, plus small typed readers.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fromBase64Strict } from '@legx/core/pq';
import { readZip, safePath } from './zip.ts';

export type Json = Record<string, unknown>;
export const isObj = (x: unknown): x is Json => typeof x === 'object' && x !== null && !Array.isArray(x);

const strict = new TextDecoder('utf-8', { fatal: true });

export class BundleFiles {
  readonly #files: ReadonlyMap<string, Uint8Array>;
  constructor(files: ReadonlyMap<string, Uint8Array>) {
    this.#files = files;
  }
  get paths(): string[] {
    return [...this.#files.keys()].sort();
  }
  has(path: string): boolean {
    return this.#files.has(path);
  }
  bytes(path: string): Uint8Array | undefined {
    return this.#files.get(path);
  }
  text(path: string): string | undefined {
    const b = this.#files.get(path);
    if (!b) return undefined;
    try {
      return strict.decode(b);
    } catch {
      return undefined;
    }
  }
  /** Parsed JSON, or undefined when the file is absent or is not JSON. */
  json(path: string): unknown {
    const t = this.text(path);
    if (t === undefined) return undefined;
    try {
      return JSON.parse(t);
    } catch {
      return undefined;
    }
  }
  /** Paths under a folder prefix (`events/`), sorted. */
  under(prefix: string, suffix = ''): string[] {
    return this.paths.filter((p) => p.startsWith(prefix) && p.endsWith(suffix));
  }
}

function readFolder(root: string, dir = ''): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  for (const name of readdirSync(join(root, dir))) {
    const rel = dir === '' ? name : `${dir}/${name}`;
    if (statSync(join(root, rel)).isDirectory()) {
      for (const [p, b] of readFolder(root, rel)) out.set(p, b);
    } else if (safePath(rel)) out.set(rel, new Uint8Array(readFileSync(join(root, rel))));
  }
  return out;
}

/** The bundle's bytes (ZIP) and its files; a folder has no archive bytes, so `archive` is undefined. */
export function loadBundle(path: string): { files: BundleFiles; archive: Uint8Array | undefined } {
  if (statSync(path).isDirectory()) return { files: new BundleFiles(readFolder(path)), archive: undefined };
  const archive = new Uint8Array(readFileSync(path));
  return { files: new BundleFiles(readZip(archive)), archive };
}

export const b64 = (s: unknown): Uint8Array | undefined => (typeof s === 'string' ? fromBase64Strict(s) : undefined);
