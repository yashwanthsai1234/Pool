// The local-folder ObjectStorePort (demo profile): write-once and checked by hash. It is a stand-in for S3 Object Lock,
// not a lock: anyone with disk access can change files. What it does guarantee is that the code never overwrites, that
// every read is checked against the SHA-256 recorded at write time, and that delete respects the retention date.
// Layout: `<dir>/objects/<key>` (read-only 0444) and `<dir>/meta/<key>.json` (`{sha256, retainUntilMs}`).
// Source: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html (the behaviour being imitated)
// Source: https://man7.org/linux/man-pages/man2/link.2.html (link() fails with EEXIST: an atomic create-if-absent)

import { randomUUID } from 'node:crypto';
import { link, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { ObjectStorePort } from '@legx/contracts/ports';
import type { Hex32 } from '@legx/contracts/values';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { z } from 'zod';
import { assertKey } from './key.ts';

const DAY_MS = 86_400_000;
const Meta = z.object({ sha256: z.string().regex(/^[0-9a-f]{64}$/), retainUntilMs: z.number() }).strict();

export interface LocalObjectStoreOptions {
  readonly dir: string;
  /** Milliseconds since the epoch, for retention only. Default: the system clock. */
  readonly now?: () => number;
}

const isCode = (e: unknown, code: string) =>
  typeof e === 'object' && e !== null && (e as { code?: string }).code === code;

export function localObjectStore(options: LocalObjectStoreOptions): ObjectStorePort {
  const now = options.now ?? Date.now;
  const objectPath = (key: string) => join(options.dir, 'objects', key);
  const metaPath = (key: string) => join(options.dir, 'meta', `${key}.json`);

  async function readMeta(key: string) {
    try {
      return Meta.parse(JSON.parse(await readFile(metaPath(key), 'utf8')));
    } catch (e) {
      if (isCode(e, 'ENOENT')) return undefined;
      throw new Error(`object store metadata for ${key} is damaged`, { cause: e });
    }
  }

  /** Reads the object and checks it against the recorded hash; a mismatch means someone changed the file. */
  async function readChecked(key: string): Promise<{ bytes: Uint8Array; sha256: Hex32 } | undefined> {
    const meta = await readMeta(key);
    if (!meta) return undefined;
    const bytes = new Uint8Array(await readFile(objectPath(key)));
    if (bytesToHex(sha256(bytes)) !== meta.sha256) throw new Error(`object ${key} does not match its recorded SHA-256`);
    return { bytes, sha256: meta.sha256 as Hex32 };
  }

  /** Writes to a temporary file, then `link()`s it to the final name: it appears whole or not at all, never twice. */
  async function createOnce(path: string, bytes: Uint8Array): Promise<boolean> {
    await mkdir(dirname(path), { recursive: true });
    const tmp = join(options.dir, `.tmp-${randomUUID()}`);
    try {
      await writeFile(tmp, bytes, { mode: 0o444 });
      await link(tmp, path);
      return true;
    } catch (e) {
      if (isCode(e, 'EEXIST')) return false;
      throw e;
    } finally {
      await rm(tmp, { force: true });
    }
  }

  return {
    async put(key, bytes, retainDays) {
      assertKey(key);
      const digest = bytesToHex(sha256(bytes)) as Hex32;
      const meta = { sha256: digest, retainUntilMs: now() + retainDays * DAY_MS };
      await mkdir(options.dir, { recursive: true });
      // The metadata file is the commit point: whoever creates it owns the key. The bytes follow immediately.
      if (await createOnce(metaPath(key), new TextEncoder().encode(JSON.stringify(meta)))) {
        await createOnce(objectPath(key), bytes);
        return { status: 'created', sha256: digest };
      }
      const existing = await waitFor(() => readChecked(key));
      if (!existing) throw new Error(`object ${key} is incomplete (an earlier write was interrupted)`);
      return existing.sha256 === digest ? { status: 'exists', sha256: digest } : { status: 'conflict' };
    },

    async get(key) {
      assertKey(key);
      return (await readChecked(key))?.bytes;
    },

    async delete(key) {
      assertKey(key);
      const meta = await readMeta(key);
      if (!meta) return { status: 'deleted' };
      if (now() < meta.retainUntilMs) return { status: 'retained' };
      await rm(objectPath(key), { force: true });
      await rm(metaPath(key), { force: true });
      return { status: 'deleted' };
    },
  };
}

/** A concurrent writer has created the metadata but may not have linked the bytes yet: wait briefly for them. */
async function waitFor<T>(read: () => Promise<T | undefined>): Promise<T | undefined> {
  for (let i = 0; i < 100; i++) {
    try {
      const v = await read();
      if (v) return v;
    } catch (e) {
      if (!isCode(e, 'ENOENT')) throw e;
    }
    await new Promise((r) => setTimeout(r, 10));
  }
  return undefined;
}
