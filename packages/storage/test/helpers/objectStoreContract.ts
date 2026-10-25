// The one ObjectStorePort contract suite (P3.6-03): every implementation runs it. Retention-dependent behaviour that
// needs a controllable clock is tested separately on the local store.

import { randomUUID } from 'node:crypto';
import type { ObjectStorePort } from '@legx/contracts/ports';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';

const bytes = (s: string) => new TextEncoder().encode(s);

export function objectStoreContract(name: string, make: () => ObjectStorePort | Promise<ObjectStorePort>): void {
  describe(`ObjectStorePort contract: ${name}`, () => {
    const key = (p = 'deal') => `${p}/${randomUUID()}.json`;

    it('creates, reads back and reports the SHA-256', async () => {
      const s = await make();
      const k = key();
      const r = await s.put(k, bytes('hello'), 30);
      expect(r).toEqual({ status: 'created', sha256: bytesToHex(sha256(bytes('hello'))) });
      expect(await s.get(k)).toEqual(bytes('hello'));
    });

    it('treats the same bytes again as a no-op and other bytes as a conflict that changes nothing', async () => {
      const s = await make();
      const k = key();
      await s.put(k, bytes('one'), 30);
      expect(await s.put(k, bytes('one'), 30)).toMatchObject({ status: 'exists' });
      expect(await s.put(k, bytes('two'), 30)).toEqual({ status: 'conflict' });
      expect(await s.get(k)).toEqual(bytes('one'));
    });

    it('returns undefined for a missing key', async () => {
      expect(await (await make()).get(key())).toBeUndefined();
    });

    it('refuses to delete before the retention date', async () => {
      const s = await make();
      const k = key();
      await s.put(k, bytes('kept'), 30);
      expect(await s.delete(k)).toEqual({ status: 'retained' });
      expect(await s.get(k)).toEqual(bytes('kept'));
    });

    it('stores empty and large objects intact', async () => {
      const s = await make();
      const big = Uint8Array.from({ length: 1_000_000 }, (_, i) => i % 251);
      const a = key();
      const b = key();
      await s.put(a, new Uint8Array(0), 30);
      await s.put(b, big, 30);
      expect(await s.get(a)).toEqual(new Uint8Array(0));
      expect(Buffer.from((await s.get(b)) ?? []).equals(Buffer.from(big))).toBe(true);
    });

    it('lets exactly one of many concurrent writers of different bytes create the key', async () => {
      const s = await make();
      const k = key();
      const results = await Promise.all(Array.from({ length: 12 }, (_, i) => s.put(k, bytes(`writer-${i}`), 30)));
      expect(results.filter((r) => r.status === 'created')).toHaveLength(1);
      expect(results.filter((r) => r.status === 'conflict')).toHaveLength(11);
    });

    it('gives concurrent writers of the same bytes one created and the rest exists', async () => {
      const s = await make();
      const k = key();
      const results = await Promise.all(Array.from({ length: 12 }, () => s.put(k, bytes('same'), 30)));
      expect(results.filter((r) => r.status === 'created')).toHaveLength(1);
      expect(results.filter((r) => r.status === 'exists')).toHaveLength(11);
    });

    it.each(['', '/abs', '../x', 'a/../b', 'a//b', 'a b', 'a\\b', 'a/./b', '.hidden', 'x'.repeat(513)])(
      'refuses the hostile key %j',
      async (k) => {
        const s = await make();
        await expect(s.put(k, bytes('x'), 1)).rejects.toThrow();
        await expect(s.get(k)).rejects.toThrow();
        await expect(s.delete(k)).rejects.toThrow();
      },
    );

    it('deleting a missing key is not an error', async () => {
      expect(await (await make()).delete(key())).toEqual({ status: 'deleted' });
    });
  });
}
