import { mkdtempSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { localObjectStore } from '../src/localStore.ts';
import { objectStoreContract } from './helpers/objectStoreContract.ts';

const dir = () => mkdtempSync(join(tmpdir(), 'legx-store-'));
const bytes = (s: string) => new TextEncoder().encode(s);

objectStoreContract('local folder', () => localObjectStore({ dir: dir() }));

describe('local folder specifics', () => {
  it('deletes after the retention date and not a moment before', async () => {
    let t = 1_000_000;
    const s = localObjectStore({ dir: dir(), now: () => t });
    await s.put('a/k', bytes('v'), 2);
    t += 2 * 86_400_000 - 1;
    expect(await s.delete('a/k')).toEqual({ status: 'retained' });
    t += 1;
    expect(await s.delete('a/k')).toEqual({ status: 'deleted' });
    expect(await s.get('a/k')).toBeUndefined();
  });

  it('detects tampering: a changed file fails the hash check on read', async () => {
    const d = dir();
    const s = localObjectStore({ dir: d });
    await s.put('k', bytes('original'), 30);
    const { chmodSync } = await import('node:fs');
    chmodSync(join(d, 'objects', 'k'), 0o644);
    writeFileSync(join(d, 'objects', 'k'), 'tampered');
    await expect(s.get('k')).rejects.toThrow(/does not match/);
    await expect(s.put('k', bytes('tampered'), 30)).rejects.toThrow(/does not match/);
  });

  it('writes objects read-only and leaves no temporary files behind', async () => {
    const d = dir();
    const s = localObjectStore({ dir: d });
    await Promise.all([s.put('k', bytes('x'), 1), s.put('k', bytes('y'), 1)]);
    const { statSync } = await import('node:fs');
    expect(statSync(join(d, 'objects', 'k')).mode & 0o222).toBe(0);
    expect(readdirSync(d).sort()).toEqual(['meta', 'objects']);
  });

  it('rejects damaged metadata instead of guessing', async () => {
    const d = dir();
    const s = localObjectStore({ dir: d });
    await s.put('k', bytes('x'), 1);
    const { chmodSync } = await import('node:fs');
    chmodSync(join(d, 'meta', 'k.json'), 0o644);
    writeFileSync(join(d, 'meta', 'k.json'), '{"sha256":"zz"}');
    await expect(s.get('k')).rejects.toThrow(/damaged/);
  });

  it('reports an interrupted write (metadata without bytes) instead of claiming a conflict', async () => {
    const d = dir();
    const s = localObjectStore({ dir: d });
    await s.put('k', bytes('x'), 1);
    const { rmSync } = await import('node:fs');
    rmSync(join(d, 'objects', 'k'));
    await expect(s.put('k', bytes('x'), 1)).rejects.toThrow(/incomplete/);
  }, 10_000);
});
