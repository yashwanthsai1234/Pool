import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fc } from '@fast-check/vitest';
import { describe, expect, it } from 'vitest';
import { assertZipPath, unzip, zip } from '../src/zip.ts';

const enc = (s: string) => new TextEncoder().encode(s);

describe('deterministic ZIP', () => {
  it('the same files in any order give the same bytes', () => {
    const files = [
      { path: 'b/two.json', bytes: enc('two') },
      { path: 'a.txt', bytes: enc('one') },
      { path: 'b/one.json', bytes: new Uint8Array([0, 1, 2, 255]) },
    ];
    expect(zip(files)).toEqual(zip([...files].reverse()));
    expect(unzip(zip(files)).map((f) => f.path)).toEqual(['a.txt', 'b/one.json', 'b/two.json']);
  });

  it('round-trips arbitrary content and paths (property)', () => {
    fc.assert(
      fc.property(
        fc.uniqueArray(
          fc.tuple(
            fc.stringMatching(/^[a-zA-Z0-9_-]{1,8}(\/[a-zA-Z0-9_.-]{1,8}){0,2}$/),
            fc.uint8Array({ maxLength: 300 }),
          ),
          { selector: ([p]) => p, maxLength: 12 },
        ),
        (pairs) => {
          const files = pairs
            .filter(([p]) => !p.split('/').some((s) => s === '.' || s === '..'))
            .map(([path, bytes]) => ({ path, bytes }));
          const back = unzip(zip(files));
          expect(back.length).toBe(files.length);
          for (const f of files) expect(back.find((b) => b.path === f.path)?.bytes).toEqual(f.bytes);
        },
      ),
    );
  });

  it('a standard unzip tool reads it, and `unzip -t` finds no error', () => {
    const dir = mkdtempSync(join(tmpdir(), 'legx-zip-'));
    const file = join(dir, 'x.zip');
    writeFileSync(
      file,
      zip([
        { path: 'dir/hello.txt', bytes: enc('héllo') },
        { path: 'empty', bytes: new Uint8Array() },
      ]),
    );
    expect(execFileSync('unzip', ['-t', file]).toString()).toContain('No errors detected');
    expect(execFileSync('unzip', ['-p', file, 'dir/hello.txt']).toString('utf8')).toBe('héllo');
    expect(readFileSync(file).length).toBeGreaterThan(0);
  });

  it('refuses unsafe or duplicate paths', () => {
    for (const p of ['', '/abs', '../x', 'a/../b', 'a//b', 'a\\b', './a', 'a\u0000b', 'a/'])
      expect(() => assertZipPath(p), p).toThrow();
    expect(() =>
      zip([
        { path: 'a', bytes: enc('1') },
        { path: 'a', bytes: enc('2') },
      ]),
    ).toThrow('duplicate');
  });

  it('the reader refuses a damaged entry (CRC-32) and a file that is not a ZIP', () => {
    const z = zip([{ path: 'a', bytes: enc('payload') }]);
    const bad = z.slice();
    bad[30 + 1] = (bad[30 + 1] as number) ^ 1; // a byte of the content
    expect(() => unzip(bad)).toThrow('CRC-32');
    expect(() => unzip(enc('nope'))).toThrow();
  });
});
