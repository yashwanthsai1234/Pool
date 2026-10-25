// "A lint rule bans the string" (IMPLEMENTATION 2.7): the proposed-transactions stream must never appear in source.
// Biome has no text rule and biome.json is shared, so the ban is this test, which scans every non-test source tree.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = resolve(import.meta.dirname, '../../../..');
const BANNED = ['accounts', 'proposed'].join('_');

function* sources(dir: string): Generator<string> {
  for (const name of readdirSync(dir)) {
    if (['node_modules', 'dist', '.tools', 'build', 'test', 'test-int', '.git'].includes(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* sources(p);
    else if (/\.(ts|tsx|js|mjs)$/.test(name)) yield p;
  }
}

describe('accounts_proposed ban', () => {
  it('no source file under packages, services, apps or tools mentions it', () => {
    const hits: string[] = [];
    let scanned = 0;
    for (const top of ['packages', 'services', 'apps', 'tools']) {
      for (const f of sources(join(root, top))) {
        scanned++;
        if (readFileSync(f, 'utf8').includes(BANNED)) hits.push(f);
      }
    }
    expect(scanned).toBeGreaterThan(20);
    expect(hits).toEqual([]);
  });
});
