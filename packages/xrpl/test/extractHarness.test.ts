// I-2.5-a: the harness extractor writes only harness.ts; it must not bring back the removed happy.int.test.ts.
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const root = new URL('../', import.meta.url);

describe('I-2.5-a extract-harness', () => {
  it('writes harness.ts and no happy test', () => {
    const harness = new URL('test-int/harness.ts', root);
    const before = readFileSync(harness, 'utf8'); // the committed copy is formatted by biome; put it back after the run
    try {
      execFileSync(process.execPath, ['scripts/extract-harness.ts'], { cwd: root });
      expect(readFileSync(harness, 'utf8')).toContain('export');
    } finally {
      writeFileSync(harness, before);
    }
    expect(existsSync(new URL('test-int/happy.int.test.ts', root))).toBe(false);
  });
});
