// The regression catalogue is complete and current (IMPLEMENTATION 6.5, item 1): no issue without a row, no test naming an
// issue that does not exist. Needs no containers.
import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { issueRows, render } from '../support/regression.ts';

const ROOT = join(import.meta.dirname, '../../..');

describe('REGRESSION.md', () => {
  it('has a row for every issue of build/ISSUES.md', () => {
    const doc = readFileSync(join(ROOT, 'tests/system/REGRESSION.md'), 'utf8');
    const missing = issueRows()
      .filter((r) => !doc.includes(`| ${r.id} |`))
      .map((r) => r.id);
    expect(missing, 'run: node tests/system/support/regression.ts').toEqual([]);
  });
  it('is current: regenerating it changes nothing', () => {
    expect(readFileSync(join(ROOT, 'tests/system/REGRESSION.md'), 'utf8')).toBe(render());
  });
  it('every I-W-* a system test names exists in the issue log', () => {
    const named = execSync('grep -rohE "I-W-[0-9]+" tests/system/test tests/system/support || true', {
      cwd: ROOT,
      encoding: 'utf8',
    })
      .split('\n')
      .filter(Boolean);
    const known = new Set(issueRows().map((r) => r.id));
    expect([...new Set(named)].filter((id) => !known.has(id))).toEqual([]);
  });
});
