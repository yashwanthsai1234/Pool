// P1.3-01: the extraction script writes DESIGN Appendix A byte for byte.
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { extractAppendixA, writeBlocks } from '../scripts/extract-appendix.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const design = readFileSync(join(root, 'DESIGN.md'), 'utf8');
const sha = (s: string | Buffer) => createHash('sha256').update(s).digest('hex');

// An independent reading of Appendix A with a regular expression, so the test does not rely on the script's own parser.
function independentBlocks(): Map<string, string> {
  const section = design.slice(design.indexOf('## Appendix A'), design.indexOf('## Appendix B'));
  const out = new Map<string, string>();
  for (const m of section.matchAll(/^### (\S+)[^\n]*\n```[a-z]*\n([\s\S]*?)\n```$/gm))
    out.set(m[1] as string, `${m[2]}\n`);
  return out;
}

describe('P1.3-01 extract-appendix', () => {
  const out = mkdtempSync(join(tmpdir(), 'legx-appendix-'));
  afterAll(() => rmSync(out, { recursive: true, force: true }));

  it('finds the 14 files of Appendix A', () => {
    expect(extractAppendixA(design).map((b) => b.path)).toEqual([
      'package.json',
      'tsconfig.json',
      'vitest.config.ts',
      'src/dealcore.ts',
      'src/contract.ts',
      'src/evidence.ts',
      'src/fees.ts',
      'src/verify.ts',
      'src/lockcheck.ts',
      'src/machine.ts',
      'test/dealcore.test.ts',
      'test/more.test.ts',
      'test/machine.test.ts',
      'test/lockcheck.test.ts',
    ]);
  });

  it('writes each block so that its SHA-256 matches the independent reading, byte for byte', () => {
    const blocks = extractAppendixA(design);
    writeBlocks(blocks, out, false);
    const expected = independentBlocks();
    expect(expected.size).toBe(blocks.length);
    for (const b of blocks) {
      expect(sha(readFileSync(join(out, b.path))), b.path).toBe(sha(expected.get(b.path) as string));
      expect(b.sha256, b.path).toBe(sha(expected.get(b.path) as string));
    }
  });

  it('refuses to overwrite an existing file unless forced', () => {
    const blocks = extractAppendixA(design);
    expect(() => writeBlocks(blocks, out, false)).toThrow(/exists/);
    expect(() => writeBlocks(blocks, out, true)).not.toThrow();
  });

  it('the adapted files differ from Appendix A only by the repo conventions', () => {
    // Imports end in .ts, type-only imports, non-null assertions for noUncheckedIndexedAccess. No logic changes:
    // stripping those edits from the package file gives the Appendix text back.
    const strip = (s: string) =>
      s
        .replace(/\.ts'/g, "'")
        .replace(/\btype (\w+)/g, '$1')
        .replace(/(\w|\])!/g, '$1')
        .replace(/!\./g, '.');
    // Files a later task changed on purpose, with that task (IMPLEMENTATION 1.4 to 1.7). They are no longer the Appendix.
    const changedByLaterTask: Record<string, string> = {
      'src/verify.ts': '1.4 strict verifyXrplKeySig',
      'src/dealcore.ts': '1.6 29-field deal seal and Domain',
      'test/dealcore.test.ts': '1.6 T-U-06 moved to dealseal.test.ts',
      'src/evidence.ts': '1.13 attest payload type, typed chain',
      'src/machine.ts': '1.14 gatePassed guard (I8), total transition',
      'test/machine.test.ts': '1.14 I8 property, exhaustive table',
      'src/lockcheck.ts': '1.11 DOMAIN_IS_SEAL recomputed, RELEASER_IS_OPS_B, DQ-11 Oracle owner',
      'test/lockcheck.test.ts': '1.11 seal rules, every ledger entry type, properties',
      'src/contract.ts': 'fix fleet F2 (I-E1): clauseBytes, the clause normalizer of DESIGN 6.1',
    };
    const unchanged = (p: string) => /^(src|test)\//.test(p) && !(p in changedByLaterTask);
    for (const b of extractAppendixA(design).filter((x) => unchanged(x.path))) {
      const current = readFileSync(join(root, 'packages/core', b.path), 'utf8');
      expect(strip(current), b.path).toBe(strip(b.content));
    }
  });
});
