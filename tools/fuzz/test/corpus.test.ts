// P5.2-01: every crash input found is saved to corpus/<target>/ and replayed here as a unit test.
// An input listed in corpus/known.json shows a crash that build/ISSUES.md reports and another task must fix: the test
// expects it to still crash, and fails with "fixed" once it does not, so the entry gets removed.
import { describe, expect, it } from 'vitest';
import { corpusFiles, knownCorpus, runOnce } from '../src/harness.ts';
import { targets } from '../src/index.ts';

const known = knownCorpus();

describe('P5.2-01 crash corpus', () => {
  for (const t of targets) {
    for (const f of corpusFiles(t.name)) {
      const id = known[`${t.name}/${f.name}`];
      it(`${t.name}/${f.name}${id ? ` (open: ${id})` : ''}`, async () => {
        const result = await runOnce(t, f.bytes).then(
          () => 'passes' as const,
          () => 'crashes' as const,
        );
        if (id) expect(result, `${id} looks fixed: remove it from corpus/known.json`).toBe('crashes');
        else expect(result).toBe('passes');
      });
    }
  }
});
