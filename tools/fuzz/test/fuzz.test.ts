// T-Z-01: every target runs LEGX_FUZZ_SECONDS (30 on pull requests, 600 nightly; 2 by default for a local run).
// LEGX_FUZZ_PKG=core|contracts|zk and LEGX_FUZZ_ONLY=<target> select a subset (CI shards by package).
import { describe, expect, it } from 'vitest';
import { fuzz, fuzzSeconds, saveCrash } from '../src/harness.ts';
import { targets } from '../src/index.ts';

const only = process.env.LEGX_FUZZ_ONLY;
const pkg = process.env.LEGX_FUZZ_PKG;

describe('T-Z-01 fuzz targets', () => {
  for (const t of targets.filter((x) => (!only || x.name === only) && (!pkg || x.pkg === pkg))) {
    it(
      `${t.name}: no crash, no hang over 1 s, accepted input round-trips`,
      async () => {
        const report = await fuzz(t);
        expect(report.runs).toBeGreaterThan(0);
        if (report.failures.length > 0) {
          const files = report.failures.map((f) => `${f.key} -> ${saveCrash(t.name, f.input)}`);
          expect.fail(`new crash(es), saved to the corpus:\n${files.join('\n')}`);
        }
      },
      (fuzzSeconds() + 60) * 1000,
    );
  }
});
