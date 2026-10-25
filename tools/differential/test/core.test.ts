// P5.3-02: @legx/core and the Python reference give the same bytes for random inputs, for every recipe of DESIGN 6.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CASES, FNS, Prng, PyRef, randomCase, seedsToRun, tsRef } from '../src/index.ts';

let py: PyRef;
beforeAll(() => {
  py = new PyRef();
});
afterAll(() => py.close());

describe('P5.3-02 core against the Python reference', () => {
  for (const seed of seedsToRun()) {
    for (const fn of FNS) {
      it(`seed ${seed}: ${fn} x ${CASES}`, async () => {
        const r = new Prng(seed ^ (FNS.indexOf(fn) * 0x9e3779b1));
        const cases = Array.from({ length: CASES }, () => randomCase(r, fn));
        const got = await py.call<string>('ref', cases, fn === 'pqKeyHash' || fn === 'mu' ? 100 : 500);
        const bad = cases.flatMap((c, i) =>
          tsRef(c) === got[i] ? [] : [`${JSON.stringify(c).slice(0, 400)}\n ts=${tsRef(c)}\n py=${got[i]}`],
        );
        expect(bad.slice(0, 2), `seed ${seed} ${fn}: ${bad.length} of ${CASES} differ`).toEqual([]);
        if (fn === 'dealSeal' || fn === 'condition') expect(got.some((g) => g === 'ERR')).toBe(true); // refusals compared too
      }, 600_000);
    }
  }
});
