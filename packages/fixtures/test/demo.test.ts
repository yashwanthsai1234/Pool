import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { DEMO_NAMES, demoFile, demoPassport } from '../src/demo.ts';
import { chipAnswerAA } from '../src/passport.ts';

describe('demo passports in packages/fixtures/demo/', () => {
  it('are the 4 named passports: Alice, Bob and 2 bad ones', () => {
    expect(DEMO_NAMES).toEqual(['alice', 'bob', 'mallory-fake-csca', 'alice-tampered-dg1']);
    expect(DEMO_NAMES.map((n) => demoPassport(n).expect)).toEqual(['accept', 'accept', 'reject', 'reject']);
  });

  it.each(DEMO_NAMES)('%s.json matches the generator byte for byte and says DEMO / TEST ONLY (P1.8-08)', (name) => {
    const onDisk = JSON.parse(readFileSync(new URL(`../demo/${name}.json`, import.meta.url), 'utf8'));
    expect(onDisk).toEqual(JSON.parse(JSON.stringify(demoFile(name))));
    expect(onDisk.label).toBe('DEMO / TEST ONLY');
    expect(onDisk.mrz.slice(5, 44)).toContain('DEMO<TEST<ONLY');
  });

  it('all share one demo CSCA, and the good ones can answer Active Authentication', () => {
    const cscas = new Set(DEMO_NAMES.map((n) => Buffer.from(demoPassport(n).csca).toString('hex')));
    expect(cscas.size).toBe(1);
    const alice = demoPassport('alice').passport;
    if (!alice.aaKey) throw new Error('no AA key');
    expect(chipAnswerAA(alice.aaKey, new Uint8Array(8))).toHaveLength(64);
  });
});
