import type { MrzInput } from './mrz.ts';
import { makePassport, type Passport } from './passport.ts';
import { DEMO_MARKER, makeTestPki } from './pki.ts';
import { makeBadVariants } from './variants.ts';

/** The demo trust anchor's seed. The demo server trusts only the CSCA this seed makes. */
export const DEMO_PKI_SEED = 'legx/demo/pki/v1';

const person = (givenNames: string, documentNumber: string, dateOfBirth: string, sex: 'M' | 'F'): MrzInput => ({
  documentNumber,
  surname: 'EXAMPLE',
  givenNames,
  dateOfBirth,
  sex,
  dateOfExpiry: '340630',
});

const DEMOS = {
  alice: { mrz: person('ALICE', 'XD0000001', '900101', 'F'), variant: undefined },
  bob: { mrz: person('BOB', 'XD0000002', '880515', 'M'), variant: undefined },
  'mallory-fake-csca': { mrz: person('MALLORY', 'XD0000003', '870707', 'M'), variant: 'wrongCsca' },
  'alice-tampered-dg1': { mrz: person('ALICE', 'XD0000001', '900101', 'F'), variant: 'changedDg1' },
} as const;

export type DemoName = keyof typeof DEMOS;
export const DEMO_NAMES = Object.keys(DEMOS) as DemoName[];

export interface DemoPassport {
  name: DemoName;
  label: typeof DEMO_MARKER;
  expect: 'accept' | 'reject';
  reason: string;
  passport: Passport;
  /** The demo CSCA (DER), the only trust anchor the demo profile uses. */
  csca: Uint8Array;
}

/** A named demo passport, rebuilt from fixed seeds (so the Active Authentication key is available too). */
export function demoPassport(name: DemoName): DemoPassport {
  const pki = makeTestPki({ seed: DEMO_PKI_SEED });
  const { mrz, variant } = DEMOS[name];
  const seed = `legx/demo/passport/${name}/v1`;
  const base = { name, label: DEMO_MARKER, csca: pki.csca.cert } as const;
  if (!variant) return { ...base, expect: 'accept', reason: 'PASS', passport: makePassport({ pki, mrz, seed }) };
  const v = makeBadVariants({ pki, mrz, seed })[variant];
  return { ...base, expect: v.expect, reason: v.reason, passport: v.passport };
}

const hex = (b?: Uint8Array) => (b ? Buffer.from(b).toString('hex') : undefined);

/** The public part of a demo passport as written to `demo/<name>.json`; no private keys. */
export function demoFile(name: DemoName) {
  const d = demoPassport(name);
  return {
    label: d.label,
    name: d.name,
    expect: d.expect,
    reason: d.reason,
    mrz: d.passport.mrz,
    dg1: hex(d.passport.dg1),
    dg14: hex(d.passport.dg14),
    dg15: hex(d.passport.dg15),
    sod: hex(d.passport.sod),
    csca: hex(d.csca),
  };
}
