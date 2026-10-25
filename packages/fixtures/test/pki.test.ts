import { describe, expect, it } from 'vitest';
import { makeTestPki } from '../src/pki.ts';
import { certOf, keyUsageOf } from './helpers.ts';

describe.each(['ecdsa-p256', 'rsa-pss'] as const)('P1.8-01 makeTestPki (%s)', (alg) => {
  const pki = makeTestPki({ seed: 'pki-test', alg });

  it('makes a self-signed CSCA with keyCertSign and cRLSign, and a DS signed by it (checked by PKI.js)', async () => {
    const csca = certOf(pki.csca.cert);
    const ds = certOf(pki.ds.cert);
    expect(await csca.verify()).toBe(true);
    expect(await ds.verify(csca)).toBe(true);
    expect(keyUsageOf(pki.csca.cert)).toEqual(['keyCertSign', 'cRLSign']);
    expect(keyUsageOf(pki.ds.cert)).toEqual(['digitalSignature']);
    expect(ds.issuer.isEqual(csca.subject)).toBe(true);
  });

  it('follows the ICAO 9303 Part 12 profile (Table 5, Table 6)', () => {
    const csca = certOf(pki.csca.cert);
    const ds = certOf(pki.ds.cert);
    const ids = (c: typeof csca) => (c.extensions ?? []).map((e) => `${e.extnID}${e.critical ? '!' : ''}`).sort();
    // SKI, KU!, PKUP, SAN, IAN, BC!, CRLDP, AKI
    expect(ids(csca)).toEqual([
      '2.5.29.14',
      '2.5.29.15!',
      '2.5.29.16',
      '2.5.29.17',
      '2.5.29.18',
      '2.5.29.19!',
      '2.5.29.31',
      '2.5.29.35',
    ]);
    // plus the ICAO documentTypeList (2.23.136.1.1.6.2), no basicConstraints
    expect(ids(ds)).toEqual([
      '2.23.136.1.1.6.2',
      '2.5.29.14',
      '2.5.29.15!',
      '2.5.29.16',
      '2.5.29.17',
      '2.5.29.18',
      '2.5.29.31',
      '2.5.29.35',
    ]);
    expect(csca.version).toBe(2); // v3
    const serial = new Uint8Array(ds.serialNumber.valueBlock.valueHexView);
    expect(serial.length).toBeLessThanOrEqual(20);
    expect((serial[0] ?? 0) & 0x80).toBe(0);
    const country = csca.subject.typesAndValues.find((t) => t.type === '2.5.4.6');
    expect(country?.value.valueBlock.value).toBe('XX');
    expect(csca.subject.typesAndValues.map((t) => t.value.valueBlock.value).join(',')).toContain('DEMO / TEST ONLY');
  });

  it('is deterministic: the same seed gives the same bytes, another seed different bytes', () => {
    const again = makeTestPki({ seed: 'pki-test', alg });
    expect(again.csca.cert).toEqual(pki.csca.cert);
    expect(again.ds.cert).toEqual(pki.ds.cert);
    expect(makeTestPki({ seed: 'other', alg }).csca.cert).not.toEqual(pki.csca.cert);
  });

  it('has validity dates that cover today and nest (DS inside CSCA)', () => {
    const csca = certOf(pki.csca.cert);
    const ds = certOf(pki.ds.cert);
    const now = new Date('2026-10-24T00:00:00Z');
    expect(csca.notBefore.value <= now && now <= csca.notAfter.value).toBe(true);
    expect(ds.notBefore.value >= csca.notBefore.value && ds.notAfter.value <= csca.notAfter.value).toBe(true);
  });
});

it('defaults to ECDSA P-256', () => {
  expect(makeTestPki({ seed: 'x' }).alg).toBe('ecdsa-p256');
});
