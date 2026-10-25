import { fc, test as fcTest } from '@fast-check/vitest';
import { parse } from 'mrz';
import { describe, expect, it } from 'vitest';
import { checkDigit, type MrzInput, td3 } from '../src/mrz.ts';
import { alnum, arbMrzInput } from './arb.ts';

// ICAO 9303 Part 4 Appendix A specimen, with the country code changed from UTO to XXA (the mrz package rejects UTO).
const SPECIMEN: MrzInput = {
  documentNumber: 'L898902C3',
  surname: 'ERIKSSON',
  givenNames: 'ANNA MARIA',
  dateOfBirth: '740812',
  sex: 'F',
  dateOfExpiry: '120415',
  personalNumber: 'ZE184226B',
};

describe('P1.8-06 MRZ check digits', () => {
  it('matches the ICAO 9303 Part 3 worked examples', () => {
    expect(checkDigit('L898902C3')).toBe('6');
    expect(checkDigit('740812')).toBe('2');
    expect(checkDigit('120415')).toBe('9');
    expect(checkDigit('ZE184226B<<<<<')).toBe('1');
    expect(checkDigit('<<<<<<<<<')).toBe('0');
  });

  it('builds the specimen TD3 MRZ byte for byte', () => {
    expect(td3(SPECIMEN)).toBe(
      'P<XXAERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<' + 'L898902C36XXA7408122F1204159ZE184226B<<<<<10',
    );
  });

  it('is accepted by the independent mrz package', () => {
    const m = td3(SPECIMEN);
    const r = parse([m.slice(0, 44), m.slice(44)]);
    expect(r.valid).toBe(true);
    expect(r.format).toBe('TD3');
  });

  it('refuses input that does not fit or uses characters outside A-Z, 0-9 and space', () => {
    expect(() => td3({ ...SPECIMEN, documentNumber: 'L898902C30' })).toThrow(RangeError);
    expect(() => td3({ ...SPECIMEN, surname: 'ÉRIKSSON' })).toThrow(RangeError);
    expect(() => td3({ ...SPECIMEN, givenNames: 'A'.repeat(40) })).toThrow(RangeError);
    expect(() => td3({ ...SPECIMEN, dateOfBirth: '7408' })).toThrow(RangeError);
    expect(() => td3({ ...SPECIMEN, personalNumber: 'X'.repeat(15) })).toThrow(RangeError);
  });
});

describe('MRZ properties', () => {
  fcTest.prop([arbMrzInput])('every built MRZ is 88 characters and valid for the mrz package', (input) => {
    const m = td3(input);
    expect(m).toHaveLength(88);
    const r = parse([m.slice(0, 44), m.slice(44)]);
    expect(r.valid).toBe(true);
    expect(r.fields.documentNumber).toBe(input.documentNumber);
    expect(r.fields.birthDate).toBe(input.dateOfBirth);
    expect(r.fields.expirationDate).toBe(input.dateOfExpiry);
    expect(r.fields.lastName).toBe(input.surname);
  });

  fcTest.prop([alnum(1, 20), fc.nat(19), alnum(1, 1)])(
    'a check digit changes when any one character changes',
    (s, i, c) => {
      const at = i % s.length;
      fc.pre(s[at] !== c);
      // Weights 7,3,1 and values below 36 make single-character changes detectable unless the value delta is a multiple of 10.
      const before = checkDigit(s);
      const after = checkDigit(s.slice(0, at) + c + s.slice(at + 1));
      const v = (ch: string) => (ch <= '9' ? Number(ch) : ch.charCodeAt(0) - 55);
      const w = [7, 3, 1][at % 3] ?? 1;
      const changes = ((v(c) - v(s[at] ?? '0')) * w) % 10 !== 0;
      expect(before !== after).toBe(changes);
    },
  );
});
