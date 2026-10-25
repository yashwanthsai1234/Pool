import { fc } from '@fast-check/vitest';
import type { MrzInput } from '../src/mrz.ts';

export const alnum = (min: number, max: number) =>
  fc.string({ unit: fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), minLength: min, maxLength: max });
const letters = (min: number, max: number) =>
  fc.string({ unit: fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'), minLength: min, maxLength: max });
const yymmdd = fc
  .record({
    y: fc.integer({ min: 0, max: 99 }),
    m: fc.integer({ min: 1, max: 12 }),
    d: fc.integer({ min: 1, max: 28 }),
  })
  .map(({ y, m, d }) => [y, m, d].map((n) => String(n).padStart(2, '0')).join(''));

export const arbMrzInput: fc.Arbitrary<MrzInput> = fc.record({
  documentNumber: alnum(1, 9),
  surname: letters(1, 12),
  givenNames: letters(1, 8),
  dateOfBirth: yymmdd,
  sex: fc.constantFrom('M', 'F', '<'),
  dateOfExpiry: yymmdd,
  personalNumber: alnum(0, 14),
});
