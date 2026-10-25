// @legx/fixtures: test PKI and fixture passports. DEMO / TEST ONLY: never trust these keys outside tests and the demo.
export { DEMO_NAMES, type DemoName, type DemoPassport, demoPassport } from './demo.ts';
export { checkDigit, type MrzInput, td3 } from './mrz.ts';
export { type Parsed, type ParsedSod, parseDg1, parseSod } from './parse.ts';
export {
  type AaKey,
  type AaKind,
  chipAnswerAA,
  makePassport,
  type Passport,
  type PassportOptions,
  type PassportWithAa,
} from './passport.ts';
export { DEMO_MARKER, type Issued, makeTestPki, type PkiAlg, type TestPki } from './pki.ts';
export type { Seed } from './seed.ts';
export { makeBadVariants, type Variant, type VariantName, type Variants } from './variants.ts';
