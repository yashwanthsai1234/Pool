// A reference sender in TypeScript: plays the Android helper against fixture passports, so the console side is
// testable end to end. The Kotlin app in apps/chip-reader-android must produce the same bytes.
// Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p11_cons_en.pdf (6.1.2)
import { type AaKey, chipAnswerAA, type Passport } from '@legx/fixtures';
import { parseQr, type Sealed, sealToQr } from './channel.ts';
import { encodeChipData } from './wire.ts';

export interface SimChip {
  readonly passport: Passport;
  /** The key that answers INTERNAL AUTHENTICATE. A clone has the passport's files but not the real key. */
  readonly aaKey?: AaKey | undefined;
}

/** Reads the chip, answers the QR's challenge, and seals the result to the QR's key. */
export async function simSend(qr: string, chip: SimChip): Promise<Sealed> {
  const q = parseQr(qr);
  if (!q) throw new Error('QR_INVALID');
  const { passport, aaKey } = chip;
  const aaSignature = aaKey ? chipAnswerAA(aaKey, q.challenge) : undefined;
  return sealToQr(
    q,
    encodeChipData({ dg1: passport.dg1, sod: passport.sod, dg14: passport.dg14, dg15: passport.dg15, aaSignature }),
  );
}
