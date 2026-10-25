import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';

/** A fixture seed. Strings are UTF-8 encoded. The same seed always gives the same fixtures. */
export type Seed = string | Uint8Array;

const SALT = utf8ToBytes('legx/fixtures/v1');

/**
 * Deterministic bytes for one purpose (`label`) from the seed: HKDF-SHA256 with a fixed salt, the label as info.
 * Source: https://www.rfc-editor.org/rfc/rfc5869
 */
export function deriveBytes(seed: Seed, label: string, length: number): Uint8Array {
  const ikm = typeof seed === 'string' ? utf8ToBytes(seed) : seed;
  return hkdf(sha256, ikm, SALT, utf8ToBytes(label), length);
}

/** A deterministic integer in [min, max). 64 random bits keep the modulo bias far below anything a test can see. */
export function deriveInt(seed: Seed, label: string, min: number, max: number): number {
  if (!(max > min)) throw new RangeError(`empty range [${min}, ${max})`);
  const v = new DataView(deriveBytes(seed, label, 8).buffer).getBigUint64(0);
  return min + Number(v % BigInt(max - min));
}
