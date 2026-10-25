// Recovery codes for the recovery file (the fallback when an authenticator has no PRF, IMPLEMENTATION 4.2).
// 128 random bits in RFC 4648 base32 (26 characters), shown in groups of four. The vault makes the code, so
// nobody chooses a weak one. JavaScript strings cannot be zeroed; the code string lives only in the UI callback.
// Source: https://www.rfc-editor.org/rfc/rfc4648#section-6
import { VaultError } from './errors.ts';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const LENGTH = 26; // ceil(128 / 5)

/** A fresh code, for example `ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ`. */
export function newRecoveryCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let bits = 0;
  let acc = 0;
  let out = '';
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(acc >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  out += ALPHABET[(acc << (5 - bits)) & 31];
  bytes.fill(0);
  return out.match(/.{1,4}/g)?.join('-') ?? out;
}

/** The KDF input for a typed code: spaces and dashes removed, upper case. A malformed code is a wrong code. */
export function codeBytes(typed: string): Uint8Array {
  const c = typed.replace(/[\s-]/g, '').toUpperCase();
  if (c.length !== LENGTH || [...c].some((ch) => !ALPHABET.includes(ch))) throw new VaultError('RECOVERY_CODE_WRONG');
  return new TextEncoder().encode(c);
}
