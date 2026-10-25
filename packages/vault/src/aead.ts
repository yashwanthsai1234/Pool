// AES-GCM sealing for the vault, with three key sources: a non-extractable device key, a key derived from the
// WebAuthn PRF output with HKDF, and a key derived from a recovery code with PBKDF2. Every ciphertext carries
// an AAD that names its entry and its kind, so a ciphertext moved to another entry or field does not open.
// Source: https://w3c.github.io/webcrypto/#aes-gcm
// Source: https://w3c.github.io/webcrypto/#hkdf (RFC 5869) and https://w3c.github.io/webcrypto/#pbkdf2
import { tupleHash } from '@legx/core/dealcore';
import { VaultError } from './errors.ts';

export type Sealed = { iv: Uint8Array; ct: Uint8Array };

/** TypeScript's DOM types want `Uint8Array<ArrayBuffer>`; noble returns `Uint8Array<ArrayBufferLike>`. */
export const bs = (b: Uint8Array): Uint8Array<ArrayBuffer> => b as Uint8Array<ArrayBuffer>;

const enc = new TextEncoder();
const AES = { name: 'AES-GCM', length: 256 } as const;
const USES: KeyUsage[] = ['encrypt', 'decrypt'];

/** PBKDF2-HMAC-SHA256 work factor for recovery codes (OWASP Password Storage Cheat Sheet, 2023 onward). */
export const PBKDF2_ITERATIONS = 600_000;
const PBKDF2_MAX = 10_000_000; // a hostile file must not hang the page

/**
 * A fresh AES-256-GCM key that no script can export (`extractable: false`); IndexedDB stores it by structured clone.
 * Source: https://w3c.github.io/webcrypto/#dfn-CryptoKey-extractable
 * Source: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey
 */
export const newDeviceKey = (): Promise<CryptoKey> => crypto.subtle.generateKey(AES, false, USES);

/** AAD: `legx/vault/v1 | entry id | field`. */
export const aad = (id: string, field: string): Uint8Array => enc.encode(`legx/vault/v1|${id}|${field}`);

export async function seal(key: CryptoKey, pt: Uint8Array, ad: Uint8Array): Promise<Sealed> {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit random IV, one per message (SP 800-38D 8.2.2)
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: bs(ad) }, key, bs(pt)));
  return { iv, ct };
}

/** Opens a sealed value. The caller owns the plaintext and must zero it. A bad tag gives `DECRYPT_FAILED`. */
export async function open(key: CryptoKey, s: Sealed, ad: Uint8Array): Promise<Uint8Array> {
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bs(s.iv), additionalData: bs(ad) }, key, bs(s.ct)),
    );
  } catch {
    throw new VaultError('DECRYPT_FAILED');
  }
}

/**
 * The share-2 key from the PRF output: HKDF-SHA256 with a salt that names the deal and slot (IMPLEMENTATION 4.2).
 * The PRF bytes are imported (WebCrypto copies them) and the caller zeroes its buffer.
 * Source: https://www.rfc-editor.org/rfc/rfc5869 ; https://w3c.github.io/webauthn/#prf-extension
 */
export async function keyFromPrf(prf: Uint8Array, dealId: string, slot: string): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey('raw', bs(prf), 'HKDF', false, ['deriveKey']);
  const salt = tupleHash('legx/vault-prf-salt/v1', [enc.encode(dealId), enc.encode(slot)]);
  const info = enc.encode('legx/vault/share2-key/v1');
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: bs(salt), info }, ikm, AES, false, USES);
}

/**
 * The recovery-file key from a recovery code: PBKDF2-HMAC-SHA256 with a random 16-byte salt.
 * The code is 128 random bits (recoveryCode.ts), so the work factor is defence in depth, not the main barrier.
 * Source: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
 */
export async function keyFromCode(code: Uint8Array, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  if (!Number.isInteger(iterations) || iterations < PBKDF2_ITERATIONS || iterations > PBKDF2_MAX)
    throw new VaultError('FILE_INVALID');
  const base = await crypto.subtle.importKey('raw', bs(code), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: bs(salt), iterations },
    base,
    AES,
    false,
    USES,
  );
}

/** Zeroes every buffer. */
export const wipe = (...bufs: (Uint8Array | undefined)[]): void => {
  for (const b of bufs) b?.fill(0);
};
