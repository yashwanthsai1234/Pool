// X-Wing HPKE for share transport (DESIGN 6.4 rule 3, 6.13): the `ShareCipher` core's DKG, refresh and repair take,
// built on task 1.16's `sealPackage('share')` (suite `hpke-xwing-v1`, info `legx/hpke/share/v1`). The blob is
// enc (1,120 bytes) || ciphertext, which the wire splits into the contract's `SealedBox`.
// Source: https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/
// Source: https://www.rfc-editor.org/rfc/rfc9180 (HPKE base mode, AAD)

import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import type { ShareCipher } from './frostDkg.ts';
import { openPackage, sealPackage, XWING_SUITE } from './pq.ts';

/** Length of the X-Wing encapsulated key (ML-KEM-768 ciphertext 1,088 plus X25519 32). */
export const XWING_ENC_LENGTH = 1120;

export const xwingShareCipher: ShareCipher = {
  suite: XWING_SUITE,
  keygen: () => ml_kem768_x25519.keygen(),
  publicKeyOf: (secretKey) => ml_kem768_x25519.getPublicKey(secretKey),
  async seal(publicKey, aad, plaintext) {
    const box = await sealPackage('share', publicKey, plaintext, aad);
    const out = new Uint8Array(box.enc.length + box.ct.length);
    out.set(box.enc);
    out.set(box.ct, box.enc.length);
    return out;
  },
  async open(secretKey, aad, blob) {
    const opened = await openPackage(
      'share',
      { suite: XWING_SUITE, enc: blob.slice(0, XWING_ENC_LENGTH), ct: blob.slice(XWING_ENC_LENGTH) },
      secretKey,
      aad,
    );
    if (!opened.ok) throw new Error(opened.code);
    return opened.plaintext;
  },
};
