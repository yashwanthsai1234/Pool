import { brainpoolP256r1 } from '@noble/curves/misc.js';
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { ECParameters } from '@peculiar/asn1-ecc';
import { RsaSaPssParams, sha256 as sha256Alg } from '@peculiar/asn1-rsa';
import { AsnConvert } from '@peculiar/asn1-schema';
import { AlgorithmIdentifier, SubjectPublicKeyInfo } from '@peculiar/asn1-x509';
import { type RsaKey, rsaKeyFromSeed, rsaPssSign, rsaSpki } from './rsa.ts';
import { deriveBytes, type Seed } from './seed.ts';

const CURVES = {
  'P-256': { curve: p256, oid: '1.2.840.10045.3.1.7' },
  brainpoolP256r1: { curve: brainpoolP256r1, oid: '1.3.36.3.3.2.8.1.1.7' },
} as const;
export type Curve = keyof typeof CURVES;

/** A Document Signer or CSCA key. Fixture use only. */
export type SigningKey =
  | { kind: 'ec'; curve: Curve; secretKey: Uint8Array }
  | { kind: 'rsa-pss'; rsa: RsaKey; saltSeed: Uint8Array };

/** Source: https://www.rfc-editor.org/rfc/rfc5480#section-2 (id-ecPublicKey with a named curve) */
export function ecKeyFromSeed(seed: Seed, label: string, curve: Curve): SigningKey {
  // 48 bytes reduced mod n - 1, plus 1 (FIPS 186-5 A.2.1), which noble's randomSecretKey(seed) implements.
  const secretKey = CURVES[curve].curve.utils.randomSecretKey(deriveBytes(seed, `${label}/ec`, 48));
  return { kind: 'ec', curve, secretKey };
}

export function rsaPssKeyFromSeed(seed: Seed, label: string, bits: number): SigningKey {
  return {
    kind: 'rsa-pss',
    rsa: rsaKeyFromSeed(seed, `${label}/rsa`, bits),
    saltSeed: deriveBytes(seed, `${label}/pss`, 32),
  };
}

export function ecSpki(curve: Curve, publicKey: Uint8Array): Uint8Array<ArrayBuffer> {
  const params = AsnConvert.serialize(new ECParameters({ namedCurve: CURVES[curve].oid }));
  const info = new SubjectPublicKeyInfo({
    algorithm: new AlgorithmIdentifier({ algorithm: '1.2.840.10045.2.1', parameters: params }),
    subjectPublicKey: publicKey.slice().buffer,
  });
  return new Uint8Array(AsnConvert.serialize(info));
}

export function spki(k: SigningKey): Uint8Array<ArrayBuffer> {
  if (k.kind === 'rsa-pss') return rsaSpki(k.rsa);
  return ecSpki(k.curve, CURVES[k.curve].curve.getPublicKey(k.secretKey, false));
}

/**
 * The signatureAlgorithm for certificates and SignerInfo: ecdsa-with-SHA256 (no parameters, RFC 5758 3.2), or
 * id-RSASSA-PSS with SHA-256, MGF1-SHA-256 and salt length 32 (RFC 4055 3.1).
 * Source: https://www.rfc-editor.org/rfc/rfc5758#section-3.2
 * Source: https://www.rfc-editor.org/rfc/rfc4055#section-3.1
 */
export function signatureAlgorithm(k: SigningKey): AlgorithmIdentifier {
  if (k.kind === 'ec') return new AlgorithmIdentifier({ algorithm: '1.2.840.10045.4.3.2' });
  const params = new RsaSaPssParams({
    hashAlgorithm: sha256Alg,
    maskGenAlgorithm: new AlgorithmIdentifier({
      algorithm: '1.2.840.113549.1.1.8',
      parameters: AsnConvert.serialize(sha256Alg),
    }),
    saltLength: 32,
  });
  return new AlgorithmIdentifier({ algorithm: '1.2.840.113549.1.1.10', parameters: AsnConvert.serialize(params) });
}

/**
 * Deterministic signature over `data` with SHA-256: DER ECDSA (RFC 6979 nonces, low S) or RSASSA-PSS with a salt
 * derived from the key's salt seed and the message.
 * Source: https://www.rfc-editor.org/rfc/rfc6979
 */
export function sign(k: SigningKey, data: Uint8Array): Uint8Array<ArrayBuffer> {
  if (k.kind === 'ec') return CURVES[k.curve].curve.sign(data, k.secretKey, { format: 'der' });
  return rsaPssSign(k.rsa, data, deriveBytes(k.saltSeed, `salt/${bytesToHex(sha256(data))}`, 32));
}
