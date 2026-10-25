// Passport data parsing for the lawyer's console (DESIGN 6.15): the BER-TLV wrappers of the LDS files, EF.SOD (CMS
// SignedData with an LDSSecurityObject), EC public keys, and one signature check with a noble fallback.
// Only `passiveAuth.ts` and `activeAuth.ts` import this module; `attest.ts` never does (raw passport data stays out of
// the release gate, invariant I7). Every function returns `undefined` or a code on bad input and never throws.
import { brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 } from '@noble/curves/misc.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { equalBytes } from '@noble/curves/utils.js';
import { sha1 } from '@noble/hashes/legacy.js';
import { sha224, sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

/** EF.SOD and the data groups are small; anything larger is refused before parsing. */
const MAX_LDS_FILE = 65536;

/**
 * The contents of one BER-TLV with the given tag, which must span `bytes` exactly. Definite lengths of up to 2 bytes
 * only (an LDS file is at most 64 KiB), so an indefinite or oversized length is refused.
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p10_cons_en.pdf (4.4 and 4.7, tags 61, 6E, 6F, 77)
 */
export function unwrapTag(bytes: Uint8Array, tag: readonly number[]): Uint8Array | undefined {
  if (bytes.length > MAX_LDS_FILE || bytes.length < tag.length + 1) return undefined;
  if (tag.some((t, i) => bytes[i] !== t)) return undefined;
  let at = tag.length;
  const first = bytes[at++] ?? 0;
  let len = first;
  if (first === 0x81 || first === 0x82) {
    const n = first & 0x7f;
    if (bytes.length < at + n) return undefined;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + (bytes[at++] ?? 0);
  } else if (first > 0x7f) return undefined;
  return at + len === bytes.length ? bytes.subarray(at) : undefined;
}

/** One DER/BER value that spans `bytes` exactly, or undefined. */
export function berExact(bytes: Uint8Array): asn1js.AsnType | undefined {
  const asn = asn1js.fromBER(bytes);
  return asn.offset === bytes.length && asn.result.error === '' ? asn.result : undefined;
}

// ---------- hashes and curves ----------

/** A one-shot hash function (noble). */
export interface Hash {
  (msg: Uint8Array): Uint8Array;
  readonly outputLen: number;
}
/** Digest algorithm OIDs (RFC 5754, RFC 3279). */
export const HASH_BY_OID: Readonly<Record<string, Hash>> = {
  '1.3.14.3.2.26': sha1,
  '2.16.840.1.101.3.4.2.4': sha224,
  '2.16.840.1.101.3.4.2.1': sha256,
  '2.16.840.1.101.3.4.2.2': sha384,
  '2.16.840.1.101.3.4.2.3': sha512,
};
/** ecdsa-with-SHA* signature algorithm OIDs to their hash (RFC 5758 3.2, RFC 3279 2.2.3). */
const ECDSA_HASH: Readonly<Record<string, Hash>> = {
  '1.2.840.10045.4.1': sha1,
  '1.2.840.10045.4.3.1': sha224,
  '1.2.840.10045.4.3.2': sha256,
  '1.2.840.10045.4.3.3': sha384,
  '1.2.840.10045.4.3.4': sha512,
};

type Curve = typeof p256;
/** Named curves by OID (RFC 5480 2.1.1.1, RFC 5639 4.1). WebCrypto has only the first three. */
const CURVES: Readonly<Record<string, Curve>> = {
  '1.2.840.10045.3.1.7': p256,
  '1.3.132.0.34': p384 as unknown as Curve,
  '1.3.132.0.35': p521 as unknown as Curve,
  '1.3.36.3.3.2.8.1.1.7': brainpoolP256r1 as unknown as Curve,
  '1.3.36.3.3.2.8.1.1.11': brainpoolP384r1 as unknown as Curve,
  '1.3.36.3.3.2.8.1.1.13': brainpoolP512r1 as unknown as Curve,
};
const WEBCRYPTO_CURVES = new Set(['1.2.840.10045.3.1.7', '1.3.132.0.34', '1.3.132.0.35']);
const ID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';

const intOf = (v: asn1js.AsnType | undefined): bigint | undefined => {
  if (!(v instanceof asn1js.Integer || v instanceof asn1js.OctetString)) return undefined;
  const hex = bytesToHex(v.valueBlock.valueHexView);
  return hex === '' ? undefined : BigInt(`0x${hex}`);
};
const mod = (a: bigint, p: bigint) => ((a % p) + p) % p;

/**
 * The noble curve whose explicit prime-field parameters (p, a, b, G, n) equal `params`, or undefined. Many CSCAs and
 * chips encode the curve this way instead of by name.
 * Source: https://www.rfc-editor.org/rfc/rfc3279#section-2.3.5 (ECParameters, specifiedCurve)
 * Source: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_V-2-1_pdf.pdf?__blob=publicationFile (5.1.1)
 */
function curveFromExplicit(params: asn1js.Sequence): Curve | undefined {
  const [, fieldId, curve, base, order] = params.valueBlock.value;
  if (!(fieldId instanceof asn1js.Sequence && curve instanceof asn1js.Sequence && base instanceof asn1js.OctetString))
    return undefined;
  const [fieldType, prime] = fieldId.valueBlock.value;
  if (!(fieldType instanceof asn1js.ObjectIdentifier) || fieldType.valueBlock.toString() !== '1.2.840.10045.1.1')
    return undefined;
  const [a, b] = curve.valueBlock.value;
  const p = intOf(prime);
  const n = intOf(order);
  for (const c of new Set(Object.values(CURVES))) {
    const k = c.Point.CURVE();
    if (p !== k.p || n !== k.n || intOf(a) !== mod(k.a, k.p) || intOf(b) !== mod(k.b, k.p)) continue;
    try {
      if (c.Point.fromBytes(base.valueBlock.valueHexView).equals(c.Point.BASE)) return c;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

/** An EC public key from a SubjectPublicKeyInfo: its noble curve, raw point, and whether WebCrypto can use it. */
export function ecKeyOf(
  spki: pkijs.PublicKeyInfo,
): { curve: Curve; point: Uint8Array; webCrypto: boolean } | undefined {
  if (spki.algorithm.algorithmId !== ID_EC_PUBLIC_KEY) return undefined;
  const params = spki.algorithm.algorithmParams as asn1js.AsnType | undefined;
  const point = spki.subjectPublicKey.valueBlock.valueHexView;
  if (params instanceof asn1js.ObjectIdentifier) {
    const oid = params.valueBlock.toString();
    const curve = CURVES[oid];
    return curve && { curve, point, webCrypto: WEBCRYPTO_CURVES.has(oid) };
  }
  const curve = params instanceof asn1js.Sequence ? curveFromExplicit(params) : undefined;
  return curve && { curve, point, webCrypto: false };
}

/**
 * ECDSA verification with noble over a digest, with `lowS: false`: passport chips, Document Signers and CSCAs do not
 * normalize S, and noble v2 rejects high S by default. Never throws.
 * Source: https://github.com/paulmillr/noble-curves (ECDSA verify options: prehash, format, lowS)
 */
export function nobleEcdsaVerify(
  key: { curve: Curve; point: Uint8Array },
  digest: Uint8Array,
  sig: Uint8Array,
  format: 'der' | 'compact',
): boolean {
  try {
    return key.curve.verify(sig, digest, key.point, { prehash: false, format, lowS: false });
  } catch {
    return false;
  }
}

export type SigCheck = 'valid' | 'invalid' | 'unsupported';

/**
 * One X.509 or CMS signature check. PKI.js (WebCrypto) is the main path. EC keys that WebCrypto cannot import
 * (brainpool, explicit parameters) take the noble fallback. `cmsHash` names the SignerInfo digest algorithm, which
 * PKI.js needs only when the signature algorithm is plain rsaEncryption.
 * Source: https://github.com/PeculiarVentures/PKI.js/blob/v3.4.3/src/CryptoEngine/CryptoEngine.ts (verifyWithPublicKey)
 * Source: https://www.rfc-editor.org/rfc/rfc5652#section-5.4 (the signed attributes are hashed as a SET OF)
 */
export async function verifySignature(
  data: Uint8Array,
  signature: Uint8Array,
  spki: pkijs.PublicKeyInfo,
  algorithm: pkijs.AlgorithmIdentifier,
  cmsHash?: string,
): Promise<SigCheck> {
  const ec = ecKeyOf(spki);
  if (spki.algorithm.algorithmId === ID_EC_PUBLIC_KEY && !ec) return 'unsupported';
  if (ec && !ec.webCrypto) {
    const hash = ECDSA_HASH[algorithm.algorithmId];
    if (!hash) return 'unsupported';
    return nobleEcdsaVerify(ec, hash(data), signature, 'der') ? 'valid' : 'invalid';
  }
  const engine = pkijs.getCrypto(true);
  const plainRsa = algorithm.algorithmId === '1.2.840.113549.1.1.1';
  try {
    const ok = await engine.verifyWithPublicKey(
      new Uint8Array(data),
      new asn1js.OctetString({ valueHex: signature }),
      spki,
      algorithm,
      plainRsa ? cmsHash : undefined,
    );
    return ok ? 'valid' : 'invalid';
  } catch {
    return 'unsupported';
  }
}

// ---------- EF.SOD ----------

export const ID_LDS_SECURITY_OBJECT = '2.23.136.1.1.1';
const ID_SIGNED_DATA = '1.2.840.113549.1.7.2';

export interface Sod {
  readonly signedData: pkijs.SignedData;
  readonly signerInfo: pkijs.SignerInfo;
  /** The certificate the SignerInfo names, if the SOD carries it. */
  readonly dsCert: pkijs.Certificate | undefined;
  readonly eContentType: string;
  readonly eContent: Uint8Array;
}

/**
 * EF.SOD: tag 77 around a ContentInfo with SignedData and exactly one SignerInfo (Part 10 Table 37). Parsed with
 * PKI.js; `undefined` for anything else.
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p10_cons_en.pdf (4.6.2, Table 37)
 * Source: https://github.com/PeculiarVentures/PKI.js/blob/v3.4.3/src/SignedData.ts
 */
export function parseSod(bytes: Uint8Array): Sod | undefined {
  try {
    const inner = unwrapTag(bytes, [0x77]);
    const asn = inner && berExact(inner);
    if (!asn) return undefined;
    const ci = new pkijs.ContentInfo({ schema: asn });
    if (ci.contentType !== ID_SIGNED_DATA) return undefined;
    const signedData = new pkijs.SignedData({ schema: ci.content });
    const [signerInfo, ...more] = signedData.signerInfos;
    const eContent = signedData.encapContentInfo.eContent;
    if (!signerInfo || more.length > 0 || !eContent) return undefined;
    const dsCert = signedData.certificates?.find(
      (c): c is pkijs.Certificate => c instanceof pkijs.Certificate && namesSigner(c, signerInfo),
    );
    return {
      signedData,
      signerInfo,
      dsCert,
      eContentType: signedData.encapContentInfo.eContentType,
      eContent: new Uint8Array(eContent.getValue()),
    };
  } catch {
    return undefined;
  }
}

/** The SignerInfo names the certificate by issuer and serial number, or by subject key identifier (RFC 5652 5.3). */
function namesSigner(cert: pkijs.Certificate, si: pkijs.SignerInfo): boolean {
  if (si.sid instanceof pkijs.IssuerAndSerialNumber) {
    return cert.issuer.isEqual(si.sid.issuer) && cert.serialNumber.isEqual(si.sid.serialNumber);
  }
  const ski = cert.extensions?.find((e) => e.extnID === '2.5.29.14')?.parsedValue as asn1js.OctetString | undefined;
  const keyId = (si.sid as asn1js.Primitive).valueBlock?.valueHexView;
  return !!ski && !!keyId && equalBytes(new Uint8Array(ski.valueBlock.valueHexView), new Uint8Array(keyId));
}

/** One signed attribute's single value, or undefined if absent or repeated. */
export function signedAttr(si: pkijs.SignerInfo, oid: string): asn1js.AsnType | undefined {
  const found = si.signedAttrs?.attributes.filter((a) => a.type === oid) ?? [];
  const [only] = found;
  return found.length === 1 && only?.values.length === 1 ? only.values[0] : undefined;
}

export interface Lds {
  readonly hash: Hash;
  /** Data group number to its hash. */
  readonly hashes: ReadonlyMap<number, Uint8Array>;
}

/**
 * LDSSecurityObject ::= SEQUENCE { version (0 | 1), hashAlgorithm, dataGroupHashValues SEQUENCE SIZE (2..16) OF
 * DataGroupHash, ldsVersionInfo present if and only if version is 1 }. 'few' is a list of fewer than 2 hashes.
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p10_cons_en.pdf (4.6.2.3)
 */
export function parseLds(eContent: Uint8Array): Lds | 'few' | undefined {
  try {
    return readLds(eContent);
  } catch {
    return undefined; // asn1js and pvtsutils throw on some malformed BER (I-22): chip data is hostile input
  }
}
function readLds(eContent: Uint8Array): Lds | 'few' | undefined {
  const asn = berExact(eContent);
  if (!(asn instanceof asn1js.Sequence)) return undefined;
  const [version, alg, list, info, ...rest] = asn.valueBlock.value;
  if (!(version instanceof asn1js.Integer && alg instanceof asn1js.Sequence && list instanceof asn1js.Sequence)) {
    return undefined;
  }
  const v = version.valueBlock.valueDec;
  if (rest.length > 0 || !(v === 0 ? info === undefined : v === 1 && info instanceof asn1js.Sequence)) return undefined;
  const oid = alg.valueBlock.value[0];
  const hash = oid instanceof asn1js.ObjectIdentifier ? HASH_BY_OID[oid.valueBlock.toString()] : undefined;
  if (!hash) return undefined;
  const hashes = new Map<number, Uint8Array>();
  for (const entry of list.valueBlock.value) {
    const [n, h, ...extra] = entry instanceof asn1js.Sequence ? entry.valueBlock.value : [];
    if (!(n instanceof asn1js.Integer && h instanceof asn1js.OctetString) || extra.length > 0) return undefined;
    const dg = n.valueBlock.valueDec;
    const value = h.valueBlock.valueHexView;
    if (dg < 1 || dg > 16 || hashes.has(dg) || value.length !== hash.outputLen) return undefined;
    hashes.set(dg, new Uint8Array(value));
  }
  if (hashes.size < 2) return 'few';
  return hashes.size <= 16 ? { hash, hashes } : undefined;
}
