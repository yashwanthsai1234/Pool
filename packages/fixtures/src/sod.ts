import { sha256 } from '@noble/hashes/sha2.js';
import {
  Attribute,
  CertificateChoices,
  CertificateSet,
  ContentInfo,
  DigestAlgorithmIdentifier,
  DigestAlgorithmIdentifiers,
  EncapsulatedContent,
  EncapsulatedContentInfo,
  IssuerAndSerialNumber,
  SignedData,
  SignerIdentifier,
  SignerInfo,
  SignerInfos,
} from '@peculiar/asn1-cms';
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';
import * as asn1js from 'asn1js';
import { derSetOf, tlv } from './der.ts';
import { sign, signatureAlgorithm } from './keys.ts';
import { encodeLds, ID_LDS_SECURITY_OBJECT, ID_SHA256 } from './lds.ts';
import type { Issued } from './pki.ts';

/** The knobs the bad-variant factory turns; each defaults to the ICAO-conformant value. */
export interface SodSpec {
  ds: Issued;
  /** Data group number to the exact bytes of that EF; each is hashed with SHA-256, in ascending order. */
  dataGroups: ReadonlyMap<number, Uint8Array>;
  eContentType?: string;
  /** Replaces SHA-256(eContent) in the messageDigest signed attribute. */
  messageDigest?: Uint8Array;
  /** false leaves out the DS certificate. */
  includeCertificate?: boolean;
  /** Changes the signature bytes after signing (bad signature, high S). */
  tweakSignature?: (signature: Uint8Array) => Uint8Array;
}

const attr = (attrType: string, value: ArrayBuffer) =>
  new Uint8Array(AsnConvert.serialize(new Attribute({ attrType, attrValues: [value] })));

/**
 * EF.SOD: tag 77 around a CMS ContentInfo with SignedData v3 holding an LDSSecurityObject v1 (LDS 1.8),
 * the DS certificate, one SignerInfo (issuerAndSerialNumber) and the signed attributes contentType and
 * messageDigest, DER-sorted because verifiers such as OpenSSL re-encode them before checking the signature.
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p10_cons_en.pdf (4.6.2, Table 37)
 * Source: https://www.rfc-editor.org/rfc/rfc5652#section-5.4
 */
export function buildSod(s: SodSpec): Uint8Array<ArrayBuffer> {
  const hashes = [...s.dataGroups.entries()]
    .sort(([a], [b]) => a - b)
    .map(([dg, bytes]) => ({ dg, hash: sha256(bytes) }));
  const eContent = encodeLds({
    version: 1,
    hashAlgorithm: ID_SHA256,
    hashes,
    ldsVersion: { lds: '0108', unicode: '040000' },
  });
  const eContentType = s.eContentType ?? ID_LDS_SECURITY_OBJECT;
  const signedAttrs = [
    attr('1.2.840.113549.1.9.3', new asn1js.ObjectIdentifier({ value: eContentType }).toBER()),
    attr('1.2.840.113549.1.9.4', AsnConvert.serialize(new OctetString(s.messageDigest ?? sha256(eContent)))),
  ];
  const signedAttrsDer = derSetOf(signedAttrs);
  const signature = (s.tweakSignature ?? ((x) => x))(sign(s.ds.key, signedAttrsDer));
  const ds = AsnConvert.parse(s.ds.cert, Certificate);
  const digestAlgorithm = new DigestAlgorithmIdentifier({ algorithm: ID_SHA256 });
  const signerInfo = new SignerInfo({
    version: 1,
    sid: new SignerIdentifier({
      issuerAndSerialNumber: new IssuerAndSerialNumber({
        issuer: ds.tbsCertificate.issuer,
        serialNumber: ds.tbsCertificate.serialNumber,
      }),
    }),
    digestAlgorithm,
    signedAttrs: [...signedAttrs].sort((a, b) => Buffer.compare(a, b)).map((a) => AsnConvert.parse(a, Attribute)),
    signatureAlgorithm: signatureAlgorithm(s.ds.key),
    signature: new OctetString(signature),
  });
  const signedData = new SignedData({
    version: 3,
    digestAlgorithms: new DigestAlgorithmIdentifiers([digestAlgorithm]),
    encapContentInfo: new EncapsulatedContentInfo({
      eContentType,
      eContent: new EncapsulatedContent({ single: new OctetString(eContent) }),
    }),
    ...(s.includeCertificate === false
      ? {}
      : { certificates: new CertificateSet([new CertificateChoices({ certificate: ds })]) }),
    signerInfos: new SignerInfos([signerInfo]),
  });
  const contentInfo = new ContentInfo({
    contentType: '1.2.840.113549.1.7.2',
    content: AsnConvert.serialize(signedData),
  });
  return tlv([0x77], new Uint8Array(AsnConvert.serialize(contentInfo)));
}
