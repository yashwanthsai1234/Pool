import { sha1 } from '@noble/hashes/legacy.js';
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import {
  AttributeTypeAndValue,
  AttributeValue,
  AuthorityKeyIdentifier,
  BasicConstraints,
  Certificate,
  CRLDistributionPoints,
  DistributionPoint,
  DistributionPointName,
  Extension,
  Extensions,
  GeneralName,
  IssueAlternativeName,
  KeyIdentifier,
  KeyUsage,
  KeyUsageFlags,
  Name,
  PrivateKeyUsagePeriod,
  RelativeDistinguishedName,
  SubjectAlternativeName,
  SubjectKeyIdentifier,
  SubjectPublicKeyInfo,
  TBSCertificate,
  Validity,
} from '@peculiar/asn1-x509';
import * as asn1js from 'asn1js';
import { ecKeyFromSeed, rsaPssKeyFromSeed, type SigningKey, sign, signatureAlgorithm, spki } from './keys.ts';
import { deriveBytes, deriveInt, type Seed } from './seed.ts';

/** The label put in every fixture certificate and passport. */
export const DEMO_MARKER = 'DEMO / TEST ONLY';

export type PkiAlg = 'ecdsa-p256' | 'rsa-pss';

/** A certificate (DER) and its private key. */
export interface Issued {
  cert: Uint8Array<ArrayBuffer>;
  key: SigningKey;
}

export interface TestPki {
  alg: PkiAlg;
  csca: Issued;
  ds: Issued;
}

const DAY = 86_400_000;
const addYears = (d: Date, y: number) => new Date(Date.UTC(d.getUTCFullYear() + y, d.getUTCMonth(), d.getUTCDate()));
const addMonths = (d: Date, m: number) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + m, d.getUTCDate()));

function name(cn: string): Name {
  const rdn = (type: string, value: string) =>
    new RelativeDistinguishedName([
      new AttributeTypeAndValue({ type, value: new AttributeValue({ printableString: value }) }),
    ]);
  return new Name([rdn('2.5.4.6', 'XX'), rdn('2.5.4.10', DEMO_MARKER), rdn('2.5.4.3', cn)]);
}

const ext = (extnID: string, value: object, critical = false) =>
  new Extension({ extnID, critical, extnValue: new OctetString(AsnConvert.serialize(value)) });

/** RFC 5280 4.2.1.2 method 1: SHA-1 of the subjectPublicKey BIT STRING value. */
function keyId(key: SigningKey): Uint8Array {
  return sha1(new Uint8Array(AsnConvert.parse(spki(key), SubjectPublicKeyInfo).subjectPublicKey));
}

/** Part 12 7.1.1.2: a directoryName with only localityName = the MRZ country code. */
const icaoAltName = () =>
  new GeneralName({
    directoryName: new Name([
      new RelativeDistinguishedName([
        new AttributeTypeAndValue({ type: '2.5.4.7', value: new AttributeValue({ printableString: 'XXA' }) }),
      ]),
    ]),
  });

/** Part 12 7.1.1.6: documentTypeList { v0, { "P" } }. */
const documentTypeList = () =>
  new Extension({
    extnID: '2.23.136.1.1.6.2',
    critical: false,
    extnValue: new OctetString(
      new asn1js.Sequence({
        value: [
          new asn1js.Integer({ value: 0 }),
          new asn1js.Set({ value: [new asn1js.PrintableString({ value: 'P' })] }),
        ],
      }).toBER(),
    ),
  });

/** Options for one certificate; every value comes from the seed stream so the bytes are reproducible. */
interface CertSpec {
  role: 'csca' | 'ds';
  subjectCn: string;
  key: SigningKey;
  /** The issuing CSCA; absent for a self-signed CSCA. */
  issuer?: Issued & { cn: string };
  serial: Uint8Array;
  notBefore: Date;
  notAfter: Date;
  keyUsage: number;
}

/**
 * Builds and signs one certificate following ICAO 9303 Part 12 Table 5 and Table 6. Built from the
 * @peculiar/asn1-x509 schema and signed with noble, so signatures are deterministic (WebCrypto ECDSA is not).
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p12_cons_en.pdf (7.1.1)
 * Source: https://www.rfc-editor.org/rfc/rfc5280#section-4.1
 */
function issueCert(spec: CertSpec): Uint8Array<ArrayBuffer> {
  const signer = spec.issuer?.key ?? spec.key;
  const ski = keyId(spec.key);
  const pkup = addMonths(spec.notBefore, spec.role === 'csca' ? 60 : 3);
  const crl = new DistributionPoint({
    distributionPoint: new DistributionPointName({
      fullName: [new GeneralName({ uniformResourceIdentifier: 'https://legx-demo.invalid/crl/XXA.crl' })],
    }),
  });
  const extensions = [
    ext('2.5.29.35', new AuthorityKeyIdentifier({ keyIdentifier: new KeyIdentifier(keyId(signer)) })),
    ext('2.5.29.14', new SubjectKeyIdentifier(ski)),
    ext('2.5.29.15', new KeyUsage(spec.keyUsage), true),
    ext('2.5.29.16', new PrivateKeyUsagePeriod({ notBefore: spec.notBefore, notAfter: pkup })),
    ext('2.5.29.17', new SubjectAlternativeName([icaoAltName()])),
    ext('2.5.29.18', new IssueAlternativeName([icaoAltName()])),
    ext('2.5.29.31', new CRLDistributionPoints([crl])),
    spec.role === 'csca'
      ? ext('2.5.29.19', new BasicConstraints({ cA: true, pathLenConstraint: 0 }), true)
      : documentTypeList(),
  ];
  const alg = signatureAlgorithm(signer);
  const tbs = new TBSCertificate({
    version: 2,
    serialNumber: spec.serial.slice().buffer,
    signature: alg,
    issuer: name(spec.issuer?.cn ?? spec.subjectCn),
    validity: new Validity({ notBefore: spec.notBefore, notAfter: spec.notAfter }),
    subject: name(spec.subjectCn),
    subjectPublicKeyInfo: AsnConvert.parse(spki(spec.key), SubjectPublicKeyInfo),
    extensions: new Extensions(extensions),
  });
  return signTbs(tbs, signer);
}

function signTbs(tbs: TBSCertificate, signer: SigningKey): Uint8Array<ArrayBuffer> {
  const tbsDer = new Uint8Array(AsnConvert.serialize(tbs));
  const signatureValue = sign(signer, tbsDer).slice().buffer;
  return new Uint8Array(
    AsnConvert.serialize(new Certificate({ tbsCertificate: tbs, signatureAlgorithm: tbs.signature, signatureValue })),
  );
}

/** What `reissue` may change in an existing certificate. */
export interface Reissue {
  /** The key that signs the new certificate (the issuer's key, or a rogue one). */
  signer: SigningKey;
  /** A new subject key; the SubjectKeyIdentifier follows it. */
  key?: SigningKey;
  /** New validity start; the end and the private key usage period keep their distance to it. */
  notBefore?: Date;
  keyUsage?: number;
}

/**
 * The same certificate with only the listed changes, signed again; the bad-variant factory uses it so each
 * variant differs from the good fixture in one way. The signature algorithm follows the signer.
 */
export function reissue(cert: Uint8Array, r: Reissue): Uint8Array<ArrayBuffer> {
  const tbs = AsnConvert.parse(cert, Certificate).tbsCertificate;
  tbs.signature = signatureAlgorithm(r.signer);
  const exts = tbs.extensions ?? new Extensions();
  const replace = (e: Extension) =>
    exts.splice(
      exts.findIndex((x) => x.extnID === e.extnID),
      1,
      e,
    );
  if (r.key) {
    tbs.subjectPublicKeyInfo = AsnConvert.parse(spki(r.key), SubjectPublicKeyInfo);
    replace(ext('2.5.29.14', new SubjectKeyIdentifier(keyId(r.key))));
  }
  if (r.keyUsage !== undefined) replace(ext('2.5.29.15', new KeyUsage(r.keyUsage), true));
  if (r.notBefore) {
    const shift = r.notBefore.getTime() - tbs.validity.notBefore.getTime().getTime();
    const moved = (d: Date) => new Date(d.getTime() + shift);
    tbs.validity = new Validity({ notBefore: r.notBefore, notAfter: moved(tbs.validity.notAfter.getTime()) });
    const pkup = AsnConvert.parse(
      exts.find((x) => x.extnID === '2.5.29.16')?.extnValue.buffer ?? new ArrayBuffer(0),
      PrivateKeyUsagePeriod,
    );
    replace(
      ext(
        '2.5.29.16',
        new PrivateKeyUsagePeriod({ notBefore: r.notBefore, notAfter: moved(pkup.notAfter ?? r.notBefore) }),
      ),
    );
  }
  return signTbs(tbs, r.signer);
}

/** A positive serial number of 8 octets with a non-zero, non-negative first octet (Part 12 Table 5). */
function serialFromSeed(seed: Seed, label: string): Uint8Array {
  const s = deriveBytes(seed, `${label}/serial`, 8);
  s[0] = ((s[0] ?? 0) & 0x7f) | 0x40;
  return s;
}

/** A date `[0, spanDays)` days after `from`, at midnight UTC. */
export function dateFromSeed(seed: Seed, label: string, from: Date, spanDays: number): Date {
  return new Date(from.getTime() + deriveInt(seed, label, 0, spanDays) * DAY);
}

const CSCA_CN = 'LegX Test CSCA XXA';

export function cscaFromSeed(seed: Seed, label: string, alg: PkiAlg): Issued & { cn: string } {
  const key = alg === 'ecdsa-p256' ? ecKeyFromSeed(seed, label, 'P-256') : rsaPssKeyFromSeed(seed, label, 3072);
  const notBefore = dateFromSeed(seed, `${label}/notBefore`, new Date('2025-01-01T00:00:00Z'), 365);
  const cert = issueCert({
    role: 'csca',
    subjectCn: CSCA_CN,
    key,
    serial: serialFromSeed(seed, label),
    notBefore,
    notAfter: addYears(notBefore, 15),
    keyUsage: KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign,
  });
  return { cert, key, cn: CSCA_CN };
}

/** A Document Signer certificate issued by `csca` for the key that `seed`/`label` derives. */
function dsFromSeed(seed: Seed, label: string, alg: PkiAlg, csca: Issued & { cn: string }): Issued {
  const key = alg === 'rsa-pss' ? rsaPssKeyFromSeed(seed, label, 2048) : ecKeyFromSeed(seed, label, 'P-256');
  const cscaStart = new Date(certNotBefore(csca.cert) + DAY);
  const notBefore = dateFromSeed(seed, `${label}/notBefore`, cscaStart, 60);
  const cert = issueCert({
    role: 'ds',
    subjectCn: 'LegX Test Document Signer XXA',
    key,
    issuer: csca,
    serial: serialFromSeed(seed, label),
    notBefore,
    notAfter: addYears(notBefore, 11),
    keyUsage: KeyUsageFlags.digitalSignature,
  });
  return { cert, key };
}

const certNotBefore = (der: Uint8Array) =>
  AsnConvert.parse(der, Certificate).tbsCertificate.validity.notBefore.getTime().getTime();

/**
 * A test CSCA (self-signed) and a Document Signer it issued. ECDSA P-256 by default; `rsa-pss` gives RSA-PSS
 * (3072-bit CSCA, 2048-bit DS). Same seed, same bytes.
 */
export function makeTestPki({ seed, alg = 'ecdsa-p256' }: { seed: Seed; alg?: PkiAlg }): TestPki {
  const csca = cscaFromSeed(seed, 'csca', alg);
  return { alg, csca: { cert: csca.cert, key: csca.key }, ds: dsFromSeed(seed, 'ds', alg, csca) };
}
