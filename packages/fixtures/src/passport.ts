import { p256 } from '@noble/curves/nist.js';
import * as asn1js from 'asn1js';
import { tlv } from './der.ts';
import { ecSpki } from './keys.ts';
import { type MrzInput, td3 } from './mrz.ts';
import { DEMO_MARKER, type Issued, type TestPki } from './pki.ts';
import { type AaRsaHash, iso9796d2Sign, type RsaKey, rsaKeyFromSeed, rsaSpki } from './rsa.ts';
import { deriveBytes, type Seed } from './seed.ts';
import { buildSod, type SodSpec } from './sod.ts';

/** The chip's Active Authentication private key. Fixture use only. */
export type AaKey =
  | { kind: 'ec'; secretKey: Uint8Array }
  | { kind: 'rsa'; rsa: RsaKey; hash: AaRsaHash; nonceSeed: Uint8Array };

export type AaKind = 'ec' | 'rsa' | 'none';

export interface Passport {
  /** The 88-character TD3 MRZ, with DEMO / TEST ONLY in the given names. */
  mrz: string;
  dg1: Uint8Array<ArrayBuffer>;
  /** Present with an EC Active Authentication key: SecurityInfos with ActiveAuthenticationInfo. */
  dg14?: Uint8Array<ArrayBuffer>;
  /** Present unless `aa` is `none`: the Active Authentication public key. */
  dg15?: Uint8Array<ArrayBuffer>;
  sod: Uint8Array<ArrayBuffer>;
  aaKey?: AaKey;
}

/** A passport with an Active Authentication key (`aa` is `ec` or `rsa`). */
export type PassportWithAa = Passport & Required<Pick<Passport, 'dg15' | 'aaKey'>>;

export interface PassportOptions {
  pki: TestPki;
  mrz: MrzInput;
  seed: Seed;
  /** The Active Authentication key: EC P-256 (default), RSA 2048 with SHA-256, or none (only DG1 is hashed). */
  aa?: AaKind;
}

/** The MRZ name form of DEMO_MARKER: punctuation dropped, spaces as fillers (Part 3 transliteration). */
const MRZ_MARKER = DEMO_MARKER.replace(/[^A-Z ]/g, '').replace(/ +/g, ' ');

/** Part 10 4.7.1: DG1 = 61 L (5F1F L MRZ). */
const dg1Of = (mrz: string) => tlv([0x61], tlv([0x5f, 0x1f], new TextEncoder().encode(mrz)));

/**
 * DG14 with one SecurityInfo, ActiveAuthenticationInfo { id-icao-mrtd-security-aaProtocolObject, 1,
 * ecdsa-plain-SHA256 (BSI TR-03111) }, which Part 11 requires when Active Authentication uses ECDSA.
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p11_cons_en.pdf (9.2, 9.2.4)
 * Source: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_V-2-1_pdf.pdf?__blob=publicationFile (4.2.1, ecdsa-plain-SHA256 = 0.4.0.127.0.7.1.1.4.1.3)
 */
function dg14Ec(): Uint8Array<ArrayBuffer> {
  const aaInfo = new asn1js.Sequence({
    value: [
      new asn1js.ObjectIdentifier({ value: '2.23.136.1.1.5' }),
      new asn1js.Integer({ value: 1 }),
      new asn1js.ObjectIdentifier({ value: '0.4.0.127.0.7.1.1.4.1.3' }),
    ],
  });
  return tlv([0x6e], new Uint8Array(new asn1js.Set({ value: [aaInfo] }).toBER()));
}

function aaKeyFromSeed(seed: Seed, kind: 'ec' | 'rsa'): AaKey {
  if (kind === 'ec') return { kind, secretKey: p256.utils.randomSecretKey(deriveBytes(seed, 'aa/ec', 48)) };
  return {
    kind,
    rsa: rsaKeyFromSeed(seed, 'aa/rsa', 2048),
    hash: 'SHA-256',
    nonceSeed: deriveBytes(seed, 'aa/nonce', 32),
  };
}

/** Part 11 6.1.5: DG15 = 6F L SubjectPublicKeyInfo. */
const dg15Of = (k: AaKey) =>
  tlv([0x6f], k.kind === 'ec' ? ecSpki('P-256', p256.getPublicKey(k.secretKey, false)) : rsaSpki(k.rsa));

/** Everything a passport is made of, before signing; the bad-variant factory changes these. */
export interface PassportParts {
  mrz: string;
  ds: Issued;
  aaKey?: AaKey;
  /** The data groups whose hashes go into the SOD; default all present. */
  hashed?: readonly number[];
  sod?: Omit<SodSpec, 'ds' | 'dataGroups'>;
}

export function assemble(p: PassportParts): Passport {
  const dg1 = dg1Of(p.mrz);
  const dg14 = p.aaKey?.kind === 'ec' ? dg14Ec() : undefined;
  const dg15 = p.aaKey ? dg15Of(p.aaKey) : undefined;
  const all = new Map<number, Uint8Array | undefined>([
    [1, dg1],
    [14, dg14],
    [15, dg15],
  ]);
  const dataGroups = new Map<number, Uint8Array>();
  for (const [n, bytes] of all) if (bytes && (p.hashed ?? [n]).includes(n)) dataGroups.set(n, bytes);
  const sod = buildSod({ ...p.sod, ds: p.ds, dataGroups });
  return { mrz: p.mrz, dg1, sod, ...(dg14 && { dg14 }), ...(dg15 && { dg15 }), ...(p.aaKey && { aaKey: p.aaKey }) };
}

/** The MRZ with DEMO / TEST ONLY appended to the given names; throws RangeError if it does not fit. */
export const markedMrz = (m: MrzInput) => td3({ ...m, givenNames: `${m.givenNames} ${MRZ_MARKER}` });

/**
 * A fixture passport: DG1 (TD3 MRZ, country XXA by default, DEMO / TEST ONLY in the given names), DG14 and DG15 for
 * Active Authentication, and EF.SOD signed by the PKI's Document Signer over DG1, DG14 and DG15.
 */
export function makePassport(o: PassportOptions & { aa?: 'ec' | 'rsa' }): PassportWithAa;
export function makePassport(o: PassportOptions): Passport;
export function makePassport({ pki, mrz, seed, aa = 'ec' }: PassportOptions): Passport {
  return assemble({ mrz: markedMrz(mrz), ds: pki.ds, ...(aa !== 'none' && { aaKey: aaKeyFromSeed(seed, aa) }) });
}

/**
 * The chip's answer to INTERNAL AUTHENTICATE with an 8-byte RND.IFD (ICAO 9303 Part 11, 6.1).
 * EC: ECDSA P-256 over SHA-256(challenge), plain r || s (BSI TR-03111). RSA: ISO/IEC 9796-2 scheme 1 with
 * SHA-256 (trailer 34CC), M1 = a nonce derived from the key and the challenge, M2 = the challenge.
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p11_cons_en.pdf (6.1.2)
 */
export function chipAnswerAA(key: AaKey, challenge: Uint8Array): Uint8Array<ArrayBuffer> {
  if (challenge.length !== 8) throw new RangeError('RND.IFD must be 8 bytes (ICAO 9303 Part 11, 6.1.2.1)');
  if (key.kind === 'ec') return p256.sign(challenge, key.secretKey, { format: 'compact' });
  const m1Len = key.rsa.bits / 8 - 1 - 32 - 2;
  const m1 = deriveBytes(key.nonceSeed, `m1/${Buffer.from(challenge).toString('hex')}`, m1Len);
  return iso9796d2Sign(key.rsa, m1, challenge, key.hash);
}
