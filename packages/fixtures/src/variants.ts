import { p256 } from '@noble/curves/nist.js';
import { KeyUsageFlags } from '@peculiar/asn1-x509';
import { ecKeyFromSeed } from './keys.ts';
import { checkDigit, type MrzInput } from './mrz.ts';
import { assemble, makePassport, markedMrz, type Passport, type PassportParts } from './passport.ts';
import { cscaFromSeed, dateFromSeed, reissue, type TestPki } from './pki.ts';
import { deriveBytes, type Seed } from './seed.ts';

export type VariantName =
  | 'badSodSignature'
  | 'wrongCsca'
  | 'changedDg1'
  | 'expiredDocument'
  | 'expiredDsCert'
  | 'highS'
  | 'brainpoolDs'
  | 'singleHash'
  | 'messageDigestMismatch'
  | 'wrongContentType'
  | 'noDsCertificate'
  | 'dsKeyUsage'
  | 'changedDg15'
  | 'badCheckDigit';

export interface Variant {
  name: VariantName;
  passport: Passport;
  /** What an ICAO 9303 conformant verifier, trusting only the good CSCA, must conclude. */
  expect: 'accept' | 'reject';
  /** The failure a verifier should report (task 1.9 codes where they exist), or PASS with a note. */
  reason: string;
  description: string;
}

/** The variants; `highS` exists only for an ECDSA Document Signer. */
export type Variants = Record<Exclude<VariantName, 'highS' | 'wrongCsca'>, Variant> & {
  wrongCsca: Variant & { rogueCsca: Uint8Array };
  highS?: Variant;
};

const fyymmdd = (d: Date) => d.toISOString().slice(2, 10).replace(/-/g, '');

/**
 * The bad-variant factory: each variant changes the good passport for (pki, mrz, seed) in one way, so a verifier test
 * can name exactly one reason. Two variants are valid but unusual (high S, brainpool DS) and must be accepted.
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p11_cons_en.pdf (5.1 passive authentication)
 */
export function makeBadVariants({ pki, mrz, seed }: { pki: TestPki; mrz: MrzInput; seed: Seed }): Variants {
  const good = makePassport({ pki, mrz, seed });
  const base: PassportParts = { mrz: good.mrz, ds: pki.ds, ...(good.aaKey && { aaKey: good.aaKey }) };
  const v = (name: VariantName, passport: Passport, reason: string, description: string): Variant => ({
    name,
    passport,
    expect: reason.startsWith('PASS') ? 'accept' : 'reject',
    reason,
    description,
  });
  const flipLastByte = (sig: Uint8Array) => {
    const out = sig.slice();
    out[out.length - 1] = (out[out.length - 1] ?? 0) ^ 0x01;
    return out;
  };

  const rogue = cscaFromSeed(seed, 'variant/rogue-csca', pki.alg);
  const forgedDs = { cert: reissue(pki.ds.cert, { signer: rogue.key }), key: pki.ds.key };

  const otherDocNumber = mrz.documentNumber === 'FORGED001' ? 'FORGED002' : 'FORGED001';
  const pastExpiry = fyymmdd(dateFromSeed(seed, 'variant/expiry', new Date('2020-01-01T00:00:00Z'), 6 * 365));

  // The document number check digit is MRZ position 54 (line 2, position 10); the composite is recomputed so it
  // stays right and exactly one check digit is wrong.
  const wrongCd = (() => {
    const m = good.mrz;
    const bad = String((Number(m[53]) + 1) % 10);
    const line2 = m.slice(44, 53) + bad + m.slice(54, 87);
    const composite = checkDigit(line2.slice(0, 10) + line2.slice(13, 20) + line2.slice(21, 43));
    return m.slice(0, 44) + line2 + composite;
  })();

  const otherAa = makePassport({ pki, mrz, seed: deriveBytes(seed, 'variant/other-aa', 32) });
  const bpKey = ecKeyFromSeed(seed, 'variant/brainpool-ds', 'brainpoolP256r1');
  const bpDs = { cert: reissue(pki.ds.cert, { signer: pki.csca.key, key: bpKey }), key: bpKey };
  const dsKey = pki.ds.key;

  const variants: Variants = {
    badSodSignature: v(
      'badSodSignature',
      assemble({ ...base, sod: { tweakSignature: flipLastByte } }),
      'SOD_SIGNATURE_INVALID',
      'One bit of the SOD signature flipped.',
    ),
    wrongCsca: {
      ...v(
        'wrongCsca',
        assemble({ ...base, ds: forgedDs }),
        'DS_NOT_CHAINED',
        'The DS certificate is signed by a rogue CSCA with the same name; every certificate field is unchanged.',
      ),
      rogueCsca: rogue.cert,
    },
    changedDg1: v(
      'changedDg1',
      {
        ...good,
        mrz: markedMrz({ ...mrz, documentNumber: otherDocNumber }),
        dg1: assemble({ ...base, mrz: markedMrz({ ...mrz, documentNumber: otherDocNumber }) }).dg1,
      },
      'DG1_HASH_MISMATCH',
      'DG1 replaced after signing by an MRZ with another document number and valid check digits.',
    ),
    expiredDocument: v(
      'expiredDocument',
      assemble({ ...base, mrz: markedMrz({ ...mrz, dateOfExpiry: pastExpiry }) }),
      'DOCUMENT_EXPIRED',
      'Correctly signed, with a date of expiry between 2020 and 2025.',
    ),
    expiredDsCert: v(
      'expiredDsCert',
      assemble({
        ...base,
        ds: {
          cert: reissue(pki.ds.cert, {
            signer: pki.csca.key,
            notBefore: dateFromSeed(seed, 'variant/old-ds', new Date('2013-01-01T00:00:00Z'), 365),
          }),
          key: dsKey,
        },
      }),
      'DS_EXPIRED',
      'The DS certificate (and its private key usage period) moved to 2013 to 2014, so its validity ended in 2024 to 2025.',
    ),
    brainpoolDs: v(
      'brainpoolDs',
      assemble({ ...base, ds: bpDs }),
      'PASS (brainpoolP256r1 needs the noble fallback; WebCrypto has no brainpool)',
      'The DS key is on brainpoolP256r1, as in many real passports.',
    ),
    singleHash: v(
      'singleHash',
      assemble({ ...base, hashed: [1] }),
      'LDS_TOO_FEW_HASHES',
      'The LDSSecurityObject hashes only DG1 (Part 10 requires 2 to 16); DG14 and DG15 are present but unhashed.',
    ),
    messageDigestMismatch: v(
      'messageDigestMismatch',
      assemble({ ...base, sod: { messageDigest: deriveBytes(seed, 'variant/digest', 32) } }),
      'SOD_DIGEST_MISMATCH',
      'The signed messageDigest attribute is not the hash of the eContent; the signature over the attributes is valid.',
    ),
    wrongContentType: v(
      'wrongContentType',
      assemble({ ...base, sod: { eContentType: '1.2.840.113549.1.7.1' } }),
      'SOD_CONTENT_TYPE',
      'eContentType and the contentType attribute are id-data, not id-icao-mrtd-security-ldsSecurityObject.',
    ),
    noDsCertificate: v(
      'noDsCertificate',
      assemble({ ...base, sod: { includeCertificate: false } }),
      'DS_CERT_MISSING',
      'SignedData without the DS certificate (Part 10 Table 37 requires it).',
    ),
    dsKeyUsage: v(
      'dsKeyUsage',
      assemble({
        ...base,
        ds: { cert: reissue(pki.ds.cert, { signer: pki.csca.key, keyUsage: KeyUsageFlags.keyCertSign }), key: dsKey },
      }),
      'DS_KEY_USAGE',
      'The DS certificate has keyCertSign instead of digitalSignature (Part 12 Table 6).',
    ),
    changedDg15: v(
      'changedDg15',
      { ...good, ...(otherAa.dg15 && { dg15: otherAa.dg15 }), ...(otherAa.aaKey && { aaKey: otherAa.aaKey }) },
      'DG15_HASH_MISMATCH',
      'DG15 and the chip key swapped for another Active Authentication key after signing (a cloned chip).',
    ),
    badCheckDigit: v(
      'badCheckDigit',
      assemble({ ...base, mrz: wrongCd }),
      'MRZ_CHECK_DIGIT',
      'Correctly signed, but the document number check digit is wrong.',
    ),
  };
  if (dsKey.kind === 'ec') {
    const n = p256.Point.CURVE().n;
    const highS = (der: Uint8Array) => {
      const s = p256.Signature.fromBytes(der, 'der');
      return new p256.Signature(s.r, n - s.s).toBytes('der');
    };
    variants.highS = v(
      'highS',
      assemble({ ...base, sod: { tweakSignature: highS } }),
      'PASS (ECDSA has no low-S rule; verify with lowS: false)',
      'The SOD signature with s replaced by n - s, which is just as valid.',
    );
  }
  return variants;
}
