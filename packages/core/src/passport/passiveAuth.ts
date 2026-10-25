// Passive authentication (ICAO 9303 Part 11, 5.1) and the nfc-chip checks the client's own lawyer signs (DESIGN 6.15).
// Runs in the lawyer's console when the chip is read; the release gate never imports it (invariant I7). Every time is
// the validated ledger close_time passed in by the caller, never the local clock.
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { passportCommitment } from '../dealcore.ts';
import { aaChallenge, verifyActiveAuth } from './activeAuth.ts';
import {
  HASH_BY_OID,
  ID_LDS_SECURITY_OBJECT,
  parseLds,
  parseSod,
  type SigCheck,
  signedAttr,
  unwrapTag,
  verifySignature,
} from './sod.ts';

const RIPPLE_EPOCH = 946_684_800; // 2000-01-01T00:00:00Z in Unix seconds

export type DgHashCode = `DG${number}_HASH_MISMATCH`;
export type PassiveAuthCode =
  | 'SOD_MALFORMED'
  | 'SOD_CONTENT_TYPE'
  | 'DS_CERT_MISSING'
  | 'SOD_ALGORITHM_UNSUPPORTED'
  | 'SOD_DIGEST_MISMATCH'
  | 'SOD_SIGNATURE_INVALID'
  | 'DS_NOT_CHAINED'
  | 'CSCA_EXPIRED'
  | 'DS_KEY_USAGE'
  | 'DS_EXPIRED'
  | 'LDS_MALFORMED'
  | 'LDS_TOO_FEW_HASHES'
  | DgHashCode
  | 'DG1_MALFORMED'
  | 'MRZ_CHECK_DIGIT'
  | 'DOCUMENT_EXPIRED';

export interface PassiveAuthInput {
  /** EF.DG1 exactly as read from the chip. */
  readonly dg1: Uint8Array;
  /** EF.SOD exactly as read from the chip. */
  readonly sod: Uint8Array;
  /** EF.DG14 and EF.DG15 when read; each must be listed in the SOD with a matching hash. */
  readonly dg14?: Uint8Array | undefined;
  readonly dg15?: Uint8Array | undefined;
  /** Trusted CSCA certificates (DER), from the ICAO PKD or a country master list (DESIGN O10). */
  readonly trustList: readonly Uint8Array[];
  /** The validated ledger close_time, Ripple epoch seconds. */
  readonly atTime: number;
}

export type PassiveAuthResult =
  | {
      readonly ok: true;
      /** The data groups the SOD lists, ascending: the chip's file set, authenticated by the issuer. */
      readonly listed: readonly number[];
      readonly dateOfExpiry: string;
    }
  | { readonly ok: false; readonly code: PassiveAuthCode };

const fail = <C extends string>(code: C) => ({ ok: false, code }) as const;
const bytes = (b: ArrayBuffer | Uint8Array) => (b instanceof Uint8Array ? b : new Uint8Array(b));
const equalBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * Passive authentication, in the order of Part 11 5.1.1 with each failure named:
 * parse EF.SOD (step 1); check the signed content type and messageDigest, then the SOD signature with the DS key
 * (step 3); chain the DS certificate to a trusted CSCA and check both at the ledger time (step 2, Part 12); check the
 * DS key usage (best practice 1); hash DG1 and the other data groups read against the SOD (step 5); and check the MRZ
 * check digits and date of expiry. The SOD signature is checked before the chain, so a sample SOD without its CSCA
 * still has its signature checked.
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p11_cons_en.pdf (5.1.1)
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p12_cons_en.pdf (certificate profiles, Table 6)
 * Source: https://www.rfc-editor.org/rfc/rfc5652#section-5.6 (signature verification process)
 * Source: https://github.com/PeculiarVentures/PKI.js/blob/v3.4.3/src/SignedAndUnsignedAttributes.ts (encodedValue is re-tagged 0x31, the SET OF the signature covers)
 */
export async function passiveAuth(i: PassiveAuthInput): Promise<PassiveAuthResult> {
  const at = new Date((i.atTime + RIPPLE_EPOCH) * 1000);
  const sod = parseSod(i.sod);
  if (!sod) return fail('SOD_MALFORMED');
  const { signerInfo: si, dsCert } = sod;

  const ct = signedAttr(si, '1.2.840.113549.1.9.3');
  const ctOid = ct instanceof asn1js.ObjectIdentifier ? ct.valueBlock.toString() : undefined;
  if (sod.eContentType !== ID_LDS_SECURITY_OBJECT || ctOid !== ID_LDS_SECURITY_OBJECT) return fail('SOD_CONTENT_TYPE');
  if (!dsCert) return fail('DS_CERT_MISSING');

  const digestAlg = HASH_BY_OID[si.digestAlgorithm.algorithmId];
  const md = signedAttr(si, '1.2.840.113549.1.9.4');
  if (!digestAlg || !si.signedAttrs) return fail('SOD_ALGORITHM_UNSUPPORTED');
  if (!(md instanceof asn1js.OctetString) || !equalBytes(md.valueBlock.valueHexView, digestAlg(sod.eContent))) {
    return fail('SOD_DIGEST_MISMATCH');
  }
  const cmsHash = (pkijs.getCrypto(true).getAlgorithmByOID(si.digestAlgorithm.algorithmId) as { name?: string }).name;
  const sig = await verifySignature(
    bytes(si.signedAttrs.encodedValue),
    si.signature.valueBlock.valueHexView,
    dsCert.subjectPublicKeyInfo,
    si.signatureAlgorithm,
    cmsHash,
  );
  if (sig === 'unsupported') return fail('SOD_ALGORITHM_UNSUPPORTED');
  if (sig === 'invalid') return fail('SOD_SIGNATURE_INVALID');

  const csca = await issuingCsca(dsCert, i.trustList, at);
  if (!csca) return fail('DS_NOT_CHAINED');
  if (!keyUsage(dsCert, 0)) return fail('DS_KEY_USAGE');
  if (!validAt(dsCert, at)) return fail('DS_EXPIRED');
  if (!validAt(csca, at)) return fail('CSCA_EXPIRED');

  const lds = parseLds(sod.eContent);
  if (lds === 'few') return fail('LDS_TOO_FEW_HASHES');
  if (!lds) return fail('LDS_MALFORMED');
  for (const [n, file] of [[1, i.dg1] as const, [14, i.dg14] as const, [15, i.dg15] as const]) {
    if (file === undefined) continue;
    const listed = lds.hashes.get(n);
    if (!listed || !equalBytes(listed, lds.hash(file))) return fail(`DG${n}_HASH_MISMATCH` as DgHashCode);
  }

  const mrz = mrzOf(i.dg1);
  if (!mrz) return fail('DG1_MALFORMED');
  if (!checkDigitsHold(mrz)) return fail('MRZ_CHECK_DIGIT');
  const dateOfExpiry = mrz.slice(65, 71);
  const end = endOfExpiryDay(dateOfExpiry);
  if (end === undefined) return fail('DG1_MALFORMED');
  if (at.getTime() >= end) return fail('DOCUMENT_EXPIRED');
  return { ok: true, listed: [...lds.hashes.keys()].sort((a, b) => a - b), dateOfExpiry };
}

const validAt = (c: pkijs.Certificate, at: Date) =>
  c.notBefore.value.getTime() <= at.getTime() && at.getTime() <= c.notAfter.value.getTime();

/** RFC 5280 4.2.1.3 keyUsage bit (0 = digitalSignature, 5 = keyCertSign); false if the extension is absent. */
function keyUsage(c: pkijs.Certificate, bit: number): boolean {
  const ext = c.extensions?.find((e) => e.extnID === '2.5.29.15')?.parsedValue;
  if (!(ext instanceof asn1js.BitString)) return false;
  return (((ext.valueBlock.valueHexView[bit >> 3] ?? 0) >> (7 - (bit & 7))) & 1) === 1;
}

const isCa = (c: pkijs.Certificate) =>
  (c.extensions?.find((e) => e.extnID === '2.5.29.19')?.parsedValue as pkijs.BasicConstraints | undefined)?.cA === true;

/**
 * The trusted CSCA that issued the DS certificate: a trust-list certificate with the DS issuer's name, a CA with
 * keyCertSign, whose key verifies the DS certificate's signature. With several (a key rollover under one name), one
 * valid at the ledger time is preferred; the caller checks validity.
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p12_cons_en.pdf (5, 7.1, Table 6)
 * Source: https://www.rfc-editor.org/rfc/rfc5280#section-6.1.3 (basic certificate processing)
 */
async function issuingCsca(
  ds: pkijs.Certificate,
  trustList: readonly Uint8Array[],
  at: Date,
): Promise<pkijs.Certificate | undefined> {
  if (ds.signature.algorithmId !== ds.signatureAlgorithm.algorithmId) return undefined; // RFC 5280 4.1.1.2
  let found: pkijs.Certificate | undefined;
  for (const der of trustList) {
    let csca: pkijs.Certificate;
    try {
      csca = pkijs.Certificate.fromBER(new Uint8Array(der)); // an ArrayBuffer-backed copy: DOM BufferSource (I-30)
    } catch {
      continue;
    }
    if (!csca.subject.isEqual(ds.issuer) || !isCa(csca) || !keyUsage(csca, 5)) continue;
    const r: SigCheck = await verifySignature(
      ds.tbsView,
      ds.signatureValue.valueBlock.valueHexView,
      csca.subjectPublicKeyInfo,
      ds.signatureAlgorithm,
    );
    if (r !== 'valid') continue;
    if (validAt(csca, at)) return csca;
    found = csca;
  }
  return found;
}

// ---------- DG1: the TD3 MRZ (ICAO 9303 Part 4, Part 10 4.7.1) ----------

/** The 88-character TD3 MRZ from DG1 = 61 L (5F1F L MRZ), or undefined. Passports are TD3 only. */
function mrzOf(dg1: Uint8Array): string | undefined {
  const outer = unwrapTag(dg1, [0x61]);
  const inner = outer && unwrapTag(outer, [0x5f, 0x1f]);
  if (inner?.length !== 88) return undefined;
  const text = String.fromCharCode(...inner);
  return /^P[A-Z<][A-Z<]{3}[A-Z<]{39}[0-9A-Z<]{44}$/.test(text) ? text : undefined;
}

/** Part 3 4.9: weights 7, 3, 1; A to Z count 10 to 35, '<' counts 0. */
function checkDigit(s: string): string {
  let sum = 0;
  for (let k = 0; k < s.length; k++) {
    const c = s.charCodeAt(k);
    const v = c === 60 ? 0 : c <= 57 ? c - 48 : c - 55;
    sum += v * ([7, 3, 1][k % 3] ?? 0);
  }
  return String(sum % 10);
}

/**
 * The TD3 check digits: document number, date of birth, date of expiry, personal number (may be '<' when the field is
 * all fillers), and the composite over positions 1 to 10, 14 to 20 and 22 to 43 of line 2.
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p4_cons_en.pdf (4.2.2.2, Appendix A)
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p3_cons_en.pdf (4.9)
 */
function checkDigitsHold(mrz: string): boolean {
  const l2 = mrz.slice(44);
  const pn = l2.slice(28, 42);
  const pnOk = l2[42] === checkDigit(pn) || (pn === '<'.repeat(14) && l2[42] === '<');
  return (
    l2[9] === checkDigit(l2.slice(0, 9)) &&
    l2[19] === checkDigit(l2.slice(13, 19)) &&
    l2[27] === checkDigit(l2.slice(21, 27)) &&
    pnOk &&
    l2[43] === checkDigit(l2.slice(0, 10) + l2.slice(13, 20) + l2.slice(21, 43))
  );
}

/**
 * The first instant after the date of expiry (YYMMDD, read as 20YY: eMRTDs exist only since 2004), in Unix ms; the
 * document is valid through its expiry date. Undefined for an impossible date.
 */
function endOfExpiryDay(yymmdd: string): number | undefined {
  if (!/^[0-9]{6}$/.test(yymmdd)) return undefined;
  const [y, m, d] = [2000 + Number(yymmdd.slice(0, 2)), Number(yymmdd.slice(2, 4)), Number(yymmdd.slice(4, 6))];
  const day = new Date(Date.UTC(y, m - 1, d));
  if (day.getUTCFullYear() !== y || day.getUTCMonth() !== m - 1 || day.getUTCDate() !== d) return undefined;
  return day.getTime() + 86_400_000;
}

// ---------- the nfc-chip attestation checks (DESIGN 6.15) ----------

/** passportRecord = LP(DG1) || LP(EF.SOD), each exactly as read (DESIGN 6.2). */
export function passportRecord(dg1: Uint8Array, sod: Uint8Array): Uint8Array {
  const out = new Uint8Array(8 + dg1.length + sod.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, dg1.length);
  out.set(dg1, 4);
  view.setUint32(4 + dg1.length, sod.length);
  out.set(sod, 8 + dg1.length);
  return out;
}

/** The `checks` object of an nfc-chip attestation, as the lawyer signs it (contracts `PassportAttestation`). */
export interface ChipChecks {
  readonly sod_signature_valid: true;
  readonly ds_cert_chains_to_csca: true;
  readonly dg1_hash_in_sod: true;
  readonly document_not_expired: true;
  readonly commitment_opens: true;
  readonly chip_authentication: 'AA' | 'CA' | 'none';
  /** The SOD lists DG14 or DG15, so the verifier refuses "none" (OD-22). */
  readonly chip_auth_available: boolean;
}

export interface ChipCheckInput extends PassiveAuthInput {
  /** The client's 32-byte commitment salt and the sealed C_side (DESIGN 6.2). */
  readonly salt: Uint8Array;
  readonly commitment: Uint8Array;
  /** presenceMsg for this check (attest.ts); its first 8 bytes were sent to the chip as RND.IFD. */
  readonly presenceMsg: Uint8Array;
  /** The chip's INTERNAL AUTHENTICATE answer to aaChallenge(presenceMsg). */
  readonly aaSignature?: Uint8Array | undefined;
  /** Chip Authentication completed by the native reader (task 4.6). Its binding to presenceMsg is DESIGN [CHECK]. */
  readonly caPassed?: boolean | undefined;
}

export type ChipCheckCode =
  | PassiveAuthCode
  | 'COMMITMENT_MISMATCH'
  | 'DG15_MISSING'
  | 'CHIP_AUTH_REQUIRED'
  | 'CHIP_AUTH_INVALID'
  | 'DG15_MALFORMED'
  | 'DG14_AA_INFO_MISSING'
  | 'AA_ALGORITHM_UNSUPPORTED';
export type ChipCheckResult =
  | { readonly ok: true; readonly checks: ChipChecks }
  | { readonly ok: false; readonly code: ChipCheckCode };

/**
 * Everything the lawyer's console must establish before it signs an nfc-chip attestation: passive authentication, the
 * commitment opening, and chip authentication when the chip supports it. The chip "has" DG15 or DG14 when the SOD
 * lists it (the SOD is signed; EF.COM is not). Active Authentication is preferred, because its challenge comes from
 * presenceMsg; an AA answer that is given must verify even if Chip Authentication also passed.
 * Source: DESIGN.md 6.15 ("Chip authentication when the chip supports it")
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p11_cons_en.pdf (6.1, 6.2)
 * Source: https://blog.protocolbench.org/2014/04/update-tr-03105-part-3-2-available/ (use EF.SOD, not EF.COM, to see which files exist)
 */
export async function chipChecks(i: ChipCheckInput): Promise<ChipCheckResult> {
  const pa = await passiveAuth(i);
  if (!pa.ok) return pa;
  let opens = false;
  try {
    opens =
      i.commitment.length === 32 && equalBytes(passportCommitment(passportRecord(i.dg1, i.sod), i.salt), i.commitment);
  } catch {
    opens = false; // a salt that is not 32 bytes
  }
  if (!opens) return fail('COMMITMENT_MISMATCH');

  const hasAa = pa.listed.includes(15);
  const hasCa = pa.listed.includes(14);
  let chipAuth: ChipChecks['chip_authentication'] = 'none';
  if (i.aaSignature !== undefined) {
    if (!i.dg15) return fail('DG15_MISSING'); // a DG15 that was given is listed in the SOD: passiveAuth checked its hash
    const aa = verifyActiveAuth({
      dg15: i.dg15,
      dg14: i.dg14,
      challenge: aaChallenge(i.presenceMsg),
      signature: i.aaSignature,
    });
    if (!aa.ok) return fail(aa.code === 'CHALLENGE_LENGTH' ? 'CHIP_AUTH_INVALID' : aa.code);
    chipAuth = 'AA';
  } else if (hasCa && i.caPassed === true) {
    chipAuth = 'CA';
  } else if (hasAa || hasCa) {
    return fail('CHIP_AUTH_REQUIRED');
  }
  return {
    ok: true,
    checks: {
      sod_signature_valid: true,
      ds_cert_chains_to_csca: true,
      dg1_hash_in_sod: true,
      document_not_expired: true,
      commitment_opens: true,
      chip_authentication: chipAuth,
      chip_auth_available: hasAa || hasCa,
    },
  };
}
