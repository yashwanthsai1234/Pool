import { ContentInfo, SignedData } from '@peculiar/asn1-cms';
import { AsnConvert } from '@peculiar/asn1-schema';
import { tlv } from './der.ts';
import { decodeLds, type Lds } from './lds.ts';

/** A parse result. The parsers here return errors as values and never throw. */
export type Parsed<T> = { ok: true; value: T } | { ok: false; error: string };

const fail = (error: string): { ok: false; error: string } => ({ ok: false, error });

/**
 * Reads one BER-TLV with the given tag that spans the whole input (no trailing bytes).
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p10_cons_en.pdf (4.4, tag-length-value)
 */
function readTlv(b: Uint8Array, tag: readonly number[]): Parsed<Uint8Array> {
  if (b.length < tag.length + 1 || tag.some((t, i) => b[i] !== t)) return fail('wrong tag');
  let i = tag.length;
  const first = b[i++] ?? 0;
  let len = first;
  if (first > 0x80 && first <= 0x83) {
    len = 0;
    for (let k = 0; k < (first & 0x7f); k++) len = len * 256 + (b[i++] ?? 0);
  } else if (first >= 0x80) return fail('unsupported length encoding');
  if (i + len !== b.length) return fail('length does not match the data');
  return { ok: true, value: b.subarray(i) };
}

/** The 88-character MRZ from a TD3 DG1: `61 5B 5F1F 58 <MRZ>`. */
export function parseDg1(dg1: Uint8Array): Parsed<string> {
  const outer = readTlv(dg1, [0x61]);
  if (!outer.ok) return fail(`DG1: ${outer.error}`);
  const inner = readTlv(outer.value, [0x5f, 0x1f]);
  if (!inner.ok) return fail(`DG1 MRZ: ${inner.error}`);
  const mrz = new TextDecoder().decode(inner.value);
  if (!/^[A-Z0-9<]{88}$/.test(mrz)) return fail('DG1: not a TD3 MRZ');
  return { ok: true, value: mrz };
}

export interface ParsedSod {
  eContentType: string;
  lds: Lds;
  certificates: Uint8Array[];
  signer: { digestAlgorithm: string; signatureAlgorithm: string; signedAttrs: Uint8Array; signature: Uint8Array };
}

/**
 * Parses EF.SOD (tag 77, CMS SignedData, LDSSecurityObject) and checks the ICAO structure rules that do not need
 * keys: SignedData, exactly one SignerInfo with signed attributes, embedded eContent, 2 to 16 DG hashes. It does
 * not verify signatures; that is passive authentication (task 1.9).
 * Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p10_cons_en.pdf (4.6.2)
 */
export function parseSod(sod: Uint8Array): Parsed<ParsedSod> {
  const body = readTlv(sod, [0x77]);
  if (!body.ok) return fail(`EF.SOD: ${body.error}`);
  try {
    const ci = AsnConvert.parse(body.value, ContentInfo);
    if (ci.contentType !== '1.2.840.113549.1.7.2') return fail('EF.SOD: not SignedData');
    const sd = AsnConvert.parse(ci.content, SignedData);
    const [si, ...more] = sd.signerInfos;
    if (!si || more.length > 0) return fail('EF.SOD: expected exactly one SignerInfo');
    const eContent = sd.encapContentInfo.eContent?.single;
    if (!eContent) return fail('EF.SOD: eContent missing');
    if (!si.signedAttrs?.length) return fail('EF.SOD: signedAttrs missing');
    const lds = decodeLds(new Uint8Array(eContent.buffer));
    const certificates = (sd.certificates ?? []).flatMap((c) =>
      c.certificate ? [new Uint8Array(AsnConvert.serialize(c.certificate))] : [],
    );
    const attrs = si.signedAttrs.map((a) => new Uint8Array(AsnConvert.serialize(a)));
    return {
      ok: true,
      value: {
        eContentType: sd.encapContentInfo.eContentType,
        lds,
        certificates,
        signer: {
          digestAlgorithm: si.digestAlgorithm.algorithm,
          signatureAlgorithm: si.signatureAlgorithm.algorithm,
          signedAttrs: tlv([0x31], Uint8Array.from(attrs.flatMap((a) => [...a]))),
          signature: new Uint8Array(si.signature.buffer),
        },
      },
    };
  } catch (e) {
    return fail(e instanceof Error ? e.message : 'EF.SOD: malformed');
  }
}
