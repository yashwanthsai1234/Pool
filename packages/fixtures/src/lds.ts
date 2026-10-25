// The LDSSecurityObject schema (ICAO 9303 Part 10, 4.6.2.3). No @peculiar/asn1-* package ships it, so it is written
// here. The @peculiar/asn1-schema decorators are called as plain functions (AsnProp(opts)(prototype, key)), which
// registers the same schema without decorator syntax, so the erasableSyntaxOnly rule holds.
// Compared with @li0ard/tsemrtd's LDSObject (dist/asn1/sod.js), which omits the optional ldsVersionInfo.
// Source: https://www.icao.int/sites/default/files/publications/DocSeries/9303_p10_cons_en.pdf (4.6.2.3)
import { AsnConvert, AsnProp, AsnPropTypes, OctetString } from '@peculiar/asn1-schema';
import { AlgorithmIdentifier } from '@peculiar/asn1-x509';

class DataGroupHash {
  dataGroupNumber = 0;
  dataGroupHashValue = new OctetString();
}
AsnProp({ type: AsnPropTypes.Integer })(DataGroupHash.prototype, 'dataGroupNumber');
AsnProp({ type: OctetString })(DataGroupHash.prototype, 'dataGroupHashValue');

class LdsVersionInfo {
  ldsVersion = '';
  unicodeVersion = '';
}
AsnProp({ type: AsnPropTypes.PrintableString })(LdsVersionInfo.prototype, 'ldsVersion');
AsnProp({ type: AsnPropTypes.PrintableString })(LdsVersionInfo.prototype, 'unicodeVersion');

class LdsSecurityObject {
  version = 0;
  hashAlgorithm = new AlgorithmIdentifier();
  dataGroupHashValues: DataGroupHash[] = [];
  ldsVersionInfo?: LdsVersionInfo;
}
AsnProp({ type: AsnPropTypes.Integer })(LdsSecurityObject.prototype, 'version');
AsnProp({ type: AlgorithmIdentifier })(LdsSecurityObject.prototype, 'hashAlgorithm');
AsnProp({ type: DataGroupHash, repeated: 'sequence' })(LdsSecurityObject.prototype, 'dataGroupHashValues');
AsnProp({ type: LdsVersionInfo, optional: true })(LdsSecurityObject.prototype, 'ldsVersionInfo');

export const ID_LDS_SECURITY_OBJECT = '2.23.136.1.1.1';
export const ID_SHA256 = '2.16.840.1.101.3.4.2.1';
const HASH_LENGTHS: Record<string, number> = {
  '1.3.14.3.2.26': 20,
  '2.16.840.1.101.3.4.2.4': 28,
  [ID_SHA256]: 32,
  '2.16.840.1.101.3.4.2.2': 48,
  '2.16.840.1.101.3.4.2.3': 64,
};

export interface Lds {
  version: number;
  hashAlgorithm: string;
  hashes: readonly { dg: number; hash: Uint8Array }[];
  ldsVersion?: { lds: string; unicode: string };
}

/** DER of an LDSSecurityObject. Digest AlgorithmIdentifiers omit NULL parameters (Part 10 4.6.2.3 Note 2). */
export function encodeLds(l: Lds): Uint8Array {
  const o = new LdsSecurityObject();
  o.version = l.version;
  o.hashAlgorithm = new AlgorithmIdentifier({ algorithm: l.hashAlgorithm });
  o.dataGroupHashValues = l.hashes.map(({ dg, hash }) =>
    Object.assign(new DataGroupHash(), { dataGroupNumber: dg, dataGroupHashValue: new OctetString(hash) }),
  );
  if (l.ldsVersion) {
    o.ldsVersionInfo = Object.assign(new LdsVersionInfo(), {
      ldsVersion: l.ldsVersion.lds,
      unicodeVersion: l.ldsVersion.unicode,
    });
  }
  return new Uint8Array(AsnConvert.serialize(o));
}

/** Parses and checks an LDSSecurityObject; throws with a reason (the caller turns it into an error result). */
export function decodeLds(der: Uint8Array): Lds {
  const o = AsnConvert.parse(der, LdsSecurityObject);
  const n = o.dataGroupHashValues.length;
  if (n < 2 || n > 16) throw new Error(`LDS: dataGroupHashValues must hold 2 to 16 entries, found ${n}`);
  if (o.version !== (o.ldsVersionInfo ? 1 : 0))
    throw new Error('LDS: version must be v1 exactly when ldsVersionInfo is present');
  const len = HASH_LENGTHS[o.hashAlgorithm.algorithm];
  if (!len) throw new Error(`LDS: unknown hash algorithm ${o.hashAlgorithm.algorithm}`);
  const hashes = o.dataGroupHashValues.map((h) => ({
    dg: h.dataGroupNumber,
    hash: new Uint8Array(h.dataGroupHashValue.buffer),
  }));
  for (const [i, h] of hashes.entries()) {
    if (!Number.isInteger(h.dg) || h.dg < 1 || h.dg > 16)
      throw new Error(`LDS: data group number ${h.dg} out of 1..16`);
    if (hashes.findIndex((x) => x.dg === h.dg) !== i) throw new Error(`LDS: data group ${h.dg} hashed twice`);
    if (h.hash.length !== len) throw new Error(`LDS: hash of data group ${h.dg} has the wrong length`);
  }
  const v = o.ldsVersionInfo;
  return {
    version: o.version,
    hashAlgorithm: o.hashAlgorithm.algorithm,
    hashes,
    ...(v ? { ldsVersion: { lds: v.ldsVersion, unicode: v.unicodeVersion } } : {}),
  };
}
