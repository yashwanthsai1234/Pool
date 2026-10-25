// Break-it 5.7: RFC 3161 token forgery against services/evidence verifyTimestampToken (ISSUES.md "From task 3.8" items 1, 2).
// Source: https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2 (the TSA's signature over TSTInfo is what makes the token)
// Source: https://github.com/PeculiarVentures/PKI.js/blob/master/src/SignedData.ts (verify: extendedMode returns
//         { signatureVerified } instead of throwing)
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
// pkijs and asn1js resolve through the evidence package, so `instanceof` checks see the same classes as tsa.ts.
import type * as AsnT from '../../../services/evidence/node_modules/asn1js/build/index.d.ts';
// @ts-expect-error TS7016: the deep path has no declaration next to it; the type comes from index.d.ts below
import * as asn1jsJs from '../../../services/evidence/node_modules/asn1js/build/index.es.js';
import type * as PkiT from '../../../services/evidence/node_modules/pkijs/build/index.d.ts';
// @ts-expect-error TS7016: as above
import * as pkijsJs from '../../../services/evidence/node_modules/pkijs/build/index.es.js';
import {
  DIGICERT,
  nodeRootCertificates,
  tokenFromResponse,
  verifyTimestampToken,
} from '../../../services/evidence/src/tsa.ts';
import { recorded } from '../../../services/evidence/test/helpers/tsaReplay.ts';

const asn1js = asn1jsJs as typeof AsnT;
const pkijs = pkijsJs as typeof PkiT;
const sha256 = (b: Uint8Array) => new Uint8Array(createHash('sha256').update(b).digest());
const ab = (b: Uint8Array) => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
const roots = nodeRootCertificates();
const realToken = () => tokenFromResponse(recorded(DIGICERT).resp) as Uint8Array;

function parse(token: Uint8Array) {
  const ci = new pkijs.ContentInfo({ schema: asn1js.fromBER(ab(token)).result });
  const sd = new pkijs.SignedData({ schema: ci.content });
  const tst = new pkijs.TSTInfo({
    schema: asn1js.fromBER((sd.encapContentInfo.eContent as AsnT.OctetString).getValue()).result,
  });
  return { sd, tst };
}
const serialize = (sd: PkiT.SignedData) =>
  new Uint8Array(
    new pkijs.ContentInfo({ contentType: pkijs.ContentInfo.SIGNED_DATA, content: sd.toSchema(true) })
      .toSchema()
      .toBER(),
  );

describe('I-S-E1 forged DigiCert timestamp: the CMS signature result is ignored', () => {
  it('a DigiCert token re-pointed at any attacker hash (messageDigest recomputed, signature stale) is refused', async () => {
    const { sd, tst } = parse(realToken());
    const attackerHash = sha256(new TextEncoder().encode('backdated evidence the attacker chose'));
    tst.messageImprint.hashedMessage = new asn1js.OctetString({ valueHex: ab(attackerHash) });
    const eContent = new Uint8Array(tst.toSchema().toBER());
    sd.encapContentInfo.eContent = new asn1js.OctetString({ valueHex: ab(eContent) });
    // Recompute the signed messageDigest attribute so only the TSA's signature (over the attributes) is now wrong.
    const attrs = (sd.signerInfos[0] as PkiT.SignerInfo).signedAttrs as PkiT.SignedAndUnsignedAttributes;
    const md = attrs.attributes.find((a: PkiT.Attribute) => a.type === '1.2.840.113549.1.9.4') as PkiT.Attribute;
    md.values = [new asn1js.OctetString({ valueHex: ab(sha256(eContent)) })];
    const r = await verifyTimestampToken(serialize(sd), attackerHash, roots);
    expect(r.ok).toBe(false);
  });

  it('a token whose signature value has one flipped byte is refused', async () => {
    const { sd } = parse(realToken());
    const si = sd.signerInfos[0] as PkiT.SignerInfo;
    const sig = new Uint8Array(si.signature.valueBlock.valueHexView).slice();
    sig[10] = (sig[10] as number) ^ 0x01;
    si.signature = new asn1js.OctetString({ valueHex: ab(sig) });
    const fixtureHash = sha256(new TextEncoder().encode('legx evidence service TSA fixture v1'));
    const r = await verifyTimestampToken(serialize(sd), fixtureHash, roots);
    expect(r.ok).toBe(false);
  });
});

describe('ISSUES 3.8 item 2: the certificate chain still binds the signer key to a trusted root', () => {
  it('a copied DigiCert signer certificate carrying the attacker key, with a valid attacker signature, is refused', async () => {
    const { sd } = parse(realToken());
    const si = sd.signerInfos[0] as PkiT.SignerInfo;
    const sid = si.sid as PkiT.IssuerAndSerialNumber;
    const certs = (sd.certificates ?? []) as PkiT.Certificate[];
    const signer = certs.find((c) => c.serialNumber.isEqual(sid.serialNumber)) as PkiT.Certificate;
    const alg = {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    };
    const keys = (await crypto.subtle.generateKey(alg, true, ['sign', 'verify'])) as {
      publicKey: CryptoKey;
      privateKey: CryptoKey;
    };
    await signer.subjectPublicKeyInfo.importKey(keys.publicKey);
    signer.tbsView = new Uint8Array(signer.encodeTBS().toBER()); // pkijs serializes the cached TBS otherwise
    // The certificate's own signature (by the DigiCert intermediate) is now stale; the CMS signature is genuinely valid.
    si.signedAttrs = undefined;
    await sd.sign(keys.privateKey, 0, 'SHA-256');
    const fixtureHash = sha256(new TextEncoder().encode('legx evidence service TSA fixture v1'));
    const r = await verifyTimestampToken(serialize(sd), fixtureHash, roots);
    expect(r).toEqual({ ok: false, code: 'CHAIN_UNTRUSTED' });
  });
});
