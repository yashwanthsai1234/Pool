// A local RFC 3161 authority for tests: its own root and TSA certificate (ECDSA P-256, time-stamping EKU), and a
// handler that answers `TimeStampReq` bytes with `TimeStampResp` bytes, so the real client code runs end to end.
// Real authorities are covered by the recorded exchanges in test/fixtures/tsa.
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { type Authority, tsaClient } from '../../src/tsa.ts';

const subject = (cn: string) =>
  new pkijs.RelativeDistinguishedNames({
    typesAndValues: [new pkijs.AttributeTypeAndValue({ type: '2.5.4.3', value: new asn1js.Utf8String({ value: cn }) })],
  });
const ab = (b: Uint8Array) => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;

async function makeCert(
  cn: string,
  issuer: { cert: pkijs.Certificate; key: CryptoKey } | undefined,
  eku: string | undefined,
  serial: number,
) {
  const alg = { name: 'ECDSA', namedCurve: 'P-256' };
  const keys = await crypto.subtle.generateKey(alg, true, ['sign', 'verify']);
  const cert = new pkijs.Certificate({
    version: 2,
    serialNumber: new asn1js.Integer({ value: serial }),
    subject: subject(cn),
    issuer: issuer ? issuer.cert.subject : subject(cn),
    notBefore: new pkijs.Time({ type: 0, value: new Date(Date.now() - 86_400_000) }),
    notAfter: new pkijs.Time({ type: 0, value: new Date(Date.now() + 10 * 365 * 86_400_000) }),
    extensions: [
      ...(eku
        ? [
            new pkijs.Extension({
              extnID: '2.5.29.37',
              critical: true,
              extnValue: new pkijs.ExtKeyUsage({ keyPurposes: [eku] }).toSchema().toBER(),
            }),
          ]
        : [
            new pkijs.Extension({
              extnID: '2.5.29.19',
              critical: true,
              extnValue: new pkijs.BasicConstraints({ cA: true }).toSchema().toBER(),
            }),
          ]),
    ],
  });
  await cert.subjectPublicKeyInfo.importKey(keys.publicKey);
  await cert.sign(issuer?.key ?? keys.privateKey, 'SHA-256');
  return { cert, key: keys.privateKey };
}

export interface LocalTsa {
  readonly name: string;
  readonly rootDer: Uint8Array;
  /** Every request seen, with the wall-clock time it arrived. */
  readonly requests: { at: number }[];
  /** Behaviour switches: a delay before answering, an HTTP status instead of an answer. */
  behave: { delayMs?: number; status?: number; wrongEku?: boolean };
  fetch: typeof fetch;
  client(opts?: { minIntervalMs?: number; trustedRoots?: readonly Uint8Array[] }): ReturnType<typeof tsaClient>;
}

export async function makeLocalTsa(name: string): Promise<LocalTsa> {
  const root = await makeCert(`${name} test root`, undefined, undefined, 1);
  const good = await makeCert(`${name} test TSA`, root, '1.3.6.1.5.5.7.3.8', 2);
  const wrong = await makeCert(`${name} test TSA (no EKU)`, root, '1.3.6.1.5.5.7.3.3', 3);
  const requests: { at: number }[] = [];
  let serial = 1000;
  const behave: LocalTsa['behave'] = {};

  async function answer(req: Uint8Array): Promise<Uint8Array> {
    const asn = asn1js.fromBER(ab(req));
    const r = new pkijs.TimeStampReq({ schema: asn.result });
    const signer = behave.wrongEku ? wrong : good;
    const tst = new pkijs.TSTInfo({
      version: 1,
      policy: '1.2.3.4.5',
      messageImprint: r.messageImprint,
      serialNumber: new asn1js.Integer({ value: serial++ }),
      genTime: new Date(),
      ...(r.nonce ? { nonce: r.nonce } : {}),
    });
    const signed = new pkijs.SignedData({
      version: 3,
      encapContentInfo: new pkijs.EncapsulatedContentInfo({
        eContentType: '1.2.840.113549.1.9.16.1.4',
        eContent: new asn1js.OctetString({ valueHex: tst.toSchema().toBER() }),
      }),
      signerInfos: [
        new pkijs.SignerInfo({
          version: 1,
          sid: new pkijs.IssuerAndSerialNumber({ issuer: signer.cert.issuer, serialNumber: signer.cert.serialNumber }),
        }),
      ],
      certificates: [signer.cert, root.cert],
    });
    await signed.sign(signer.key, 0, 'SHA-256');
    const resp = new pkijs.TimeStampResp({
      status: new pkijs.PKIStatusInfo({ status: 0 }),
      timeStampToken: new pkijs.ContentInfo({
        contentType: pkijs.ContentInfo.SIGNED_DATA,
        content: signed.toSchema(true),
      }),
    });
    return new Uint8Array(resp.toSchema().toBER());
  }

  const fetchImpl = (async (_url: string, init?: RequestInit) => {
    requests.push({ at: Date.now() });
    if (behave.delayMs) await new Promise((r) => setTimeout(r, behave.delayMs));
    if (behave.status) return new Response(null, { status: behave.status });
    return new Response(await answer(new Uint8Array(init?.body as ArrayBuffer)), { status: 200 });
  }) as typeof fetch;

  const rootDer = new Uint8Array(root.cert.toSchema().toBER());
  return {
    name,
    rootDer,
    requests,
    behave,
    fetch: fetchImpl,
    client: (opts = {}) => {
      const authority: Authority = { name, url: `http://tsa.test/${name}`, minIntervalMs: opts.minIntervalMs ?? 0 };
      return tsaClient({ authority, trustedRoots: opts.trustedRoots ?? [rootDer], fetch: fetchImpl });
    },
  };
}
