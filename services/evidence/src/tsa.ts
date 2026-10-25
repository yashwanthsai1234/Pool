// RFC 3161 time-stamp client (DESIGN 8.4) on PKI.js. We build a `TimeStampReq` for a SHA-256 hash, POST it to an
// authority, and accept the `TimeStampToken` only after checking it: granted status, message imprint, nonce, the CMS
// signature, the certificate chain to a trusted root at `genTime`, and the time-stamping extended key usage.
// Source: https://www.rfc-editor.org/rfc/rfc3161 (sections 2.4 request and response, 2.4.2 TSTInfo, 4 transport:
//   Content-Type application/timestamp-query and application/timestamp-reply)
// Source: https://www.rfc-editor.org/rfc/rfc5652#section-5.4 (SignedData verification, signed attributes)
// Source: https://pkijs.org/docs/classes/TimeStampReq.html and https://pkijs.org/docs/classes/SignedData.html
import type { Hex32 } from '@legx/contracts/values';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

const SHA256_OID = '2.16.840.1.101.3.4.2.1';
const EKU_TIME_STAMPING = '1.3.6.1.5.5.7.3.8';
const EXT_KEY_USAGE = '2.5.29.37';
const PKI_GRANTED = new Set([0, 1]); // granted, grantedWithMods (RFC 3161 2.4.2)

/** An independent free authority. `minIntervalMs` is the least time between two requests we send it. */
export interface Authority {
  readonly name: string;
  readonly url: string;
  readonly minIntervalMs: number;
}

// Free authorities that answered a real request on 24 Oct 2026 (task 3.4 research). DigiCert and SSL.com chain to
// different roots, so they are independent. Sectigo asks for 15 s or more between requests; the others publish no
// limit, so we keep one second. Entrust is signed by Sectigo and is not independent of it.
export const DIGICERT: Authority = { name: 'digicert', url: 'http://timestamp.digicert.com', minIntervalMs: 1000 };
export const SSL_COM: Authority = { name: 'ssl.com', url: 'http://ts.ssl.com', minIntervalMs: 1000 };
export const SECTIGO: Authority = { name: 'sectigo', url: 'http://timestamp.sectigo.com', minIntervalMs: 15_000 };
export const DEFAULT_AUTHORITIES: readonly [Authority, Authority] = [DIGICERT, SSL_COM];

const toAb = (b: Uint8Array): ArrayBuffer => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
const fromAb = (a: ArrayBuffer): Uint8Array => new Uint8Array(a);
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/** The Mozilla root bundle shipped with Node, as DER. The default trust anchors for the public authorities. */
export function nodeRootCertificates(): Uint8Array[] {
  // Loaded lazily by name so the offline verifier bundle holds no static network-module import.
  // Source: https://nodejs.org/api/process.html#processgetbuiltinmoduleid
  const tls = process.getBuiltinModule('node:tls');
  return tls.rootCertificates.map((pem) =>
    Uint8Array.from(Buffer.from(pem.replace(/-----[^-]+-----|\s/g, ''), 'base64')),
  );
}

/** A positive 8-byte nonce (top bit clear, so the DER INTEGER stays positive). */
export const randomNonce = (): Uint8Array => {
  const n = crypto.getRandomValues(new Uint8Array(8));
  n[0] = (n[0] as number) & 0x7f;
  return n;
};

/** DER `TimeStampReq` for a SHA-256 hash (version 1, certReq true so the token carries the TSA chain). */
export function buildTimestampReq(sha256: Uint8Array, nonce: Uint8Array): Uint8Array {
  if (sha256.length !== 32) throw new Error('hash must be 32 bytes');
  const req = new pkijs.TimeStampReq({
    version: 1,
    messageImprint: new pkijs.MessageImprint({
      hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: SHA256_OID, algorithmParams: new asn1js.Null() }),
      hashedMessage: new asn1js.OctetString({ valueHex: toAb(sha256) }),
    }),
    nonce: new asn1js.Integer({ valueHex: toAb(nonce) }),
    certReq: true,
  });
  return fromAb(req.toSchema().toBER());
}

export type TokenCode =
  | 'MALFORMED'
  | 'NOT_GRANTED'
  | 'NOT_SIGNED_DATA'
  | 'NOT_TSTINFO'
  | 'IMPRINT_MISMATCH'
  | 'NONCE_MISMATCH'
  | 'SIGNATURE_INVALID'
  | 'CHAIN_UNTRUSTED'
  | 'NOT_TIME_STAMPING_CERT';
export interface TokenInfo {
  readonly genTime: Date;
  readonly serial: string;
  readonly policy: string;
  readonly signer: string;
  /** Every certificate the token carries, DER, for the evidence bundle. */
  readonly certificates: readonly Uint8Array[];
}
export type TokenResult = ({ readonly ok: true } & TokenInfo) | { readonly ok: false; readonly code: TokenCode };

const parseCms = (token: Uint8Array): pkijs.SignedData | TokenCode => {
  const asn = asn1js.fromBER(toAb(token));
  if (asn.offset === -1) return 'MALFORMED';
  const ci = new pkijs.ContentInfo({ schema: asn.result });
  if (ci.contentType !== pkijs.ContentInfo.SIGNED_DATA) return 'NOT_SIGNED_DATA';
  return new pkijs.SignedData({ schema: ci.content });
};

const tstInfoOf = (sd: pkijs.SignedData): pkijs.TSTInfo | undefined => {
  const content = sd.encapContentInfo.eContent;
  if (sd.encapContentInfo.eContentType !== '1.2.840.113549.1.9.16.1.4' || !content) return undefined;
  const asn = asn1js.fromBER(content.getValue());
  return asn.offset === -1 ? undefined : new pkijs.TSTInfo({ schema: asn.result });
};

const hasTimeStampingEku = (cert: pkijs.Certificate): boolean => {
  const ext = cert.extensions?.find((e) => e.extnID === EXT_KEY_USAGE);
  const parsed = ext?.parsedValue as pkijs.ExtKeyUsage | undefined;
  return parsed?.keyPurposes.includes(EKU_TIME_STAMPING) ?? false;
};

/**
 * Checks a `TimeStampToken` (a CMS ContentInfo) over `sha256`: imprint, optional `nonce`, signature, chain to one of
 * `trustedRoots` evaluated at the token's own `genTime`, and the time-stamping EKU on the signer. Never throws.
 */
export async function verifyTimestampToken(
  token: Uint8Array,
  sha256: Uint8Array,
  trustedRoots: readonly Uint8Array[],
  nonce?: Uint8Array,
): Promise<TokenResult> {
  const fail = (code: TokenCode) => ({ ok: false, code }) as const;
  try {
    const sd = parseCms(token);
    if (typeof sd === 'string') return fail(sd);
    const tst = tstInfoOf(sd);
    if (!tst) return fail('NOT_TSTINFO');
    const imprint = fromAb(tst.messageImprint.hashedMessage.valueBlock.valueHexView.slice().buffer as ArrayBuffer);
    if (tst.messageImprint.hashAlgorithm.algorithmId !== SHA256_OID || !same(imprint, sha256)) {
      return fail('IMPRINT_MISMATCH');
    }
    if (nonce) {
      const got = tst.nonce ? new Uint8Array(tst.nonce.valueBlock.valueHexView) : undefined;
      const trimmed = got && got.length > 1 && got[0] === 0 ? got.subarray(1) : got;
      const want = nonce[0] === 0 ? nonce.subarray(1) : nonce;
      if (!trimmed || !same(trimmed, want)) return fail('NONCE_MISMATCH');
    }
    const certs = sd.certificates?.filter((c): c is pkijs.Certificate => c instanceof pkijs.Certificate) ?? [];
    const signer = findSigner(sd, certs);
    if (!signer) return fail('CHAIN_UNTRUSTED');
    // pkijs checks the TSTInfo imprint against the original data, which we do not hold (we stamp a hash), and tries
    // every certificate in the token as a path candidate. We checked the imprint above, so: signature through the CMS
    // path as plain data, then the chain through the validation engine on the other certificates.
    sd.encapContentInfo.eContentType = pkijs.ContentInfo.DATA;
    // extendedMode reports a bad signature as `signatureVerified: false` instead of throwing, so the result is the
    // verdict (I-S-E1). Source: https://github.com/PeculiarVentures/PKI.js/blob/master/src/SignedData.ts (verify)
    try {
      const sig = await sd.verify({ signer: 0, checkChain: false, extendedMode: true });
      if (sig.signatureVerified !== true) return fail('SIGNATURE_INVALID');
    } catch {
      return fail('SIGNATURE_INVALID');
    }
    const roots = trustedRoots.map((r) => pkijs.Certificate.fromBER(toAb(r)));
    const chain = await new pkijs.CertificateChainValidationEngine({
      certs: pathTo(signer, certs, roots),
      trustedCerts: roots,
      checkDate: tst.genTime,
    }).verify({ passedWhenNotRevValues: true });
    if (!chain.result) return fail('CHAIN_UNTRUSTED');
    if (!hasTimeStampingEku(signer)) return fail('NOT_TIME_STAMPING_CERT');
    return {
      ok: true,
      genTime: tst.genTime,
      serial: bytesToHex(new Uint8Array(tst.serialNumber.valueBlock.valueHexView)),
      policy: tst.policy,
      signer: signer.subject.typesAndValues
        .map((t) => `${t.type}=${(t.value.valueBlock as { value?: string }).value}`)
        .join(','),
      certificates: certs.map((c) => fromAb(c.toSchema().toBER())),
    };
  } catch {
    return fail('MALFORMED');
  }
}

/**
 * The signer's certificate preceded by the token's intermediates that lead to a trusted root. A token often carries a
 * cross-certificate for the root (DigiCert does); following the first trusted issuer we meet drops it, because the
 * validation engine refuses a candidate set that contains certificates outside every path.
 */
function pathTo(signer: pkijs.Certificate, pool: pkijs.Certificate[], roots: pkijs.Certificate[]): pkijs.Certificate[] {
  const path = [signer];
  let current = signer;
  for (let i = 0; i < pool.length; i++) {
    if (roots.some((r) => r.subject.isEqual(current.issuer))) break;
    const next = pool.find((c) => c.subject.isEqual(current.issuer) && !path.includes(c));
    if (!next) break;
    path.unshift(next);
    current = next;
  }
  return path;
}

function findSigner(sd: pkijs.SignedData, certs: pkijs.Certificate[]): pkijs.Certificate | undefined {
  const sid = sd.signerInfos[0]?.sid;
  return certs.find((c) =>
    sid instanceof pkijs.IssuerAndSerialNumber
      ? c.serialNumber.isEqual(sid.serialNumber) && c.issuer.isEqual(sid.issuer)
      : false,
  );
}

/** `TimeStampResp` to its token: refuses any status but granted (RFC 3161 2.4.2). Returns the token's DER. */
export function tokenFromResponse(resp: Uint8Array): Uint8Array | TokenCode {
  const asn = asn1js.fromBER(toAb(resp));
  if (asn.offset === -1) return 'MALFORMED';
  try {
    const r = new pkijs.TimeStampResp({ schema: asn.result });
    if (!PKI_GRANTED.has(r.status.status as number) || !r.timeStampToken) return 'NOT_GRANTED';
    return fromAb(r.timeStampToken.toSchema().toBER());
  } catch {
    return 'MALFORMED';
  }
}

export class TsaError extends Error {
  readonly authority: string;
  constructor(authority: string, message: string) {
    super(`${authority}: ${message}`);
    this.name = 'TsaError';
    this.authority = authority;
  }
}

export interface TsaClientOptions {
  readonly authority: Authority;
  readonly trustedRoots: readonly Uint8Array[];
  readonly fetch?: typeof fetch;
  readonly nonce?: () => Uint8Array;
  /** Milliseconds, for rate limiting only. */
  readonly now?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly timeoutMs?: number;
}

/**
 * One authority as a `TsaPort`. Requests to it are spaced by `authority.minIntervalMs` (they queue behind each other),
 * and an HTTP 429 pushes the next request out by `Retry-After`. A response is returned only if it verifies.
 */
export function tsaClient(o: TsaClientOptions) {
  const { authority } = o;
  const doFetch = o.fetch ?? fetch;
  const now = o.now ?? Date.now;
  const sleep = o.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  let nextAt = 0;
  let queue: Promise<unknown> = Promise.resolve();

  // The slot is taken before the request goes out, so concurrent callers are spaced, never bunched.
  const slot = (): Promise<void> => {
    const turn = queue.then(async () => {
      const wait = nextAt - now();
      if (wait > 0) await sleep(wait);
      nextAt = now() + authority.minIntervalMs;
    });
    queue = turn.catch(() => undefined);
    return turn;
  };

  return {
    authority,
    async timestamp(sha256: Hex32): Promise<{ authority: string; token: Uint8Array }> {
      const hash = hexToBytes(sha256);
      const nonce = (o.nonce ?? randomNonce)();
      await slot();
      let res: Response;
      try {
        res = await doFetch(authority.url, {
          method: 'POST',
          headers: { 'content-type': 'application/timestamp-query' },
          body: toAb(buildTimestampReq(hash, nonce)),
          signal: AbortSignal.timeout(o.timeoutMs ?? 15_000),
        });
      } catch (e) {
        throw new TsaError(authority.name, `unreachable (${(e as Error).message})`);
      }
      if (res.status === 429) {
        const after = Number(res.headers.get('retry-after'));
        nextAt = Math.max(
          nextAt,
          now() + (Number.isFinite(after) && after > 0 ? after * 1000 : authority.minIntervalMs * 4),
        );
        throw new TsaError(authority.name, 'rate limited (HTTP 429)');
      }
      if (!res.ok) throw new TsaError(authority.name, `HTTP ${res.status}`);
      const token = tokenFromResponse(new Uint8Array(await res.arrayBuffer()));
      if (typeof token === 'string') throw new TsaError(authority.name, `bad response (${token})`);
      const checked = await verifyTimestampToken(token, hash, o.trustedRoots, nonce);
      if (!checked.ok) throw new TsaError(authority.name, `token refused (${checked.code})`);
      return { authority: authority.name, token };
    },
  };
}
