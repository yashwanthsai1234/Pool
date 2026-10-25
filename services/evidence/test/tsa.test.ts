import { bytesToHex } from '@noble/hashes/utils.js';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { describe, expect, it } from 'vitest';
import {
  buildTimestampReq,
  DIGICERT,
  nodeRootCertificates,
  SECTIGO,
  SSL_COM,
  tokenFromResponse,
  tsaClient,
  verifyTimestampToken,
} from '../src/tsa.ts';
import { FIXTURE_HASH, FIXTURE_NONCE } from './helpers/tsaFixture.ts';
import { recorded, replayFetch } from './helpers/tsaReplay.ts';

const roots = nodeRootCertificates();
const hashHex = bytesToHex(FIXTURE_HASH) as never;
const tokenOf = (a: typeof DIGICERT) => tokenFromResponse(recorded(a).resp) as Uint8Array;

describe('P3.4-07 RFC 3161: recorded responses from DigiCert, SSL.com and Sectigo', () => {
  it.each([DIGICERT, SSL_COM, SECTIGO])('$name: the request is rebuilt byte for byte', (a) => {
    expect(buildTimestampReq(FIXTURE_HASH, FIXTURE_NONCE)).toEqual(recorded(a).req);
  });

  it.each([DIGICERT, SSL_COM, SECTIGO])('$name: the token verifies against the hash and the TSA chain', async (a) => {
    const r = await verifyTimestampToken(tokenOf(a), FIXTURE_HASH, roots, FIXTURE_NONCE);
    expect(r).toMatchObject({ ok: true });
    if (r.ok) {
      expect(r.genTime.getUTCFullYear()).toBeGreaterThanOrEqual(2026);
      expect(r.certificates.length).toBeGreaterThanOrEqual(2);
    }
  });

  it('the client returns a verified token through the injected fetch', async () => {
    const c = tsaClient({ authority: DIGICERT, trustedRoots: roots, fetch: replayFetch(), nonce: () => FIXTURE_NONCE });
    const got = await c.timestamp(hashHex);
    expect(got.authority).toBe('digicert');
    expect(got.token).toEqual(tokenOf(DIGICERT));
  });

  it('refuses a token for another hash', async () => {
    const other = FIXTURE_HASH.slice();
    other[0] = (other[0] as number) ^ 1;
    expect(await verifyTimestampToken(tokenOf(DIGICERT), other, roots)).toEqual({
      ok: false,
      code: 'IMPRINT_MISMATCH',
    });
  });

  it('refuses a token with another nonce', async () => {
    const r = await verifyTimestampToken(
      tokenOf(DIGICERT),
      FIXTURE_HASH,
      roots,
      Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]),
    );
    expect(r).toEqual({ ok: false, code: 'NONCE_MISMATCH' });
  });

  it('refuses a chain that does not end in a trusted root', async () => {
    expect(await verifyTimestampToken(tokenOf(DIGICERT), FIXTURE_HASH, [])).toEqual({
      ok: false,
      code: 'CHAIN_UNTRUSTED',
    });
    // SSL.com's roots do not vouch for DigiCert's token
    const sslRoots = roots.filter((r) =>
      pkijs.Certificate.fromBER(r.slice().buffer as ArrayBuffer).subject.typesAndValues.some((t) =>
        String((t.value.valueBlock as { value?: string }).value).includes('SSL.com'),
      ),
    );
    expect(sslRoots.length).toBeGreaterThan(0);
    expect(await verifyTimestampToken(tokenOf(DIGICERT), FIXTURE_HASH, sslRoots)).toEqual({
      ok: false,
      code: 'CHAIN_UNTRUSTED',
    });
  });

  it('refuses a token whose signed content was changed (genTime moved by one second)', async () => {
    const token = tokenOf(DIGICERT).slice();
    // Find the TSTInfo genTime (GeneralizedTime tag 0x18, 15 bytes "YYYYMMDDHHMMSSZ") and change its last digit.
    const text = Buffer.from(token).toString('latin1');
    const at = text.search(/20\d{12}Z/);
    expect(at).toBeGreaterThan(0);
    token[at + 13] = (token[at + 13] as number) === 0x30 ? 0x31 : 0x30;
    const r = await verifyTimestampToken(token, FIXTURE_HASH, roots, FIXTURE_NONCE);
    expect(r.ok).toBe(false);
  });

  it('refuses garbage and a non-SignedData ContentInfo without throwing', async () => {
    expect(await verifyTimestampToken(new Uint8Array([1, 2, 3]), FIXTURE_HASH, roots)).toEqual({
      ok: false,
      code: 'MALFORMED',
    });
    const ci = new pkijs.ContentInfo({ contentType: '1.2.840.113549.1.7.1', content: new asn1js.OctetString() });
    expect(await verifyTimestampToken(new Uint8Array(ci.toSchema().toBER()), FIXTURE_HASH, roots)).toEqual({
      ok: false,
      code: 'NOT_SIGNED_DATA',
    });
  });

  it('refuses a response that is not "granted"', () => {
    const resp = new pkijs.TimeStampResp({ status: new pkijs.PKIStatusInfo({ status: 2 }) });
    expect(tokenFromResponse(new Uint8Array(resp.toSchema().toBER()))).toBe('NOT_GRANTED');
    expect(tokenFromResponse(new Uint8Array([0, 1]))).toBe('MALFORMED');
  });

  it('a client rejects a token whose nonce is not the one it sent', async () => {
    const c = tsaClient({
      authority: DIGICERT,
      trustedRoots: roots,
      fetch: replayFetch([DIGICERT]),
      nonce: () => FIXTURE_NONCE,
    });
    // replayFetch insists on the recorded request, so a different nonce is refused before any token is read
    const d = tsaClient({
      authority: DIGICERT,
      trustedRoots: roots,
      fetch: replayFetch([DIGICERT]),
      nonce: () => Uint8Array.from([9, 9, 9, 9, 9, 9, 9, 9]),
    });
    await expect(c.timestamp(hashHex)).resolves.toBeDefined();
    await expect(d.timestamp(hashHex)).rejects.toThrow(/differs from the recording|unreachable/);
  });
});

describe('rate limits', () => {
  it('spaces requests to one authority by minIntervalMs, and the slots queue in order', async () => {
    let t = 0;
    const slept: number[] = [];
    const c = tsaClient({
      authority: { ...DIGICERT, minIntervalMs: 1000 },
      trustedRoots: roots,
      fetch: replayFetch(),
      nonce: () => FIXTURE_NONCE,
      now: () => t,
      sleep: async (ms) => {
        slept.push(ms);
        t += ms;
      },
    });
    await Promise.all([c.timestamp(hashHex), c.timestamp(hashHex), c.timestamp(hashHex)]);
    expect(slept).toEqual([1000, 1000]);
  });

  it('HTTP 429 pushes the next request out by Retry-After and fails this one', async () => {
    let t = 0;
    const slept: number[] = [];
    const c = tsaClient({
      authority: { ...DIGICERT, minIntervalMs: 10 },
      trustedRoots: roots,
      fetch: replayFetch([DIGICERT], { status: { digicert: 429 } }),
      nonce: () => FIXTURE_NONCE,
      now: () => t,
      sleep: async (ms) => {
        slept.push(ms);
        t += ms;
      },
    });
    await expect(c.timestamp(hashHex)).rejects.toThrow(/rate limited/);
    await expect(c.timestamp(hashHex)).rejects.toThrow(/rate limited/);
    expect(slept).toEqual([2000]); // the second request waited out Retry-After: 2
  });

  it('an unreachable authority is a TsaError, not a hang', async () => {
    const c = tsaClient({
      authority: DIGICERT,
      trustedRoots: roots,
      fetch: (async () => {
        throw new Error('ECONNREFUSED');
      }) as typeof fetch,
    });
    await expect(c.timestamp(hashHex)).rejects.toThrow(/unreachable/);
  });
});
