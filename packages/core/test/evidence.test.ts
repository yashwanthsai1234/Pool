// Evidence primitives (task 1.13): T-U-10, T-U-11, P1.13-01, P1.13-04, P1.13-05.
// Source: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md, DESIGN 8.1, 8.2, 8.10
import { ed25519 } from '@noble/curves/ed25519.js';
import { hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { dsse } from '@sigstore/core';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { verifyClientRecords } from '../src/clientRecords.ts';
import {
  ATTEST_PAYLOAD_TYPE,
  type ChainEntry,
  type Envelope,
  ed25519Check,
  leafHashOf,
  PAYLOAD_TYPE,
  pae,
  signAttestation,
  signEnvelope,
  verifyAttestationEnvelope,
  verifyChain,
  verifyEnvelope,
  ZERO,
} from '../src/evidence.ts';

const seed = randomBytes(32);
const pub = ed25519.getPublicKey(seed);
const keyFor = (k: string) => (k === 'k1' ? pub : undefined);
const json = (o: unknown) => utf8ToBytes(JSON.stringify(o));
const store = (env: Envelope): ChainEntry => {
  const envelopeBytes = json(env);
  return { envelopeBytes, leafHash: leafHashOf(envelopeBytes) };
};
const b64 = (s: string) => Buffer.from(s, 'base64');

type Signer = (body: Uint8Array, seed: Uint8Array, keyid: string) => Envelope;
function makeChain(n: number, sign: Signer, extra: (i: number) => object = () => ({})): ChainEntry[] {
  const out: ChainEntry[] = [];
  let prev = ZERO;
  for (let i = 0; i < n; i++) {
    const e = store(
      sign(json({ predicate: { seq: i, prev_hash: prev, kind: 'check.passed', ...extra(i) } }), seed, 'k1'),
    );
    out.push(e);
    prev = e.leafHash;
  }
  return out;
}

describe('DSSE PAE (T-U-11)', () => {
  it('matches the spec example and @sigstore/core preAuthEncoding', () => {
    expect(Buffer.from(pae('http://example.com/HelloWorld', utf8ToBytes('hello world'))).toString()).toBe(
      'DSSEv1 29 http://example.com/HelloWorld 11 hello world',
    );
    fc.assert(
      fc.property(fc.string(), fc.uint8Array({ maxLength: 200 }), (type, body) => {
        expect(Buffer.from(pae(type, body)).equals(dsse.preAuthEncoding(type, Buffer.from(body)))).toBe(true);
      }),
      { numRuns: 300 },
    );
  });
  it('the length is in bytes, not characters', () => {
    expect(
      Buffer.from(pae('é', new Uint8Array([1])))
        .subarray(0, 12)
        .toString(),
    ).toBe('DSSEv1 2 é ');
  });
});

describe('P1.13-01 two payload types, one code path', () => {
  const body = json({ predicate: { seq: 0 } });
  const ev = signEnvelope(body, seed, 'k1');
  const at = signAttestation(body, seed, 'k1');
  it('each verifier accepts only its own type', () => {
    expect(ev.payloadType).toBe(PAYLOAD_TYPE);
    expect(at.payloadType).toBe(ATTEST_PAYLOAD_TYPE);
    expect(verifyEnvelope(ev, pub)).toBe(true);
    expect(verifyAttestationEnvelope(at, pub)).toBe(true);
    expect(verifyAttestationEnvelope(ev, pub)).toBe(false);
    expect(verifyEnvelope(at, pub)).toBe(false);
  });
  it('relabelling the type breaks the signature too (the type is inside the PAE)', () => {
    expect(verifyAttestationEnvelope({ ...ev, payloadType: ATTEST_PAYLOAD_TYPE }, pub)).toBe(false);
    expect(verifyEnvelope({ ...at, payloadType: PAYLOAD_TYPE }, pub)).toBe(false);
  });
  it('rejects a changed payload, a wrong key, non-canonical base64 and junk without throwing', () => {
    expect(verifyEnvelope({ ...ev, payload: Buffer.from('{"predicate":{"seq":1}}').toString('base64') }, pub)).toBe(
      false,
    );
    expect(verifyEnvelope(ev, ed25519.getPublicKey(randomBytes(32)))).toBe(false);
    expect(verifyEnvelope({ ...ev, payload: ev.payload.replace(/=+$/, '') }, pub)).toBe(false);
    expect(verifyEnvelope({ ...ev, signatures: [{ keyid: 'k1', sig: 'not base64!' }] }, pub)).toBe(false);
    expect(verifyEnvelope({ ...ev, signatures: [null] } as unknown as Envelope, pub)).toBe(false);
    expect(verifyEnvelope({} as Envelope, pub)).toBe(false);
  });
  it('rejects a small-order key with the all-identity signature that ZIP-215 accepts for every message', () => {
    // vectors/ed25519/noble-zip215.json entry 0: key = identity point, signature = (R = identity, S = 0).
    const identity = hexToBytes('01'.padEnd(64, '0'));
    const sig = Buffer.from(hexToBytes(`01${'00'.repeat(63)}`)).toString('base64');
    const forged = { ...ev, signatures: [{ keyid: 'k1', sig }] };
    expect(
      ed25519.verify(Buffer.from(sig, 'base64'), pae(PAYLOAD_TYPE, b64(ev.payload)), identity, { zip215: true }),
    ).toBe(true);
    expect(verifyEnvelope(forged, identity)).toBe(false);
  });
  it('a signature flipped in one bit fails', () => {
    const sig = b64(ev.signatures[0]!.sig);
    sig[7] = sig[7]! ^ 1;
    expect(verifyEnvelope({ ...ev, signatures: [{ keyid: 'k1', sig: sig.toString('base64') }] }, pub)).toBe(false);
  });
});

describe.each([
  ['event', signEnvelope, PAYLOAD_TYPE],
  ['attest', signAttestation, ATTEST_PAYLOAD_TYPE],
] as const)('T-U-10 chain, %s type', (_name, sign, type) => {
  const entries = makeChain(5, sign);
  const verify = (e: ChainEntry[]) => verifyChain(e, keyFor, type);

  it('verifies, and the other type does not', () => {
    expect(verify(entries)).toBe(true);
    expect(verifyChain(entries, keyFor, type === PAYLOAD_TYPE ? ATTEST_PAYLOAD_TYPE : PAYLOAD_TYPE)).toBe(false);
    expect(verify([])).toBe(true);
  });
  it('detects a replaced entry, a wrong stored leaf hash and an unknown key', () => {
    const junk = utf8ToBytes('{}');
    expect(verify(entries.map((e, i) => (i === 2 ? { envelopeBytes: junk, leafHash: leafHashOf(junk) } : e)))).toBe(
      false,
    );
    expect(verify(entries.map((e, i) => (i === 2 ? { ...e, leafHash: ZERO } : e)))).toBe(false);
    expect(verifyChain(entries, () => undefined, type)).toBe(false);
  });
  it('P1.13-05 a dropped, swapped or duplicated entry fails even though every remaining hash is recomputed', () => {
    expect(verify(entries.filter((_, i) => i !== 3))).toBe(false);
    expect(verify(entries.filter((_, i) => i !== 0))).toBe(false);
    expect(verify([entries[1]!, entries[0]!, ...entries.slice(2)])).toBe(false);
    expect(verify([...entries, entries[4]!])).toBe(false);
    // An attacker re-signs a gapless-looking chain by recomputing prev_hash but cannot fix the signed seq.
    const rechained: ChainEntry[] = [];
    let prev = ZERO;
    for (const i of [0, 1, 2, 4]) {
      const e = store(sign(json({ predicate: { seq: i, prev_hash: prev, kind: 'check.passed' } }), seed, 'k1'));
      rechained.push(e);
      prev = e.leafHash;
    }
    expect(verify(rechained)).toBe(false);
  });
  it('rejects a non-integer, string or missing seq and prev_hash', () => {
    const bad = (pred: object) => verify([store(sign(json({ predicate: pred }), seed, 'k1'))]);
    expect(bad({ seq: '0', prev_hash: ZERO })).toBe(false);
    expect(bad({ seq: 0 })).toBe(false);
    expect(bad({ prev_hash: ZERO })).toBe(false);
    expect(verify([store(sign(utf8ToBytes('not json'), seed, 'k1'))])).toBe(false);
    expect(verify([store(sign(json({ no: 'predicate' }), seed, 'k1'))])).toBe(false);
  });
});

describe('never re-serialize an envelope', () => {
  it('stores, reloads and hashes the same bytes; a re-formatted copy has another leaf hash and fails the chain', () => {
    const entries = makeChain(3, signEnvelope);
    const reloaded = entries.map((e) => ({
      envelopeBytes: new Uint8Array(Buffer.from(Buffer.from(e.envelopeBytes).toString('latin1'), 'latin1')),
      leafHash: e.leafHash,
    }));
    expect(reloaded.map((e) => leafHashOf(e.envelopeBytes))).toEqual(entries.map((e) => e.leafHash));
    expect(verifyChain(reloaded, keyFor)).toBe(true);
    // Same JSON value, different bytes (pretty-printed): the signature still verifies, the stored leaf hash does not.
    const e1 = entries[1]!;
    const pretty = utf8ToBytes(JSON.stringify(JSON.parse(Buffer.from(e1.envelopeBytes).toString()), null, 2));
    expect(leafHashOf(pretty)).not.toBe(e1.leafHash);
    expect(verifyChain([entries[0]!, { envelopeBytes: pretty, leafHash: e1.leafHash }, entries[2]!], keyFor)).toBe(
      false,
    );
    // A reordered key order does not change what the signature covers: PAE is over the payload bytes.
    const env: Envelope = JSON.parse(Buffer.from(e1.envelopeBytes).toString());
    expect(
      verifyEnvelope({ signatures: env.signatures, payload: env.payload, payloadType: env.payloadType }, pub),
    ).toBe(true);
  });
});

describe('P1.13-04 client records view', () => {
  const none = () => undefined;
  const check = ed25519Check(keyFor);
  const withLedger = (i: number) =>
    i === 1 ? { ledger: { tx_hash: 'AB'.repeat(32), ledger_index: 55, validated: true } } : {};
  const entries = makeChain(4, signEnvelope, withLedger);
  const idx = (h: string) => (h === 'AB'.repeat(32) ? 55 : undefined);

  it('reports signature, chain position and ledger link for each record', () => {
    expect(verifyClientRecords(entries, check, { ledgerIndexOf: idx })).toEqual(
      entries.map((e, i) => ({
        seq: i,
        leafHash: e.leafHash,
        signature: true,
        chain: true,
        ledger: i === 1 ? 'linked' : 'none',
      })),
    );
  });
  it('flags a ledger index that disagrees, or a transaction the ledger does not know', () => {
    expect(verifyClientRecords(entries, check, { ledgerIndexOf: () => 56 })[1]!.ledger).toBe('mismatch');
    expect(verifyClientRecords(entries, check, { ledgerIndexOf: none })[1]!.ledger).toBe('mismatch');
  });
  it('a dropped record fails the chain of the record after the gap only', () => {
    const r = verifyClientRecords(
      entries.filter((_, i) => i !== 2),
      check,
      { ledgerIndexOf: idx },
    );
    expect(r.map((x) => x.chain)).toEqual([true, true, false]);
    expect(r.every((x) => x.signature)).toBe(true);
  });
  it('a record signed by an unknown key or with changed bytes fails its signature', () => {
    const r = verifyClientRecords(
      entries,
      ed25519Check(() => undefined),
      { ledgerIndexOf: idx },
    );
    expect(r.every((x) => !x.signature)).toBe(true);
    const junk = utf8ToBytes('{}');
    const swapped = entries.map((e, i) => (i === 0 ? { envelopeBytes: junk, leafHash: leafHashOf(junk) } : e));
    const r2 = verifyClientRecords(swapped, check, { ledgerIndexOf: idx });
    expect(r2[0]).toMatchObject({ seq: -1, signature: false, chain: false, ledger: 'none' });
    expect(r2[1]).toMatchObject({ signature: true, chain: false });
  });
  it('a list that starts mid-chain checks against the given start', () => {
    const tail = entries.slice(2);
    const opts = { ledgerIndexOf: idx, start: { seq: 2, prevHash: entries[1]!.leafHash } };
    expect(verifyClientRecords(tail, check, opts).map((x) => x.chain)).toEqual([true, true]);
    expect(verifyClientRecords(tail, check, { ledgerIndexOf: idx }).map((x) => x.chain)).toEqual([false, true]);
  });
});
