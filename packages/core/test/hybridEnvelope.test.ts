// Hybrid DSSE envelopes (DESIGN 6.13, 8.1): T-U-24, P1.16-01, P1.16-02, P1.16-09, P1.16-11, P1.16-16.
// Source: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md (several signatures over one PAE)

import { ATTEST_PAYLOAD_TYPE, EVENT_PAYLOAD_TYPE } from '@legx/contracts/records';
import type { KeyId } from '@legx/contracts/values';
import { ed25519 } from '@noble/curves/ed25519.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { type Envelope, pae, signEnvelope, verifyEnvelope } from '../src/evidence.ts';
import {
  type KeyRegistry,
  type RecordType,
  type RegisteredKey,
  SIG_POLICY,
  type SigPolicy,
  signHybrid,
  verifyHybrid,
} from '../src/hybridEnvelope.ts';
import { fromBase64Strict, mldsaSign, mldsaVerify, nobleHybridSigner, pqKeygen, toBase64 } from '../src/pq.ts';

const seed = (n: number) => new Uint8Array(32).fill(n);
const edSk = seed(1);
const edPub = ed25519.getPublicKey(edSk);
const pq = pqKeygen(seed(2));
const ED = 'enroll:alice:ed' as KeyId;
const PQ = 'enroll:alice:pq' as KeyId;
const signer = nobleHybridSigner(
  { keyId: ED, publicKey: edPub, sign: async (m) => ed25519.sign(m, edSk) },
  { keyId: PQ, secretKey: pq.secretKey },
);
const AT = 800_000_000; // a ledger close_time (Ripple epoch)
const keys: Record<string, RegisteredKey> = {
  [ED]: { alg: 'ed25519', publicKey: edPub, validFrom: 1, logged: true, pair: 'alice' },
  [PQ]: { alg: 'ml-dsa-65', publicKey: pq.publicKey, validFrom: 1, logged: true, pair: 'alice' },
};
const registry: KeyRegistry = (id) => keys[id];

const attest = (over: Record<string, unknown> = {}) =>
  utf8ToBytes(JSON.stringify({ kind: 'test', sig_algs: ['ed25519', 'ml-dsa-65'], ...over }));
const event = (sigAlgs: unknown) =>
  utf8ToBytes(JSON.stringify({ _type: 'https://in-toto.io/Statement/v1', predicate: { seq: 0, sig_algs: sigAlgs } }));
const fails = (code: string) => ({ ok: false, code });
// Signs any body, bypassing signHybrid's own sig_algs check, to build records an attacker could forge.
const rawSign = async (payloadType: string, body: Uint8Array): Promise<Envelope> => {
  const h = await signer.signHybrid(pae(payloadType, body), 'legx/dsse/v1');
  return {
    payloadType,
    payload: toBase64(body),
    signatures: [
      { keyid: h.keyIds.ed25519, sig: toBase64(h.ed25519) },
      { keyid: h.keyIds.mlDsa65, sig: toBase64(h.mlDsa65) },
    ],
  };
};

describe('the record-type policy table', () => {
  it('covers exactly the two payload types of the contracts, both hybrid', () => {
    expect(Object.keys(SIG_POLICY).sort()).toEqual([ATTEST_PAYLOAD_TYPE, EVENT_PAYLOAD_TYPE].sort());
    for (const t of Object.keys(SIG_POLICY) as RecordType[])
      expect(SIG_POLICY[t].algs).toEqual(['ed25519', 'ml-dsa-65']);
  });

  it('a classical-only policy does not compile (no downgrade setting exists)', () => {
    const tryConfigure = (): SigPolicy => ({
      // @ts-expect-error the table type admits only the hybrid tuple
      algs: ['ed25519'],
      sigAlgsOf: () => ['ed25519'],
    });
    expect(tryConfigure).toBeTypeOf('function');
  });
});

describe('T-U-24 hybrid envelope', () => {
  it('T-U-24a: both signatures over the same PAE verify, for an attestation and for an event', async () => {
    const env = await signHybrid(ATTEST_PAYLOAD_TYPE, attest(), signer);
    expect(env.signatures.map((s) => s.keyid)).toEqual([ED, PQ]);
    const r = verifyHybrid(env, registry, AT);
    expect(r.ok && r.keyIds).toEqual({ ed25519: ED, mlDsa65: PQ });
    const ev = await signHybrid(EVENT_PAYLOAD_TYPE, event(['ed25519', 'ml-dsa-65']), signer);
    expect(verifyHybrid(ev, registry, AT).ok).toBe(true);
  });

  it('T-U-24b/c: either signature removed', async () => {
    const env = await signHybrid(ATTEST_PAYLOAD_TYPE, attest(), signer);
    const [ed, ml] = env.signatures as [Envelope['signatures'][0], Envelope['signatures'][0]];
    expect(verifyHybrid({ ...env, signatures: [ed] }, registry, AT)).toEqual(fails('PQ_SIGNATURE_MISSING'));
    expect(verifyHybrid({ ...env, signatures: [ml] }, registry, AT)).toEqual(fails('ED_SIGNATURE_MISSING'));
    expect(verifyHybrid({ ...env, signatures: [] }, registry, AT)).toEqual(fails('ED_SIGNATURE_MISSING'));
  });

  it('T-U-24d: the signatures swapped, the key IDs swapped, or the signature bytes swapped', async () => {
    const env = await signHybrid(ATTEST_PAYLOAD_TYPE, attest(), signer);
    const [ed, ml] = env.signatures as [Envelope['signatures'][0], Envelope['signatures'][0]];
    expect(verifyHybrid({ ...env, signatures: [ml, ed] }, registry, AT)).toEqual(fails('SIGNATURE_ORDER'));
    const idSwap = [
      { keyid: ml.keyid, sig: ed.sig },
      { keyid: ed.keyid, sig: ml.sig },
    ];
    expect(verifyHybrid({ ...env, signatures: idSwap }, registry, AT)).toEqual(fails('SIGNATURE_ORDER'));
    const sigSwap = [
      { keyid: ed.keyid, sig: ml.sig },
      { keyid: ml.keyid, sig: ed.sig },
    ];
    expect(verifyHybrid({ ...env, signatures: sigSwap }, registry, AT)).toEqual(fails('ED_SIGNATURE_INVALID'));
  });

  it('T-U-24e: sig_algs in the payload differs from what the envelope carries', async () => {
    for (const algs of [
      ['ed25519'],
      ['ml-dsa-65'],
      ['ed25519', 'ml-dsa-65', 'slh-dsa'],
      ['ed25519', 'ml-dsa-65', 'ml-dsa-65'],
      ['ml-dsa-65', 'ed25519'],
      [],
      'ed25519,ml-dsa-65',
      undefined,
    ]) {
      const env = await rawSign(ATTEST_PAYLOAD_TYPE, attest({ sig_algs: algs }));
      expect(verifyHybrid(env, registry, AT), JSON.stringify(algs)).toEqual(fails('SIG_ALGS_MISMATCH'));
    }
    const ev = await rawSign(EVENT_PAYLOAD_TYPE, event(['ed25519']));
    expect(verifyHybrid(ev, registry, AT)).toEqual(fails('SIG_ALGS_MISMATCH'));
    // An event keeps sig_algs in its predicate: a top-level list does not count.
    const top = await rawSign(EVENT_PAYLOAD_TYPE, attest());
    expect(verifyHybrid(top, registry, AT)).toEqual(fails('SIG_ALGS_MISMATCH'));
  });

  it('signHybrid refuses to sign a payload whose sig_algs does not match the table', async () => {
    await expect(signHybrid(ATTEST_PAYLOAD_TYPE, attest({ sig_algs: ['ed25519'] }), signer)).rejects.toThrow(
      'SIG_ALGS_MISMATCH',
    );
    await expect(signHybrid(EVENT_PAYLOAD_TYPE, utf8ToBytes('not json'), signer)).rejects.toThrow('SIG_ALGS_MISMATCH');
  });

  it('T-U-24f: an old classical-only envelope is never accepted (no downgrade)', () => {
    const old = signEnvelope(event(['ed25519']), edSk, ED);
    expect(verifyEnvelope(old, edPub)).toBe(true);
    expect(verifyHybrid(old, registry, AT)).toEqual(fails('PQ_SIGNATURE_MISSING'));
  });

  it('T-U-24g: a record that lists only ed25519 and carries one signature fails anyway', async () => {
    const body = attest({ sig_algs: ['ed25519'] });
    const env: Envelope = {
      payloadType: ATTEST_PAYLOAD_TYPE,
      payload: toBase64(body),
      signatures: [{ keyid: ED, sig: toBase64(ed25519.sign(pae(ATTEST_PAYLOAD_TYPE, body), edSk)) }],
    };
    expect(verifyHybrid(env, registry, AT)).toEqual(fails('PQ_SIGNATURE_MISSING'));
  });

  it('T-U-24h / P1.16-02: an ML-DSA signature under the empty context or another use context fails', async () => {
    const body = attest();
    const env = await signHybrid(ATTEST_PAYLOAD_TYPE, body, signer);
    const m = pae(ATTEST_PAYLOAD_TYPE, body);
    const withSig = (sig: Uint8Array) => ({
      ...env,
      signatures: [env.signatures[0] as Envelope['signatures'][0], { keyid: PQ, sig: toBase64(sig) }],
    });
    expect(verifyHybrid(withSig(ml_dsa65.sign(m, pq.secretKey)), registry, AT)).toEqual(fails('PQ_SIGNATURE_INVALID'));
    for (const ctx of ['legx/pq-binding/v1', 'legx/checkpoint/v1'] as const) {
      expect(verifyHybrid(withSig(mldsaSign('ml-dsa-65', pq.secretKey, m, ctx)), registry, AT)).toEqual(
        fails('PQ_SIGNATURE_INVALID'),
      );
    }
  });

  it('a payload type outside the table, and malformed envelopes, give typed errors and never throw', async () => {
    const env = await signHybrid(ATTEST_PAYLOAD_TYPE, attest(), signer);
    expect(verifyHybrid({ ...env, payloadType: 'application/vnd.legx.event+json;v=2' }, registry, AT)).toEqual(
      fails('PAYLOAD_TYPE_UNKNOWN'),
    );
    expect(verifyHybrid({ ...env, payloadType: 'toString' }, registry, AT)).toEqual(fails('PAYLOAD_TYPE_UNKNOWN'));
    const hostile: unknown[] = [
      null,
      42,
      'x',
      {},
      { ...env, signatures: 'x' },
      { ...env, signatures: [null, null] },
      { ...env, signatures: [{ keyid: 1, sig: 'x' }] },
      { ...env, payload: 'not base64!' },
      { ...env, payload: `${env.payload}=` },
      { ...env, payload: toBase64(utf8ToBytes('[not json')) },
    ];
    for (const h of hostile) {
      const r = verifyHybrid(h as Envelope, registry, AT);
      expect(r.ok, JSON.stringify(h)?.slice(0, 60)).toBe(false);
    }
  });

  it('wrong lengths: ML-DSA signature not 3,309 B, key not 1,952 B, Ed25519 signature not 64 B', async () => {
    const env = await signHybrid(ATTEST_PAYLOAD_TYPE, attest(), signer);
    const [ed, ml] = env.signatures as [Envelope['signatures'][0], Envelope['signatures'][0]];
    const short = toBase64((fromBase64Strict(ml.sig) as Uint8Array).subarray(1));
    expect(verifyHybrid({ ...env, signatures: [ed, { ...ml, sig: short }] }, registry, AT)).toEqual(
      fails('PQ_SIGNATURE_INVALID'),
    );
    const edShort = toBase64((fromBase64Strict(ed.sig) as Uint8Array).subarray(1));
    expect(verifyHybrid({ ...env, signatures: [{ ...ed, sig: edShort }, ml] }, registry, AT)).toEqual(
      fails('ED_SIGNATURE_INVALID'),
    );
    const badKeys: KeyRegistry = (id) =>
      id === PQ ? { ...(keys[PQ] as RegisteredKey), publicKey: pq.publicKey.subarray(1) } : keys[id];
    expect(verifyHybrid(env, badKeys, AT)).toEqual(fails('PQ_SIGNATURE_INVALID'));
  });

  it('a plain DSSE verifier still reads the Ed25519 signature alone (compatibility); ours requires both', async () => {
    const env = await signHybrid(EVENT_PAYLOAD_TYPE, event(['ed25519', 'ml-dsa-65']), signer);
    expect(verifyEnvelope(env, edPub)).toBe(true);
  });
});

describe('defensive paths', () => {
  it('a registry that throws gives MALFORMED; the signer port reports both public keys', async () => {
    const env = await signHybrid(ATTEST_PAYLOAD_TYPE, attest(), signer);
    const throwing: KeyRegistry = () => {
      throw new Error('db down');
    };
    expect(verifyHybrid(env, throwing, AT)).toEqual(fails('MALFORMED'));
    const pk = await signer.publicKeys();
    expect([pk.ed25519.length, pk.mlDsa65.length, pk.keyIds]).toEqual([32, 1952, { ed25519: ED, mlDsa65: PQ }]);
  });

  it('Ed25519 is verified strictly: the identity-key forgery that ZIP-215 accepts for any message fails', async () => {
    const env = await signHybrid(ATTEST_PAYLOAD_TYPE, attest(), signer);
    const identity = new Uint8Array(32);
    identity[0] = 1;
    const forged = new Uint8Array(64);
    forged[0] = 1; // R = identity, S = 0
    expect(ed25519.verify(forged, pae(ATTEST_PAYLOAD_TYPE, attest()), identity)).toBe(true); // lenient default
    const reg: KeyRegistry = (id) => (id === ED ? { ...(keys[ED] as RegisteredKey), publicKey: identity } : keys[id]);
    const ml = env.signatures[1] as Envelope['signatures'][0];
    const bad = { ...env, signatures: [{ keyid: ED, sig: toBase64(forged) }, ml] };
    expect(verifyHybrid(bad, reg, AT)).toEqual(fails('ED_SIGNATURE_INVALID'));
  });

  it('mldsaVerify returns false, never throws, on input that is not bytes', () => {
    const m = utf8ToBytes('x');
    expect(
      mldsaVerify('ml-dsa-65', pq.publicKey, 'x' as unknown as Uint8Array, new Uint8Array(3309), 'legx/dsse/v1'),
    ).toBe(false);
    expect(mldsaVerify('ml-dsa-65', pq.publicKey, m, new Uint8Array(3309), 'legx/dsse/v1')).toBe(false);
  });
});

describe('P1.16-01 sig_algs stripping attack', () => {
  it('removing the ML-DSA signature and rewriting sig_algs breaks the Ed25519 signature', async () => {
    const env = await signHybrid(EVENT_PAYLOAD_TYPE, event(['ed25519', 'ml-dsa-65']), signer);
    const stripped: Envelope = {
      payloadType: env.payloadType,
      payload: toBase64(event(['ed25519'])),
      signatures: [env.signatures[0] as Envelope['signatures'][0]],
    };
    expect(verifyEnvelope(stripped, edPub)).toBe(false); // the plain verifier also fails: the payload changed
    expect(verifyHybrid(stripped, registry, AT).ok).toBe(false);
    const keptPq = { ...stripped, signatures: env.signatures };
    expect(verifyHybrid(keptPq, registry, AT).ok).toBe(false);
  });
});

describe('P1.16-16 duplicated signatures', () => {
  it('the same ML-DSA or Ed25519 signature listed twice fails', async () => {
    const env = await signHybrid(ATTEST_PAYLOAD_TYPE, attest(), signer);
    const [ed, ml] = env.signatures as [Envelope['signatures'][0], Envelope['signatures'][0]];
    for (const sigs of [
      [ed, ml, ml],
      [ed, ed, ml],
      [ed, ed],
      [ml, ml],
    ]) {
      expect(verifyHybrid({ ...env, signatures: sigs }, registry, AT)).toEqual(fails('DUPLICATE_SIGNATURE'));
    }
  });
});

describe('P1.16-09 key registry', () => {
  it('unknown key ID, outside validFrom and validTo, hash not yet in the evidence log', async () => {
    const env = await signHybrid(ATTEST_PAYLOAD_TYPE, attest(), signer);
    const with_ =
      (id: string, over: object): KeyRegistry =>
      (k) =>
        k === id ? { ...(keys[k] as RegisteredKey), ...over } : keys[k];
    expect(verifyHybrid(env, (k) => (k === PQ ? undefined : keys[k]), AT)).toEqual(fails('KEY_UNKNOWN'));
    expect(verifyHybrid(env, (k) => (k === ED ? undefined : keys[k]), AT)).toEqual(fails('KEY_UNKNOWN'));
    expect(verifyHybrid(env, with_(PQ, { validTo: AT - 1 }), AT)).toEqual(fails('KEY_EXPIRED'));
    expect(verifyHybrid(env, with_(ED, { validFrom: AT + 1 }), AT)).toEqual(fails('KEY_EXPIRED'));
    expect(verifyHybrid(env, with_(PQ, { validTo: AT }), AT).ok).toBe(true);
    expect(verifyHybrid(env, with_(PQ, { logged: false }), AT)).toEqual(fails('KEY_NOT_LOGGED'));
    expect(verifyHybrid(env, with_(ED, { logged: false }), AT)).toEqual(fails('KEY_NOT_LOGGED'));
    // I-S-P1: both halves come from one holder's enrollment key pair.
    expect(verifyHybrid(env, with_(PQ, { pair: 'bob' }), AT)).toEqual(fails('PAIR_MISMATCH'));
    expect(verifyHybrid(env, (k) => ({ ...(keys[k] as RegisteredKey), pair: '' }), AT)).toEqual(fails('PAIR_MISMATCH'));
    expect(verifyHybrid(env, with_(ED, { pair: undefined as never }), AT)).toEqual(fails('PAIR_MISMATCH'));
    expect(verifyHybrid(env, (k) => (k === PQ ? keys[ED] : keys[k]), AT)).toEqual(fails('DUPLICATE_SIGNATURE'));
    expect(verifyHybrid(env, () => undefined, Number.NaN)).toEqual(fails('KEY_UNKNOWN'));
    expect(verifyHybrid(env, registry, Number.NaN)).toEqual(fails('KEY_EXPIRED'));
  });
});

describe('P1.16-11 sizes', () => {
  it('a hybrid envelope for a 1 KB event stays under 6 KB and is 4.3 to 4.6 KB larger than Ed25519-only', async () => {
    const body = utf8ToBytes(
      JSON.stringify({ predicate: { sig_algs: ['ed25519', 'ml-dsa-65'], pad: 'x'.repeat(1024 - 60) } }),
    );
    expect(body.length).toBeGreaterThanOrEqual(1000);
    expect(body.length).toBeLessThanOrEqual(1024);
    const hybrid = JSON.stringify(await signHybrid(EVENT_PAYLOAD_TYPE, body, signer));
    const classical = JSON.stringify(signEnvelope(body, edSk, ED));
    expect(hybrid.length).toBeLessThan(6 * 1024);
    expect(hybrid.length - classical.length).toBeGreaterThanOrEqual(4300);
    expect(hybrid.length - classical.length).toBeLessThanOrEqual(4600);
  });
});

describe('property: round trip, and any single-bit mutation fails', () => {
  const payloadArb = fc.record({ n: fc.integer(), s: fc.string({ maxLength: 200 }) });
  it('random payloads round trip; a flipped bit in the payload, either signature, or sig_algs fails', async () => {
    await fc.assert(
      fc.asyncProperty(
        payloadArb,
        fc.nat(),
        fc.integer({ min: 0, max: 7 }),
        fc.integer({ min: 0, max: 3 }),
        async (p, at, bit, where) => {
          const body = attest(p);
          const env = await signHybrid(ATTEST_PAYLOAD_TYPE, body, signer);
          if (!verifyHybrid(env, registry, AT).ok) return false;
          const flip = (b: Uint8Array) => {
            const i = at % b.length;
            return Uint8Array.from(b, (x, j) => (j === i ? x ^ (1 << bit) : x));
          };
          const [ed, ml] = env.signatures as [Envelope['signatures'][0], Envelope['signatures'][0]];
          const dec = (s: string) => fromBase64Strict(s) as Uint8Array;
          let bad: Envelope;
          if (where === 0) bad = { ...env, payload: toBase64(flip(body)) };
          else if (where === 1) bad = { ...env, signatures: [{ ...ed, sig: toBase64(flip(dec(ed.sig))) }, ml] };
          else if (where === 2) bad = { ...env, signatures: [ed, { ...ml, sig: toBase64(flip(dec(ml.sig))) }] };
          else {
            const text = new TextDecoder().decode(body).replace('"ml-dsa-65"', '"ml-dsa-66"');
            bad = { ...env, payload: toBase64(utf8ToBytes(text)) };
          }
          return !verifyHybrid(bad, registry, AT).ok;
        },
      ),
      { numRuns: 30 },
    );
  }, 60_000); // ML-DSA signing is about 10 ms a run, slower under coverage

  it('strict base64: only canonical encodings decode', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 100 }), (b) => {
        const s = toBase64(b);
        return (fromBase64Strict(s) as Uint8Array).every((x, i) => x === b[i]);
      }),
    );
    for (const bad of ['QQ', 'QR==', 'QQ==\n', ' QQ==', 'Q===', '====', 'QUJD=', 'QUJD-_==']) {
      expect(fromBase64Strict(bad), bad).toBeUndefined();
    }
    expect(fromBase64Strict('')).toEqual(new Uint8Array(0));
  });
});
