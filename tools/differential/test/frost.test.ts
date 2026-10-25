// P5.3-04 (without a Rust CLI, see build/status/5.3b.md): noble's FROST against the ZF frost-ed25519 3.0.0 vectors,
// and against Node's OpenSSL Ed25519 as an independent verifier, in a random-transcript replay.
import { createPublicKey, verify as nodeVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { ed25519, ed25519_FROST as F } from '@noble/curves/ed25519.js';
import { describe, expect, it } from 'vitest';
import { hex, Prng, seedsToRun } from '../src/index.ts';

const dir = new URL('../../frost-ref/vectors/', import.meta.url);
const vector = (f: string) => JSON.parse(readFileSync(new URL(f, dir), 'utf8'));
const unhex = (s: string) => Uint8Array.from(Buffer.from(s, 'hex'));
const Fn = ed25519.Point.Fn;

interface Setup {
  ids: number[];
  max: number;
  groupKey: string;
  msg: string;
  rand: Record<number, [string, string]>;
  commitments: Record<number, [string, string]>;
  sigShares: Record<number, string>;
  sig: string;
  shares: Record<number, Uint8Array>;
}

function load(file: string): Setup {
  const v = vector(file);
  const ids = v.inputs.participant_list as number[];
  const a0 = Fn.fromBytes(unhex(v.inputs.group_secret_key));
  const a1 = Fn.fromBytes(unhex(v.inputs.share_polynomial_coefficients[0]));
  const r1 = v.round_one_outputs.outputs as Record<string, string | number>[];
  const r2 = v.round_two_outputs.outputs as Record<string, string | number>[];
  return {
    ids,
    max: Number(v.config.MAX_PARTICIPANTS),
    groupKey: v.inputs.verifying_key_key,
    msg: v.inputs.message,
    rand: Object.fromEntries(r1.map((o) => [o.identifier, [o.hiding_nonce_randomness, o.binding_nonce_randomness]])),
    commitments: Object.fromEntries(
      r1.map((o) => [o.identifier, [o.hiding_nonce_commitment, o.binding_nonce_commitment]]),
    ),
    sigShares: Object.fromEntries(r2.map((o) => [o.identifier, o.sig_share])),
    sig: v.final_output.sig,
    shares: Object.fromEntries(ids.map((i) => [i, Fn.toBytes(Fn.add(a0, Fn.mul(a1, BigInt(i))))])),
  };
}

const publicOf = (s: Setup) => ({
  signers: { min: 2, max: s.max },
  commitments: [unhex(s.groupKey)],
  verifyingShares: Object.fromEntries(
    s.ids.map((i) => [
      F.Identifier.fromNumber(i),
      ed25519.Point.BASE.multiply(Fn.fromBytes(s.shares[i] as Uint8Array)).toBytes(),
    ]),
  ),
});

const nodeKey = (groupKey: string) =>
  createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(groupKey, 'hex').toString('base64url') },
    format: 'jwk',
  });

/** Hands out the given chunks one call at a time, like the vector's nonce randomness. */
const chunks = (cs: Uint8Array[]) => {
  let k = 0;
  return () => cs[k++] as Uint8Array;
};

function signWith(s: Setup, ids: number[], msg: Uint8Array, rng: (i: number) => (n?: number) => Uint8Array) {
  const pub = publicOf(s);
  const commit = ids.map((i) =>
    F.commit({ identifier: F.Identifier.fromNumber(i), signingShare: s.shares[i] as Uint8Array }, rng(i)),
  );
  const list = commit.map((c) => c.commitments);
  const shares = Object.fromEntries(
    ids.map((i, k) => [
      F.Identifier.fromNumber(i),
      F.signShare(
        { identifier: F.Identifier.fromNumber(i), signingShare: s.shares[i] as Uint8Array },
        pub,
        (commit[k] as (typeof commit)[0]).nonces,
        list,
        msg,
      ),
    ]),
  );
  return { pub, list, shares, sig: F.aggregate(pub, list, msg, shares) };
}

describe('FROST: noble against the ZF vectors and Node Ed25519', () => {
  for (const file of ['zf-vectors.json', 'zf-vectors-big-identifier.json']) {
    const s = load(file);
    it(`${file}: the vector transcript replays byte for byte and verifies in Node`, () => {
      const msg = unhex(s.msg);
      const out = signWith(
        s,
        s.ids,
        msg,
        (i) => chunks((s.rand[i] as [string, string]).map(unhex)) as () => Uint8Array,
      );
      out.list.forEach((c, k) => {
        expect(hex(c.hiding)).toBe((s.commitments[s.ids[k] as number] as [string, string])[0]);
        expect(hex(c.binding)).toBe((s.commitments[s.ids[k] as number] as [string, string])[1]);
      });
      for (const i of s.ids) expect(hex(out.shares[F.Identifier.fromNumber(i)] as Uint8Array)).toBe(s.sigShares[i]);
      expect(hex(out.sig)).toBe(s.sig);
      expect(nodeVerify(null, msg, nodeKey(s.groupKey), unhex(s.sig))).toBe(true);
    });

    for (const seed of seedsToRun()) {
      it(`${file} seed ${seed}: 100 random messages and signer subsets verify in noble and in Node`, () => {
        const r = new Prng(seed);
        const key = nodeKey(s.groupKey);
        for (let n = 0; n < 100; n++) {
          const msg = r.bytes(r.int(300));
          const ids = r.shuffle(s.ids).slice(0, r.range(2, s.ids.length));
          const out = signWith(
            s,
            ids,
            msg,
            () =>
              (len = 32) =>
                r.bytes(len),
          );
          for (const c of out.list)
            expect(F.verifyShare(out.pub, out.list, msg, c.identifier, out.shares[c.identifier] as Uint8Array)).toBe(
              true,
            );
          expect(nodeVerify(null, msg, key, out.sig)).toBe(true);
          expect(ed25519.verify(out.sig, msg, unhex(s.groupKey), { zip215: false })).toBe(true);
          expect(nodeVerify(null, new Uint8Array([...msg, 1]), key, out.sig)).toBe(false);
        }
      }, 120_000);
    }
  }
});
