// T-P-01: for random slots, every 2-of-3 pair signs and passes strict verification; one share alone cannot.
// Flipping a bit in the message, a commitment or a share makes verification or verifyShare fail.
import { ed25519_FROST } from '@noble/curves/ed25519.js';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  aggregateChecked,
  type FrostError,
  holderId,
  SigningSession,
  slotPubkey,
  THRESHOLD,
  verifyEd25519Strict,
  verifyShares,
} from '../src/frost.ts';
import { allow, frostSign } from './helpers/frost.ts';

/** A slot from noble's three DKG rounds without transport (transport is covered by frost.dkg.test.ts). */
function slotKeys() {
  const ids = [1, 2, 3].map(holderId);
  const r1 = ids.map((id) => ed25519_FROST.DKG.round1(id, THRESHOLD));
  const r2 = r1.map((p, i) =>
    ed25519_FROST.DKG.round2(
      p.secret,
      r1.filter((_, j) => j !== i).map((x) => x.public),
    ),
  );
  const keys = ids.map((id, i) =>
    ed25519_FROST.DKG.round3(
      r1[i]!.secret,
      r1.filter((_, j) => j !== i).map((x) => x.public),
      r2.filter((_, j) => j !== i).map((m) => m[id]!),
    ),
  );
  return { keys, pub: keys[0]!.public };
}

const flip = (b: Uint8Array, bit: number) => {
  const c = b.slice();
  const i = Math.floor(bit / 8) % c.length;
  c[i] = (c[i] as number) ^ (1 << (bit % 8));
  return c;
};

describe('T-P-01 FROST slot property', () => {
  it('holds for 100 DKG slots (noble DKG rounds; our signing, aggregation and strict checks)', async () => {
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ minLength: 1, maxLength: 64 }), fc.nat(511), async (msg, bit) => {
        const { keys, pub } = slotKeys();
        const shares = keys.map((k) => k.secret);
        const pk = slotPubkey(pub);
        for (const [a, b] of [
          [0, 1],
          [0, 2],
          [1, 2],
        ] as const) {
          const sig = frostSign(pub, [shares[a]!, shares[b]!], msg);
          expect(verifyEd25519Strict(sig, msg, pk)).toBe(true);
          expect(verifyEd25519Strict(sig, flip(msg, bit), pk)).toBe(false);
          expect(verifyEd25519Strict(flip(sig, bit), msg, pk)).toBe(false);
        }
        // Flipped share or flipped commitment: verifyShare names the share.
        const s = [shares[0]!, shares[2]!].map((k) => SigningSession.open(k, pub, msg));
        const list = s.map((x) => x.commitment);
        const sig = Object.fromEntries(
          [shares[0]!, shares[2]!].map((k, i) => [k.identifier, s[i]!.signShare(msg, list, allow)]),
        );
        const id = shares[0]!.identifier;
        expect(verifyShares(pub, list, msg, { ...sig, [id]: flip(sig[id]!, bit % 248) })).toContain(id);
        const badList = [{ ...list[0]!, hiding: flip(list[0]!.hiding, bit % 248) }, list[1]!];
        expect(verifyShares(pub, badList, msg, sig).length).toBeGreaterThan(0);
        // One share alone: our wrapper refuses, and noble cannot aggregate it either.
        const one = SigningSession.open(shares[1]!, pub, msg);
        const err = (() => {
          try {
            aggregateChecked(pub, [one.commitment], msg, {});
          } catch (e) {
            return (e as FrostError).code;
          }
        })();
        expect(err).toBe('BELOW_THRESHOLD');
        const g = ed25519_FROST.commit(shares[1]!);
        expect(() => ed25519_FROST.signShare(shares[1]!, pub, g.nonces, [g.commitments], msg)).toThrow();
      }),
      { numRuns: 100 },
    );
  }, 300_000);
});
