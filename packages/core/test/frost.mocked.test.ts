// P1.15-05 (nonce lifetime) and P1.15-10 (strict check of the aggregate), with noble's FROST wrapped to observe it.
import { ed25519 } from '@noble/curves/ed25519.js';
import { describe, expect, it, vi } from 'vitest';
import { aggregateChecked, type FrostError, SigningSession } from '../src/frost.ts';
import { allow, dkgKeys, enc } from './helpers/frost.ts';

// DKG and X-Wing are slow when the whole suite runs in parallel.
vi.setConfig({ testTimeout: 60_000 });

const spy = vi.hoisted(() => ({
  nonces: [] as { hiding: Uint8Array; binding: Uint8Array }[],
  aggregate: undefined as ((sig: Uint8Array) => Uint8Array) | undefined,
}));

vi.mock('@noble/curves/ed25519.js', async (importOriginal) => {
  const orig = await importOriginal<typeof import('@noble/curves/ed25519.js')>();
  const F = orig.ed25519_FROST;
  return {
    ...orig,
    ed25519_FROST: {
      ...F,
      commit: (...a: Parameters<typeof F.commit>) => {
        const r = F.commit(...a);
        spy.nonces.push(r.nonces);
        return r;
      },
      aggregate: (...a: Parameters<typeof F.aggregate>) => {
        const sig = F.aggregate(...a);
        return spy.aggregate ? spy.aggregate(sig) : sig;
      },
    },
  };
});

const slot = await dkgKeys('A');
const [k1, k2] = slot.keys.map((k) => k.secret);

describe('P1.15-05 nonce lifetime', () => {
  it('after signShare the nonce buffers are zeroed, and serializing the session never exposes them', () => {
    spy.nonces.length = 0;
    const msg = enc('m');
    const a = SigningSession.open(k1!, slot.pub, msg);
    const b = SigningSession.open(k2!, slot.pub, msg);
    const [na] = spy.nonces;
    expect(na!.hiding.some((x) => x !== 0)).toBe(true);
    const before = Buffer.from(na!.hiding).toString('hex');
    expect(() => JSON.stringify(a)).toThrow('NOT_SERIALIZABLE');
    expect(JSON.stringify(structuredClone(a))).not.toContain(before.slice(0, 16));
    a.signShare(msg, [a.commitment, b.commitment], allow);
    expect(na!.hiding.every((x) => x === 0) && na!.binding.every((x) => x === 0)).toBe(true);
  });
});

describe('P1.15-10 the aggregate is checked strictly before it is returned', () => {
  const sign = () => {
    const msg = enc('m');
    const a = SigningSession.open(k1!, slot.pub, msg);
    const b = SigningSession.open(k2!, slot.pub, msg);
    const list = [a.commitment, b.commitment];
    const shares = { [k1!.identifier]: a.signShare(msg, list, allow), [k2!.identifier]: b.signShare(msg, list, allow) };
    return () => aggregateChecked(slot.pub, list, msg, shares);
  };
  const code = (f: () => unknown) => {
    try {
      f();
    } catch (e) {
      return (e as FrostError).code;
    }
    return 'NO_THROW';
  };

  it('an aggregate with a hand-built bad R (a small-order component added) is AGGREGATE_INVALID', () => {
    const torsion = ed25519.Point.fromHex('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a');
    let bad = new Uint8Array();
    spy.aggregate = (sig) => {
      const R = ed25519.Point.fromBytes(sig.subarray(0, 32)).add(torsion);
      bad = new Uint8Array([...R.toBytes(), ...sig.subarray(32)]);
      return bad;
    };
    expect(code(sign())).toBe('AGGREGATE_INVALID');
    // The hand-built signature fails strict verification, which is what aggregateChecked runs last.
    expect(ed25519.verify(bad, enc('m'), slot.pub.commitments[0]!, { zip215: false })).toBe(false);
    spy.aggregate = () => {
      throw new Error('noble aggregation failed');
    };
    expect(code(sign())).toBe('AGGREGATE_INVALID');
    spy.aggregate = undefined;
    expect(sign()()).toHaveLength(64);
  });
});
