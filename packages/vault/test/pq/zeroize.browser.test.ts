// P4.9-02 (second half): the expanded ML-DSA-65 secret key handed to core's signer is zeroed after the call.
// noble's exports are frozen, so the core wrapper is mocked (calling through) to see the key it receives.
import { randomBytes } from '@noble/hashes/utils.js';
import { describe, expect, it, vi } from 'vitest';
import { pqKeys } from '../../src/pq/keys.ts';
import { dealId, freshDb, isZero } from '../helpers.ts';

const seen = vi.hoisted(() => [] as Uint8Array[]);
vi.mock('@legx/core/pq', async (orig) => {
  const real = await orig<typeof import('@legx/core/pq')>();
  return {
    ...real,
    mldsaSign: (...a: Parameters<typeof real.mldsaSign>) => {
      seen.push(a[1]);
      return real.mldsaSign(...a);
    },
  };
});

describe('P4.9-02 expanded key', () => {
  it('is 4,032 bytes while signing and all zero afterwards, also when signing throws', async () => {
    const id = dealId();
    const keys = pqKeys({ role: 'alice', dbName: freshDb() });
    await keys.create(id);
    const half = await keys.half(id, 'k#ml-dsa-65');
    await half.sign(randomBytes(32), 'legx/pq-binding/v1');
    // A context noble refuses (over 255 bytes) still zeroes the key.
    await expect(half.sign(randomBytes(1), 'x'.repeat(300) as 'legx/dsse/v1')).rejects.toThrow();
    expect(seen).toHaveLength(2);
    for (const sk of seen) {
      expect(sk).toHaveLength(4032);
      expect(isZero(sk)).toBe(true);
    }
  });
});
