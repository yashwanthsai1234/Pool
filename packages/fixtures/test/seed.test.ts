import { describe, expect, it } from 'vitest';
import { deriveBytes, deriveInt } from '../src/seed.ts';

describe('seed stream (HKDF-SHA256 over the seed)', () => {
  it('is deterministic and separates labels and seeds', () => {
    expect(deriveBytes('s', 'a', 32)).toEqual(deriveBytes('s', 'a', 32));
    expect(deriveBytes('s', 'a', 32)).not.toEqual(deriveBytes('s', 'b', 32));
    expect(deriveBytes('s', 'a', 32)).not.toEqual(deriveBytes('t', 'a', 32));
    expect(deriveBytes(new TextEncoder().encode('s'), 'a', 32)).toEqual(deriveBytes('s', 'a', 32));
  });

  it('gives integers inside the half-open range', () => {
    for (let i = 0; i < 200; i++) {
      const n = deriveInt('s', `n${i}`, 5, 9);
      expect(n).toBeGreaterThanOrEqual(5);
      expect(n).toBeLessThan(9);
    }
    expect(() => deriveInt('s', 'x', 3, 3)).toThrow(RangeError);
  });
});
