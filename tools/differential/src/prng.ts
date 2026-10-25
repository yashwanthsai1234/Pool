// A small seeded PRNG (mulberry32) so a failing case replays from its seed. Not for cryptography.
// Source: https://github.com/bryc/code/blob/master/jshash/PRNGs.md#mulberry32
export class Prng {
  #s: number;

  constructor(seed: number) {
    this.#s = seed >>> 0;
  }

  u32(): number {
    this.#s = (this.#s + 0x6d2b79f5) >>> 0;
    let t = this.#s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return (t ^ (t >>> 14)) >>> 0;
  }

  /** An integer in [0, n). */
  int(n: number): number {
    return this.u32() % n;
  }

  /** An integer in [lo, hi], both included. */
  range(lo: number, hi: number): number {
    return lo + this.int(hi - lo + 1);
  }

  chance(p: number): boolean {
    return this.u32() / 2 ** 32 < p;
  }

  pick<T>(xs: readonly T[]): T {
    return xs[this.int(xs.length)] as T;
  }

  bytes(n: number): Uint8Array {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i += 4) {
      const w = this.u32();
      for (let k = 0; k < 4 && i + k < n; k++) out[i + k] = (w >>> (8 * k)) & 0xff;
    }
    return out;
  }

  shuffle<T>(xs: readonly T[]): T[] {
    const a = [...xs];
    for (let i = a.length - 1; i > 0; i--) {
      const j = this.int(i + 1);
      [a[i], a[j]] = [a[j] as T, a[i] as T];
    }
    return a;
  }

  /** A string of random Unicode scalar values (no lone surrogates), including astral ones and combining marks. */
  text(maxLen: number): string {
    const pools: readonly (readonly [number, number])[] = [
      [0x20, 0x7e],
      [0xa1, 0x24f],
      [0x300, 0x36f],
      [0x4e00, 0x4e80],
      [0x1f300, 0x1f340],
    ];
    let s = '';
    for (let n = this.int(maxLen + 1); n > 0; n--) {
      const [lo, hi] = this.pick(pools);
      s += String.fromCodePoint(this.range(lo, hi));
    }
    return s;
  }
}

/** The seeds each differential test runs: two fixed ones, and one random one (LEGX_SEED fixes it for a replay). */
export function seedsToRun(): number[] {
  const fromEnv = process.env.LEGX_SEED;
  const random = fromEnv === undefined ? Math.floor(Math.random() * 2 ** 32) : Number(fromEnv);
  return [20261024, 7, random];
}

/** Number of cases per function (T-Z-02 and P5.3-02 ask for 10,000). */
export const CASES = Number(process.env.LEGX_DIFF_N ?? 10_000);
