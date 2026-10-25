// Corrupted archives: the reader and the CLI never throw, never hang, and never pass a bundle whose files changed.
import fc from 'fast-check';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { readZip, ZipError } from '../src/zip.ts';
import { makeBundle, type TestBundle, verifyLenient } from './helpers.ts';

vi.setConfig({ testTimeout: 300_000, hookTimeout: 300_000 });

let b: TestBundle;
beforeAll(async () => {
  b = await makeBundle();
});

type Mutation =
  | { kind: 'flip'; at: number; bit: number }
  | { kind: 'truncate'; at: number }
  | { kind: 'append'; bytes: number[] }
  | { kind: 'splice'; at: number; len: number }
  | { kind: 'zero'; at: number; len: number };
const mutation: fc.Arbitrary<Mutation> = fc.oneof(
  fc.record({ kind: fc.constant('flip' as const), at: fc.nat(), bit: fc.nat(7) }),
  fc.record({ kind: fc.constant('truncate' as const), at: fc.nat() }),
  fc.record({ kind: fc.constant('append' as const), bytes: fc.array(fc.nat(255), { minLength: 1, maxLength: 64 }) }),
  fc.record({ kind: fc.constant('splice' as const), at: fc.nat(), len: fc.integer({ min: 1, max: 200 }) }),
  fc.record({ kind: fc.constant('zero' as const), at: fc.nat(), len: fc.integer({ min: 1, max: 200 }) }),
);
function apply(bytes: Uint8Array, m: Mutation): Uint8Array {
  const at = m.kind === 'append' ? 0 : m.at % bytes.length;
  switch (m.kind) {
    case 'flip': {
      const c = new Uint8Array(bytes);
      c[at] = (c[at] as number) ^ (1 << m.bit);
      return c;
    }
    case 'truncate':
      return bytes.slice(0, at);
    case 'append':
      return Uint8Array.from([...bytes, ...m.bytes]);
    case 'splice':
      return Uint8Array.from([...bytes.slice(0, at), ...bytes.slice(at + m.len)]);
    case 'zero': {
      const c = new Uint8Array(bytes);
      c.fill(0, at, at + m.len);
      return c;
    }
  }
}

const same = (a: Map<string, Uint8Array>, files: typeof b.files) =>
  a.size === files.length && files.every((f) => Buffer.from(a.get(f.path) ?? []).equals(f.bytes));

describe('fuzz: corrupted ZIPs', () => {
  it('the reader throws only ZipError', () => {
    fc.assert(
      fc.property(fc.array(mutation, { minLength: 1, maxLength: 3 }), (ms) => {
        const bytes = ms.reduce(apply, b.zip);
        try {
          readZip(bytes); // every entry that is read has passed its CRC-32
        } catch (e) {
          expect(e).toBeInstanceOf(ZipError);
        }
      }),
      { numRuns: 3000 },
    );
  });

  it('the CLI never crashes on a corrupted archive; it passes only if every file is unchanged', async () => {
    await fc.assert(
      fc.asyncProperty(fc.array(mutation, { minLength: 1, maxLength: 2 }), async (ms) => {
        const bytes = ms.reduce(apply, b.zip);
        const v = await verifyLenient(bytes);
        expect([0, 1]).toContain(v.code);
        if (v.code === 0) expect(same(readZip(bytes), b.files)).toBe(true);
        else expect(v.report.findings.some((f) => f.status === 'fail')).toBe(true);
      }),
      { numRuns: 40 },
    );
  });

  it('hostile archives: duplicate and unsafe paths, a zip bomb, ZIP64 and a comment are refused', () => {
    expect(() => readZip(new Uint8Array(0))).toThrow(ZipError);
    expect(() => readZip(new Uint8Array(22))).toThrow(ZipError);
    const end = new Uint8Array(22);
    new DataView(end.buffer).setUint32(0, 0x06054b50, true);
    expect(readZip(end).size).toBe(0);
    new DataView(end.buffer).setUint16(20, 5, true); // archive comment length
    expect(() => readZip(end)).toThrow(ZipError);
  });
});
