import { readFileSync } from 'node:fs';
import { fc, test } from '@fast-check/vitest';
import { describe, expect } from 'vitest';
import { z } from 'zod';
import { SCHEMAS } from '../src/catalog.ts';

const NAMES = Object.keys(SCHEMAS);
const golden = (name: string): unknown[] =>
  JSON.parse(readFileSync(new URL(`../examples/${name}.json`, import.meta.url), 'utf8'));

/** parse() may only throw a ZodError; safeParse() may never throw. */
function onlyZodErrors(schema: z.ZodType, value: unknown): void {
  expect(() => schema.safeParse(value)).not.toThrow();
  try {
    schema.parse(value);
  } catch (e) {
    expect(e).toBeInstanceOf(z.ZodError);
  }
}

/** Replaces one random node of a golden example with a random JSON value. */
const mutated = (name: string) =>
  fc
    .tuple(fc.constantFrom(...golden(name)), fc.array(fc.nat(), { maxLength: 6 }), fc.jsonValue())
    .map(([ex, picks, value]) => {
      const copy = structuredClone(ex) as Record<string, unknown>;
      let node: Record<string, unknown> = copy;
      for (const p of picks) {
        const keys = Object.keys(node);
        if (keys.length === 0) break;
        const k = keys[p % keys.length] as string;
        const child = node[k];
        if (child === null || typeof child !== 'object' || picks.indexOf(p) === picks.length - 1) {
          node[k] = value;
          break;
        }
        node = child as Record<string, unknown>;
      }
      return copy;
    });

describe('fuzz: schemas never throw anything but a ZodError', () => {
  describe.each(NAMES)('%s', (name) => {
    const schema = SCHEMAS[name] as z.ZodType;
    test.prop([fc.anything({ withBigInt: true, withDate: true, withMap: true, withSet: true, withTypedArray: true })], {
      numRuns: 60,
    })('fc.anything()', (v) => onlyZodErrors(schema, v));
    test.prop([mutated(name)], { numRuns: 60 })('mutated golden example', (v) => onlyZodErrors(schema, v));
  });
});

describe('hostile input', () => {
  const env = golden('Envelope')[0] as Record<string, unknown>;

  test('a "__proto__" key from JSON.parse is an unknown key, not a prototype change', () => {
    const parsed = JSON.parse(`{"__proto__":{"polluted":1},${JSON.stringify(env).slice(1)}`);
    const r = (SCHEMAS.Envelope as z.ZodType).safeParse(parsed);
    expect(r.success).toBe(false);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  // Known limit, pinned: a throwing getter (never produced by JSON.parse) escapes as its own error. So every
  // boundary parses JSON.parse output, never a live object handed over by other code.
  test('a throwing getter is not wrapped in a ZodError', () => {
    const hostile = {
      ...env,
      get payload(): string {
        throw new Error('getter');
      },
    };
    expect(() => (SCHEMAS.Envelope as z.ZodType).safeParse(hostile)).toThrow('getter');
  });
});
