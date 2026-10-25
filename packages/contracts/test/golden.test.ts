import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { jsonSchemaOf, SCHEMAS } from '../src/catalog.ts';

const DIR = new URL('../examples/', import.meta.url);
const load = (name: string): unknown[] => JSON.parse(readFileSync(new URL(`${name}.json`, DIR), 'utf8'));
const NAMES = Object.keys(SCHEMAS);

type Path = (string | number)[];

/** Every leaf (non-object, non-array value) in an example, with its path. */
function leaves(v: unknown, path: Path = []): Path[] {
  if (Array.isArray(v)) return v.flatMap((x, i) => leaves(x, [...path, i]));
  if (v !== null && typeof v === 'object') return Object.entries(v).flatMap(([k, x]) => leaves(x, [...path, k]));
  return [path];
}

/** Every object in an example, with its path. */
function objects(v: unknown, path: Path = []): Path[] {
  if (Array.isArray(v)) return v.flatMap((x, i) => objects(x, [...path, i]));
  if (v !== null && typeof v === 'object')
    return [path, ...Object.entries(v).flatMap(([k, x]) => objects(x, [...path, k]))];
  return [];
}

function setAt(root: unknown, path: Path, f: (old: unknown) => unknown): unknown {
  const copy = structuredClone(root);
  if (path.length === 0) return f(copy);
  let node = copy as Record<string | number, unknown>;
  for (const k of path.slice(0, -1)) node = node[k] as Record<string | number, unknown>;
  const last = path[path.length - 1] as string | number;
  node[last] = f(node[last]);
  return copy;
}

const wrongType = (v: unknown) => (typeof v === 'string' ? 12345 : 'x');
/** Free-form JSON the contracts deliberately leave open (SDK queries, unsigned transactions, keyed maps). */
const OPEN = new Set([
  'originalQuery',
  'queryResult',
  'unsignedTx',
  'ports',
  'queryResultErrors',
  'tx',
  'releaseInput',
  'hashes',
]);
const inOpen = (p: Path) =>
  p.some((k) => typeof k === 'string' && OPEN.has(k)) || (p.includes('proofs') && p.includes('committedInputs'));
const related = (a: Path, b: Path) => {
  const n = Math.min(a.length, b.length);
  return a.slice(0, n).every((k, i) => k === b[i]);
};

describe('P1.2-01 golden examples', () => {
  it('every catalog schema has a golden example file, and every file has a schema', () => {
    const files = readdirSync(DIR).map((f) => f.replace(/\.json$/, ''));
    expect(files.sort()).toEqual([...NAMES].sort());
  });

  it.each(NAMES)('%s parses its golden examples', (name) => {
    for (const ex of load(name)) expect(SCHEMAS[name]?.safeParse(ex).error?.issues ?? []).toEqual([]);
  });

  it.each(NAMES)('%s round trips through JSON unchanged', (name) => {
    for (const ex of load(name)) expect(SCHEMAS[name]?.parse(JSON.parse(JSON.stringify(ex)))).toEqual(ex);
  });
});

describe('P1.2-02 one wrong field', () => {
  it.each(NAMES)('%s: a wrong value in any field fails with a path to that field', (name) => {
    const schema = SCHEMAS[name];
    for (const ex of load(name)) {
      for (const path of leaves(ex)) {
        if (inOpen(path)) continue;
        const r = schema?.safeParse(setAt(ex, path, wrongType));
        expect(r?.success, `${name} ${path.join('.')}`).toBe(false);
        expect(
          r?.error?.issues.some((i) => related(i.path as Path, path)),
          `${name} ${path.join('.')}`,
        ).toBe(true);
      }
    }
  });

  it.each(NAMES)('%s: an extra key on any object fails with that object’s path', (name) => {
    const schema = SCHEMAS[name];
    for (const ex of load(name)) {
      for (const path of objects(ex)) {
        if (inOpen(path) || OPEN.has(String(path[path.length - 1]))) continue;
        const r = schema?.safeParse(setAt(ex, path, (o) => ({ ...(o as object), unexpected_key: 1 })));
        expect(r?.success, `${name} ${path.join('.')}`).toBe(false);
        expect(r?.error?.issues.some((i) => related(i.path as Path, path))).toBe(true);
      }
    }
  });
});

describe('P1.2-03 JSON Schema snapshots', () => {
  it.each(NAMES)('%s matches its committed JSON Schema', async (name) => {
    const schema = SCHEMAS[name];
    if (!schema) throw new Error(name);
    await expect(`${JSON.stringify(jsonSchemaOf(schema), null, 2)}\n`).toMatchFileSnapshot(
      `../json-schema/${name}.schema.json`,
    );
  });
});
