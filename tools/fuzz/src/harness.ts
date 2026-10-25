// The fuzz harness: one property per parser, driven by fast-check for a time budget (LEGX_FUZZ_SECONDS).
// Source: https://fast-check.dev/docs/core-blocks/runners/ (`interruptAfterTimeLimit`, `numRuns`)
// Source: IMPLEMENTATION 5.2 (T-Z-01: no crash, no hang over 1 s, no uncaught exception; accepted input round-trips)
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import fc from 'fast-check';

export const HANG_MS = 1000;
export const CORPUS_DIR = join(import.meta.dirname, '..', 'corpus');

export interface Target {
  readonly name: string;
  /** Which package the parser lives in; CI shards by it. */
  readonly pkg: 'core' | 'contracts' | 'zk';
  /** Valid inputs from the vectors, fixtures and examples; the generator mutates them. */
  readonly seeds: () => readonly Uint8Array[] | Promise<readonly Uint8Array[]>;
  /**
   * Runs the parser on one input. It returns when the parser gave a result (accept or reject) and the properties held;
   * it throws when the parser threw an untyped error or a property failed.
   */
  readonly run: (input: Uint8Array) => void | Promise<void>;
  /** Crashes already reported in build/ISSUES.md. They are counted and kept, not failed, so the run can find others. */
  readonly known?: readonly KnownCrash[];
}

/** A reported crash: the parser (`label` of the `attempt` call) and the message it throws. */
export interface KnownCrash {
  readonly id: string;
  readonly label: string;
  readonly message: RegExp;
}

/** A property of a target failed (as opposed to the parser throwing). */
export class PropertyViolation extends Error {}
/** A parser threw something that is not one of its typed errors. */
export class UntypedThrow extends Error {
  readonly original: unknown;
  readonly label: string;
  readonly detail: string;
  constructor(original: unknown, label: string) {
    const detail = original instanceof Error ? `${original.name}: ${original.message}` : String(original);
    super(`untyped throw from ${label}: ${detail}`);
    this.original = original;
    this.label = label;
    this.detail = detail;
  }
}

export function assert(cond: unknown, what: string): asserts cond {
  if (!cond) throw new PropertyViolation(what);
}
export function assertEqual(a: unknown, b: unknown, what: string): void {
  if (!isDeepStrictEqual(a, b)) throw new PropertyViolation(`${what}: values differ`);
}

export type Attempt<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: unknown };

/**
 * Calls a parser. A return is `ok`; a throw that `typed` accepts is `ok: false`; any other throw becomes an
 * `UntypedThrow`, which is a crash. The default accepts no throw at all.
 */
export function attempt<T>(label: string, fn: () => T, typed: (e: unknown) => boolean = () => false): Attempt<T> {
  try {
    return { ok: true, value: fn() };
  } catch (error) {
    if (typed(error)) return { ok: false, error };
    throw new UntypedThrow(error, label);
  }
}
export async function attemptAsync<T>(
  label: string,
  fn: () => Promise<T>,
  typed: (e: unknown) => boolean = () => false,
): Promise<Attempt<T>> {
  try {
    return { ok: true, value: await fn() };
  } catch (error) {
    if (typed(error)) return { ok: false, error };
    throw new UntypedThrow(error, label);
  }
}

/** Bytes to JSON, or undefined when they are not UTF-8 JSON. Not a parser under test. */
export function jsonOf(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    return undefined;
  }
}
export const toBytes = (v: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(v));
export const text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes); // lossy on purpose
export const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
export const unhex = (h: string): Uint8Array => new Uint8Array(Buffer.from(h, 'hex'));

// ---------- input generators ----------

type ByteOp = readonly ['flip' | 'set' | 'ins' | 'del' | 'trunc' | 'dup', number, number];
const byteOps: fc.Arbitrary<ByteOp> = fc.tuple(
  fc.constantFrom('flip', 'set', 'ins', 'del', 'trunc', 'dup'),
  fc.nat(1 << 20),
  fc.nat(255),
);

function applyByteOp(b: Uint8Array, [op, at, v]: ByteOp): Uint8Array {
  const i = b.length === 0 ? 0 : at % b.length;
  const out = Array.from(b);
  if (op === 'flip' && b.length > 0) out[i] = (out[i] as number) ^ (1 << (v % 8));
  else if (op === 'set' && b.length > 0) out[i] = v;
  else if (op === 'ins') out.splice(i, 0, v);
  else if (op === 'del' && b.length > 0) out.splice(i, 1);
  else if (op === 'trunc') out.length = i;
  else if (op === 'dup' && b.length > 0) out.splice(i, 0, ...out.slice(i, i + 1 + (v % 16)));
  return Uint8Array.from(out);
}

const JUNK: readonly unknown[] = [
  null,
  true,
  false,
  0,
  1,
  -1,
  2 ** 31,
  2 ** 32,
  2 ** 53,
  1e308,
  0.5,
  '',
  'x',
  'A'.repeat(70),
  '0x',
  '\u0000',
  '00'.repeat(32),
  '0'.repeat(65),
  'ff'.repeat(33),
  [],
  {},
  [[]],
  JSON.parse('{"__proto__":{"polluted":true}}'),
  JSON.parse('{"constructor":{"prototype":{"polluted":true}}}'),
];

/** One change to a JSON value: delete a field, replace it by junk or by a leaf of another seed, or change one character. */
type JsonEdit = readonly [number, 'delete' | 'junk' | 'leaf' | 'tweak' | 'dupkey', number];
const jsonEdits: fc.Arbitrary<JsonEdit> = fc.tuple(
  fc.nat(1 << 24),
  fc.constantFrom('delete', 'junk', 'leaf', 'tweak', 'dupkey'),
  fc.nat(1 << 20),
);

const isContainer = (v: unknown): v is Record<string, unknown> | unknown[] => typeof v === 'object' && v !== null;

function leavesOf(v: unknown, out: unknown[] = []): unknown[] {
  if (isContainer(v)) for (const c of Object.values(v)) leavesOf(c, out);
  else out.push(v);
  return out;
}

function tweak(v: unknown, n: number): unknown {
  if (typeof v === 'string' && v.length > 0) {
    const i = n % v.length;
    const c = v[i] as string;
    const swap = c === '0' ? '1' : c === 'a' ? 'b' : c === 'A' ? 'B' : '0';
    return v.slice(0, i) + swap + v.slice(i + 1);
  }
  if (typeof v === 'number') return v + (n % 2 === 0 ? 1 : -1);
  if (typeof v === 'boolean') return !v;
  return v;
}

function applyJsonEdit(root: unknown, [path, op, n]: JsonEdit, donors: readonly unknown[]): unknown {
  let doc = structuredClone(root);
  let parent: Record<string, unknown> | unknown[] | undefined;
  let key = '';
  let node = doc;
  let p = path;
  while (isContainer(node)) {
    const keys = Object.keys(node);
    const k = p % (keys.length + 1);
    p = Math.floor(p / (keys.length + 1));
    if (k === keys.length) break;
    parent = node;
    key = keys[k] as string;
    node = (node as Record<string, unknown>)[key];
  }
  const set = (v: unknown) => {
    if (parent) (parent as Record<string, unknown>)[key] = v;
    else doc = v;
  };
  if (op === 'delete') {
    if (Array.isArray(parent)) parent.splice(Number(key), 1);
    else if (parent) delete (parent as Record<string, unknown>)[key];
    else doc = undefined;
  } else if (op === 'junk') set(JUNK[n % JUNK.length]);
  else if (op === 'leaf') {
    const pool = donors.flatMap((d) => leavesOf(d));
    set(pool.length > 0 ? pool[n % pool.length] : null);
  } else if (op === 'tweak') set(tweak(node, n));
  else if (op === 'dupkey' && parent && !Array.isArray(parent)) (parent as Record<string, unknown>)[`${key}_`] = node;
  return doc;
}

/**
 * Inputs for a target: random bytes, a seed unchanged, a seed with a few byte edits, and (for JSON seeds) a seed with
 * one or two field edits. The unchanged seeds make sure the accept path runs.
 */
export function inputsFor(seeds: readonly Uint8Array[]): fc.Arbitrary<Uint8Array> {
  const random = fc.uint8Array({ maxLength: 300 });
  if (seeds.length === 0) return random;
  const pick = fc.nat(seeds.length - 1);
  const docs = seeds.map(jsonOf);
  const jsonSeeds = docs.flatMap((d, i) => (d === undefined || !isContainer(d) ? [] : [i]));
  const arbs: { arbitrary: fc.Arbitrary<Uint8Array>; weight: number }[] = [
    { arbitrary: random, weight: 2 },
    { arbitrary: pick.map((i) => seeds[i] as Uint8Array), weight: 2 },
    {
      arbitrary: fc
        .tuple(pick, fc.array(byteOps, { minLength: 1, maxLength: 6 }))
        .map(([i, ops]) => ops.reduce(applyByteOp, seeds[i] as Uint8Array)),
      weight: 3,
    },
  ];
  if (jsonSeeds.length > 0) {
    arbs.push({
      arbitrary: fc
        .tuple(fc.constantFrom(...jsonSeeds), fc.array(jsonEdits, { minLength: 1, maxLength: 2 }))
        .map(([i, edits]) => {
          const donors = jsonSeeds.map((j) => docs[j]);
          const edited = edits.reduce((d, e) => applyJsonEdit(d, e, donors), docs[i]);
          return toBytes(edited ?? null);
        }),
      weight: 5,
    });
  }
  return fc.oneof(...arbs);
}

// ---------- running ----------

export interface Finding {
  readonly key: string;
  readonly input: Uint8Array;
  /** The id of the known crash this is, if it is one. */
  readonly known?: string;
}
export interface FuzzReport {
  readonly runs: number;
  /** Crashes and property violations, one per distinct key; the shortest input is kept. */
  readonly findings: readonly Finding[];
  /** The ones that are not in `Target.known`: any of these fails the run. */
  readonly failures: readonly Finding[];
}

export function fuzzSeconds(): number {
  const n = Number(process.env.LEGX_FUZZ_SECONDS);
  return Number.isFinite(n) && n > 0 ? n : 2;
}

const keyOf = (e: unknown): { key: string; label?: string; detail?: string } => {
  if (e instanceof UntypedThrow)
    return { key: `${e.label}: ${e.detail.slice(0, 120)}`, label: e.label, detail: e.detail };
  if (e instanceof PropertyViolation) return { key: e.message.slice(0, 120), label: 'property', detail: e.message };
  return { key: e instanceof Error ? e.message.slice(0, 120) : String(e) };
};

/** Runs one input; a run over `HANG_MS` is a failure, because the parser could be made to stall a server. */
export async function runOnce(t: Target, input: Uint8Array): Promise<void> {
  const t0 = performance.now();
  await t.run(input);
  const ms = performance.now() - t0;
  if (ms > HANG_MS) throw new PropertyViolation(`hang: ${Math.round(ms)} ms (limit ${HANG_MS} ms)`);
}

/**
 * Fuzzes a target for `seconds`. A crash does not stop the run (it is recorded once per distinct message and parser),
 * so a known crash cannot hide a new one. The caller fails the run on `failures`.
 */
export async function fuzz(t: Target, seconds: number = fuzzSeconds()): Promise<FuzzReport> {
  const found = new Map<string, Finding>();
  const property = fc.asyncProperty(inputsFor(await t.seeds()), async (input) => {
    try {
      await runOnce(t, input);
    } catch (e) {
      const { key, label, detail } = keyOf(e);
      const known = t.known?.find((k) => k.label === label && k.message.test(detail ?? ''))?.id;
      const prev = found.get(key);
      if (!prev || input.length < prev.input.length) found.set(key, { key, input, ...(known ? { known } : {}) });
    }
  });
  const res = await fc.check(property, {
    numRuns: Number.MAX_SAFE_INTEGER,
    interruptAfterTimeLimit: seconds * 1000,
    markInterruptAsFailure: false,
  });
  const findings = [...found.values()];
  return { runs: res.numRuns, findings, failures: findings.filter((f) => !f.known) };
}

// ---------- the crash corpus (P5.2-01) ----------

export const corpusDirOf = (target: string): string => join(CORPUS_DIR, target);

/** Saves a crash input to `corpus/<target>/<sha256 prefix>.bin`; the corpus test replays it as a unit test. */
export function saveCrash(target: string, input: Uint8Array): string {
  const dir = corpusDirOf(target);
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `${createHash('sha256').update(input).digest('hex').slice(0, 16)}.bin`);
  writeFileSync(file, input);
  return file;
}

export function corpusFiles(target: string): { name: string; bytes: Uint8Array }[] {
  const dir = corpusDirOf(target);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith('.bin'))
    .sort()
    .map((name) => ({ name, bytes: new Uint8Array(readFileSync(join(dir, name))) }));
}

/** `corpus/known.json` maps `<target>/<file>` to the open crash it shows; the corpus test expects those to still crash. */
const KNOWN_FILE = join(CORPUS_DIR, 'known.json');
export function knownCorpus(): Record<string, string> {
  return existsSync(KNOWN_FILE) ? (JSON.parse(readFileSync(KNOWN_FILE, 'utf8')) as Record<string, string>) : {};
}
export function recordKnown(target: string, file: string, id: string): void {
  const all = knownCorpus();
  all[`${target}/${file.split('/').pop()}`] = id;
  writeFileSync(KNOWN_FILE, `${JSON.stringify(all, null, 2)}\n`);
}
