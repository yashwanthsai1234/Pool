// Servers never sign with noble's ML-DSA (DESIGN 6.13: not audited, not constant-time). The biome rule blocks the direct
// import; these tests do not rely on it:
//   1. a static walk of the import graph from every service source file, naming each workspace file that reaches
//      `@noble/post-quantum`;
//   2. a runtime check: the service signing flows (hybrid signing, the checkpoint cosigner, the renewal job, key rotation)
//      run with noble's `sign` and `keygen` counted, and neither is ever called, while `verify` is.
// Source: https://github.com/paulmillr/noble-post-quantum#security (unaudited, not constant-time)
import { existsSync, mkdtempSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { KeyId } from '@legx/contracts/values';
import { generateNodeCheckpointKeys, generateNodeSignerKeys, nodeCheckpointSigner, nodeSigner } from '@legx/signer';
import { localObjectStore } from '@legx/storage/localStore';
import { describe, expect, it, vi } from 'vitest';
import { cosignCheckpoint, createKeyring } from '../../evidence/src/pq/index.ts';
import { makeLocalTsa } from '../../evidence/test/helpers/localTsa.ts';
import { createRenewal } from '../src/index.ts';

// Mock the very file core imports (the deep path is the realpath both resolve to), counting sign, keygen and verify.
const calls = vi.hoisted(() => ({ sign: 0, keygen: 0, verify: 0 }));
vi.mock('../../../packages/core/node_modules/@noble/post-quantum/ml-dsa.js', async (importOriginal) => {
  const real = await importOriginal<Record<string, Record<string, (...a: unknown[]) => unknown>>>();
  const counted = (alg: Record<string, (...a: unknown[]) => unknown>) => {
    const wrapped = Object.create(alg) as Record<string, unknown>;
    for (const fn of ['sign', 'keygen', 'verify'] as const) {
      Object.defineProperty(wrapped, fn, {
        value: (...args: unknown[]) => {
          calls[fn]++;
          return Reflect.apply(alg[fn] as (...a: unknown[]) => unknown, alg, args);
        },
      });
    }
    return wrapped;
  };
  return { ...real, ml_dsa44: counted(real.ml_dsa44 as never), ml_dsa65: counted(real.ml_dsa65 as never) };
});

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const NOBLE = /^@noble\/post-quantum(\/|$)/;
// The one service file that may import noble's post-quantum package, and only its KEM side (I-W-14): the X-Wing share
// cipher of the DKG. It never signs: ML-DSA signing stays out of every service file. Core's `ShareCipher` is synchronous
// (`keygen`, `publicKeyOf`), and a synchronous X-Wing key pair exists only in noble's `hybrid.js`; the HPKE library is
// asynchronous. Moving the cipher into core with an asynchronous `ShareCipher` removes this entry (request to F2).
const KEM_ONLY: Readonly<Record<string, string>> = {
  'packages/core/src/xwingShareCipher.ts': '@noble/post-quantum/hybrid.js',
};
const SPEC = /(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g;

const walk = (dir: string): string[] =>
  readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return n === 'node_modules' ? [] : statSync(p).isDirectory() ? walk(p) : p.endsWith('.ts') ? [p] : [];
  });

/** Workspace package name to source directory, from each package.json (`exports` map `./*` and `.`). */
function workspaceRoots(): Map<string, string> {
  const m = new Map<string, string>();
  for (const group of ['packages', 'services', 'apps', 'tools']) {
    if (!existsSync(join(ROOT, group))) continue;
    for (const d of readdirSync(join(ROOT, group))) {
      const pj = join(ROOT, group, d, 'package.json');
      if (existsSync(pj)) m.set(JSON.parse(readFileSync(pj, 'utf8')).name, join(ROOT, group, d));
    }
  }
  return m;
}

function resolveSpec(from: string, spec: string, roots: Map<string, string>): string | undefined {
  if (spec.startsWith('.')) return resolve(dirname(from), spec);
  const parts = spec.split('/');
  const name = spec.startsWith('@') ? parts.slice(0, 2).join('/') : (parts[0] as string);
  const dir = roots.get(name);
  if (!dir) return undefined; // an external package
  const sub = spec.slice(name.length + 1);
  return join(dir, 'src', sub === '' ? 'index.ts' : `${sub}.ts`);
}

/** Every workspace file reachable from `entries`, and the ones among them that import noble's post-quantum package. */
function graph(entries: string[]): { files: Set<string>; nobleImporters: Map<string, string> } {
  const roots = workspaceRoots();
  const files = new Set<string>();
  const nobleImporters = new Map<string, string>();
  const todo = [...entries];
  while (todo.length) {
    const f = todo.pop() as string;
    if (files.has(f) || !existsSync(f)) continue;
    files.add(f);
    for (const [, spec] of readFileSync(f, 'utf8').matchAll(SPEC)) {
      if (NOBLE.test(spec as string)) nobleImporters.set(relative(ROOT, f), spec as string);
      const next = resolveSpec(f, spec as string, roots);
      if (next) todo.push(next);
    }
  }
  return { files, nobleImporters };
}

// Production code of every service: each file under services/*/src is an entry point.
const serviceEntries = readdirSync(join(ROOT, 'services')).flatMap((d) =>
  existsSync(join(ROOT, 'services', d, 'src')) ? walk(join(ROOT, 'services', d, 'src')) : [],
);

describe('servers never use noble ML-DSA: the module graph', () => {
  it('finds the service entry points of every service folder', () => {
    expect(serviceEntries.length).toBeGreaterThan(20);
    for (const s of ['coordinator', 'evidence', 'renewal', 'verifier'])
      expect(serviceEntries.some((e) => e.includes(`/services/${s}/src/`))).toBe(true);
  });

  it('no file of a service, @legx/signer or @legx/storage imports @noble/post-quantum', () => {
    const own = [
      ...serviceEntries,
      ...walk(join(ROOT, 'packages/signer/src')),
      ...walk(join(ROOT, 'packages/storage/src')),
    ];
    const hits = [...graph(own).nobleImporters.keys()].filter(
      (f) => /^(services|packages\/(signer|storage))\//.test(f) && !(f in KEM_ONLY),
    );
    expect(hits).toEqual([]);
  });

  it("the allow-listed cipher file reaches only noble's KEM module, never ML-DSA (I-W-14)", () => {
    const { nobleImporters } = graph(serviceEntries);
    for (const [file, spec] of Object.entries(KEM_ONLY)) expect(nobleImporters.get(file)).toBe(spec);
    for (const [file, spec] of nobleImporters)
      if (file.startsWith('services/')) expect(spec, file).not.toMatch(/ml-dsa|slh-dsa/);
    // a second file that starts importing noble without being listed fails the previous test, and so does a listed
    // file that stops (the list would be stale)
    expect(Object.keys(KEM_ONLY).every((f) => nobleImporters.has(f))).toBe(true);
  });

  it('the only workspace files reaching it are the two verify-side modules of core (DQ-3.12-1)', () => {
    const { nobleImporters } = graph(serviceEntries);
    // @legx/core/pq (the context wrapper, `mldsaVerify`, `muFor`) and @legx/core/pqCheckpoint (`verifyCheckpoint`).
    // Their `sign` and `keygen` are for browsers and tests; the runtime test below shows services never call them.
    expect([...nobleImporters.keys()].filter((f) => !(f in KEM_ONLY)).sort()).toEqual([
      'packages/core/src/pq.ts',
      'packages/core/src/pqCheckpoint.ts',
    ]);
  });

  it.todo(
    'DQ-3.12-1: the strict form (no @noble/post-quantum anywhere in the graph) needs core to verify through node:crypto',
  );
});

describe('servers never use noble ML-DSA: at run time', () => {
  it('hybrid signing, the checkpoint cosigner, the renewal job and a key rotation call noble verify but never sign or keygen', async () => {
    const local = await makeLocalTsa('nonoble');
    const first = nodeSigner(generateNodeSignerKeys(KeyId.parse('nn-1'), KeyId.parse('nn-1:pq')));
    const second = nodeSigner(generateNodeSignerKeys(KeyId.parse('nn-2'), KeyId.parse('nn-2:pq')));
    const cp = nodeCheckpointSigner(generateNodeCheckpointKeys(KeyId.parse('nc-e'), KeyId.parse('nc-p')));
    calls.sign = calls.keygen = calls.verify = 0;

    const ring = await createKeyring(first, 0);
    await ring.rotate(second, 10, async () => {});
    const note = `legx.test/nn\n1\n${Buffer.alloc(32, 1).toString('base64')}\n\n`;
    const cosigned = await cosignCheckpoint(note, { signer: cp, closeTime: 1000 });
    const svc = createRenewal({
      objects: localObjectStore({ dir: mkdtempSync(join(tmpdir(), 'legx-nn-')) }),
      retainDays: 1,
      signer: ring.signer,
      tsa: local.client(),
      head: async () => cosigned,
    });
    expect((await svc.run('d')).status).toBe('renewed');

    expect(calls.verify).toBeGreaterThan(0); // verification is the one thing noble does here
    expect(calls.sign).toBe(0);
    expect(calls.keygen).toBe(0);
  });
});
