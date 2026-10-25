// Builds bundles that carry recorded zero-knowledge proofs (task 1.17 sets) in the files the CLI reads (build/ISSUES.md 3).
import { trustRecordOf } from '@legx/core/zkIdentity';
import { bodiesOf, loadSet, type RecordedSet } from '../../../packages/zk/test/fixtures.ts';
import { type ZipFile, zip } from '../../../services/evidence/src/zip.ts';
import { makeBundle, resign, type TestBundle } from './helpers.ts';

export const enc = (x: unknown) => new TextEncoder().encode(JSON.stringify(x));
export let b: TestBundle;
export const ready = async () => {
  b = await makeBundle();
};

export const recordFiles = (name: string, s: RecordedSet, trust: Record<string, unknown> = {}) => ({
  [`zk/proofs/${name}.json`]: enc({ side: name[0], stage: 'release' }),
  [`zk/reverify/${name}.json`]: enc({
    set: { request: s.request, proofs: s.proofs, queryResult: s.queryResult },
    verification: s.verification,
    loaders: s.loaders,
    bodies: Object.fromEntries(bodiesOf(s)),
  }),
  ...trust,
});
const trustFile = (rows: { side: string; stage: string; roots: object }[]) =>
  enc(rows.map((r) => ({ side: r.side, stage: r.stage, registry_roots: r.roots })));
export const rootsOf = (s: RecordedSet, over: Record<string, unknown> = {}) => ({
  ...trustRecordOf(s.verification),
  loader_files: {},
  ...over,
});

export const alice = loadSet('alice-release');
export const bob = loadSet('bob-release');
export async function withZk(
  extra: Record<string, Uint8Array | null>,
  trust: object[] = [{ side: 'A', stage: 'release', roots: rootsOf(alice) }],
) {
  const files: ZipFile[] = await resign(b, {
    ...recordFiles('A-release', alice),
    ...recordFiles('B-release', bob),
    'zk/trust_records.json': trustFile(trust as never),
    ...extra,
  });
  return zip(files);
}
