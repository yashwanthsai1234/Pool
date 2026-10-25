// A/B: compares what the repository suite observed on PGlite and on Postgres 18 (refusal codes and messages, the schema
// snapshot, outbox counts). Run both test projects first. Usage: node packages/db/scripts/ab-compare.ts
import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';

const read = (e: string) =>
  JSON.parse(readFileSync(new URL(`../../../build/tmp/3.1/ab-${e}.json`, import.meta.url), 'utf8')) as Record<
    string,
    unknown
  >;
const a = read('pglite');
const b = read('pg');
const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
let diff = 0;
for (const k of keys) {
  const same = isDeepStrictEqual(a[k], b[k]);
  if (!same) diff++;
  console.log(`${same ? 'same' : 'DIFF'}  ${k}`);
  if (!same) console.log(`  pglite: ${JSON.stringify(a[k])}\n  pg:     ${JSON.stringify(b[k])}`);
}
console.log(`${keys.length} observations, ${diff} differences`);
process.exit(diff === 0 ? 0 : 1);
