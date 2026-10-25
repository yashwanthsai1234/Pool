// Downloads the post-quantum test vectors from pinned commits and writes the subsets in vectors/pq/.
// Usage: node packages/core/scripts/pq-vectors.ts
// Source: https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files
// Source: https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem/blob/984c2f7a93b8f8d8f8073ebb53f9f4ce50b5babd/spec/test-vectors.json
// Source: https://github.com/hupe1980/doubleentry/tree/2d76ec5641d0adf7bdd1b144319d855a1dc5cd9d/tests/vectors/c2sp
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '../vectors/pq');
const ACVP =
  'https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files';
const XWING =
  'https://raw.githubusercontent.com/dconnolly/draft-connolly-cfrg-xwing-kem/984c2f7a93b8f8d8f8073ebb53f9f4ce50b5babd/spec/test-vectors.json';
const C2SP =
  'https://raw.githubusercontent.com/hupe1980/doubleentry/2d76ec5641d0adf7bdd1b144319d855a1dc5cd9d/tests/vectors/c2sp';

interface Group {
  tgId: number;
  tests: Record<string, unknown>[];
}

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.text();
}

// Keeps the named groups (and at most `max` tests of each), and drops the fields no test reads.
async function acvp(folder: string, out: string, keep: Record<number, number>, drop: string[] = []): Promise<void> {
  const url = `${ACVP}/${folder}/internalProjection.json`;
  const doc = JSON.parse(await fetchText(url)) as { testGroups: Group[] };
  const testGroups = doc.testGroups
    .filter((g) => g.tgId in keep)
    .map((g) => ({
      ...g,
      tests: g.tests
        .slice(0, keep[g.tgId])
        .map((t) => Object.fromEntries(Object.entries(t).filter(([k]) => !drop.includes(k)))),
    }));
  writeFileSync(join(OUT, 'acvp', out), `${JSON.stringify({ source: url, ...doc, testGroups }, null, 1)}\n`);
}

mkdirSync(join(OUT, 'acvp'), { recursive: true });
mkdirSync(join(OUT, 'c2sp'), { recursive: true });
// keyGen: ML-DSA-44 (tg 1) and ML-DSA-65 (tg 2).
await acvp('ML-DSA-keyGen-FIPS204', 'ml-dsa-keygen.json', { 1: 5, 2: 10 });
// sigVer: ML-DSA-44 external pure (tg 1), ML-DSA-65 external pure (tg 3), ML-DSA-65 internal with external mu (tg 9).
await acvp('ML-DSA-sigVer-FIPS204', 'ml-dsa-sigver.json', { 1: 15, 3: 15, 9: 15 }, ['sk']);
// sigGen, deterministic: ML-DSA-65 external pure (tg 3) and ML-DSA-65 external mu (tg 9).
await acvp('ML-DSA-sigGen-FIPS204', 'ml-dsa-siggen.json', { 3: 5, 9: 5 });
// ML-KEM-768 only: keyGen (tg 2), encapsulation (tg 2), decapsulation (tg 5).
await acvp('ML-KEM-keyGen-FIPS203', 'ml-kem-keygen.json', { 2: 10 });
await acvp('ML-KEM-encapDecap-FIPS203', 'ml-kem-encapdecap.json', { 2: 10, 5: 10 });
writeFileSync(join(OUT, 'xwing-draft-11.json'), await fetchText(XWING));
for (const f of ['policies/ml-dsa.txt', 'policies/verdicts/ml-dsa-counted-by-go.txt', 'keys/signed-note-example.txt']) {
  writeFileSync(join(OUT, 'c2sp', f.split('/').pop() as string), await fetchText(`${C2SP}/${f}`));
}
