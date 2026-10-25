// The independent Python reference vectors (task 5.3a), written from DESIGN alone: tools/py-ref/vectors/*.json.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export type PyVector<I = Record<string, unknown>, O = string> = { fn: string; inputs: I; output: O };

const DIR = join(dirname(fileURLToPath(import.meta.url)), '../../../../tools/py-ref/vectors');

/** Every vector in `tools/py-ref/vectors/<file>.json`, in file order. */
export const pyVectors = <I = Record<string, unknown>, O = string>(file: string): PyVector<I, O>[] =>
  JSON.parse(readFileSync(join(DIR, `${file}.json`), 'utf8')) as PyVector<I, O>[];

/** The vector named `fn` in `tools/py-ref/vectors/<file>.json`; throws if it is missing, so a renamed vector fails loudly. */
export function pyVector<I = Record<string, string>, O = string>(file: string, fn: string): PyVector<I, O> {
  const v = pyVectors<I, O>(file).find((x) => x.fn === fn);
  if (!v) throw new Error(`no vector ${fn} in ${file}.json`);
  return v;
}
