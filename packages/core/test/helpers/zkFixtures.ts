// The recorded mock-passport proof sets of task 1.17 (packages/zk/fixtures/), read as plain files: core tests never
// load the ZKPassport SDK.
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ZkVerification } from '@legx/contracts/records';

const DIR = join(dirname(fileURLToPath(import.meta.url)), '../../../zk/fixtures');

export interface ZkSet {
  readonly inputs: Readonly<
    Record<
      'deal1' | 'deal2' | 'contractRoot' | 'slotPub' | 'dealSeal1' | 'dealSeal2' | 'ledgerHash' | 'lawyerNonce',
      string
    >
  > & {
    readonly cancelAfter: number;
  };
  readonly request: {
    readonly scope: string;
    readonly domain: string;
    readonly originalQuery: Record<string, unknown>;
  };
  readonly proofs: readonly { readonly name: string; readonly committedInputs?: object }[];
  readonly queryResult: Record<string, unknown>;
  readonly verification: ZkVerification;
}

export const zkSet = (name: string): ZkSet =>
  JSON.parse(readFileSync(join(DIR, 'sets', `${name}.json`), 'utf8')) as ZkSet;

/** Every recorded circuit file and manifest, by its file name. */
export const zkFiles = (): Map<string, Uint8Array> =>
  new Map(readdirSync(join(DIR, 'files')).map((f) => [f, new Uint8Array(readFileSync(join(DIR, 'files', f)))]));
