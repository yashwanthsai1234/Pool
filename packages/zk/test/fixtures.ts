// The recorded mock-passport fixtures (packages/zk/fixtures/, written by tools/record.ts).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ZkVerification } from '@legx/contracts/records';
import type { ProofResult, QueryResult } from '../src/sdk.ts';
import type { RecordedLoaders, ZkRequestRecord } from '../src/verify.ts';

export const FIXTURES = join(import.meta.dirname, '../fixtures');

/** The deal values the fixtures bind; tools/record.ts writes them into every set. */
export const FIXTURE_INPUTS = {
  deal1: '0192f0a0-0000-7000-8000-000000000001',
  deal2: '0192f0a0-0000-7000-8000-000000000002',
  contractRoot: '22'.repeat(32),
  slotPub: `ed${'33'.repeat(32)}`,
  cancelAfter: Date.UTC(2030, 0, 1) / 1000,
  dealSeal1: '55'.repeat(32),
  dealSeal2: '56'.repeat(32),
  ledgerHash: '51'.repeat(32),
  lawyerNonce: '52'.repeat(32),
} as const;

export const SET_NAMES = [
  'alice-onboarding',
  'alice-release',
  'alice-release-facematch',
  'alice-deal2',
  'bob-release',
  'alice-other-domain',
  'expired',
] as const;
export type SetName = (typeof SET_NAMES)[number];

export interface RecordedSet {
  readonly name: SetName;
  readonly note: string;
  readonly recordedAt: string;
  readonly versions: { sdk: string; utils: string; registry: string };
  readonly inputs: typeof FIXTURE_INPUTS;
  readonly request: ZkRequestRecord;
  readonly proofs: ProofResult[];
  readonly queryResult: QueryResult;
  readonly verification: ZkVerification;
  readonly loaders: RecordedLoaders;
}

/** `manifest/0.21.1` -> `manifest-0.21.1.json`; `circuit/0xab..` -> `circuit-0xab...json`. */
export const fileName = (key: string) => `${key.replace('/', '-')}.json`;

export const loadSet = (name: SetName): RecordedSet =>
  JSON.parse(readFileSync(join(FIXTURES, 'sets', `${name}.json`), 'utf8')) as RecordedSet;

/** The recorded file bodies one set needs, read from disk. */
export const bodiesOf = (set: RecordedSet): Map<string, string> =>
  new Map(Object.keys(set.loaders.files).map((k) => [k, readFileSync(join(FIXTURES, 'files', fileName(k)), 'utf8')]));
