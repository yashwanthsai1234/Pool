// The recorded demo proofs (demo/recorded-proofs/): fallback when the ZKPassport CDN, Sepolia RPC or a phone is down.
// They are devMode mock-passport proofs, so they exist for the DEMO profile only; production refuses them.
// Source: DESIGN 6.10; build/DECISIONS.md OD-34; services/zk-verifier DEVMODE_REFUSED
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

export const RECORDED_DIR = resolve(import.meta.dirname, '../../../demo/recorded-proofs');
export type RecordedName = 'alice-onboarding' | 'alice-release' | 'bob-release';
export type DemoProfile = 'demo' | 'production';

export class RecordedRefused extends Error {
  readonly code = 'RECORDED_PROOFS_DEMO_ONLY';
  constructor() {
    super('recorded proofs are devMode mock-passport proofs: refused outside the demo profile');
  }
}

/** One recorded proof set. `profile` must be `demo`; anything else throws before a file is read. */
export function loadRecorded(name: RecordedName, profile: DemoProfile, dir: string = RECORDED_DIR) {
  if (profile !== 'demo') throw new RecordedRefused();
  const rec = JSON.parse(readFileSync(join(dir, 'sets', `${name}.json`), 'utf8')) as {
    request: { devMode: boolean };
    proofs: unknown;
    queryResult: unknown;
    recordedAt: string;
  };
  if (!rec.request.devMode) throw new RecordedRefused();
  return {
    source: 'recorded' as const,
    recordedAt: rec.recordedAt,
    request: rec.request,
    proofs: rec.proofs,
    queryResult: rec.queryResult,
  };
}
