// `node tools/zk-prove/cli.ts --person alice|bob --deal-id <uuid> --presence-msg <hex> [--out file] [--recorded]`
// Makes a FRESH release proof (mock passport, devMode, face match off) bound to a presenceMsg, with the vendored
// headless prover (packages/zk/tools/zk-prove). Needs Sepolia RPC (SEPOLIA_RPC_URL) and ZKPassport's circuit CDN.
// If those fail, or with --recorded, it prints the recorded proof from demo/recorded-proofs (source "recorded": its
// bound value is NOT this presenceMsg, so it only serves the demo profile).
// Source: packages/zk/tools/record.ts (same recipe); IMPLEMENTATION 1.17
import { writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { parseArgs } from 'node:util';
import { hexToBytes } from '@noble/hashes/utils.js';
import { offlineQuery, releaseQuery, requestConfig } from '../../packages/zk/src/request.ts';
import type { Query } from '../../packages/zk/src/sdk.ts';
import { proveFastMode } from '../../packages/zk/tools/zk-prove/prove.ts';
import { loadRecorded } from './src/recorded.ts';

const PEOPLE = {
  alice: {
    firstName: 'ALICE',
    lastName: 'ONE',
    dateOfBirth: new Date('1990-01-01'),
    expiryDate: new Date('2035-12-31'),
    documentNumber: 'A1111111',
  },
  bob: {
    firstName: 'BOB',
    lastName: 'TWO',
    dateOfBirth: new Date('1985-05-05'),
    expiryDate: new Date('2036-12-31'),
    documentNumber: 'B2222222',
  },
} as const;

export async function proveFresh(person: keyof typeof PEOPLE, dealId: string, presenceMsg: Uint8Array) {
  const require = createRequire(new URL('../../packages/zk/package.json', import.meta.url));
  const { createRegistryClient } = require('@zkpassport/registry');
  const { createMockPassport } = require('@zkpassport/utils/mock-passports');
  const registry = createRegistryClient('ethereum_sepolia');
  const manifest = await registry.getCircuitManifest();
  const cfg = requestConfig({ dealId, devMode: true });
  const originalQuery = JSON.parse(
    JSON.stringify(
      releaseQuery(offlineQuery(cfg.domain), {
        facts: { minAge: 18 },
        presenceMsg,
        faceMatch: false,
        dealAllowsNoFaceMatch: true,
      }).done().query,
    ),
  ) as Query;
  const { proofs, queryResult } = await proveFastMode({
    passport: createMockPassport(PEOPLE[person]),
    query: originalQuery,
    domain: cfg.domain,
    scope: cfg.scope,
    circuitVersion: manifest.version,
    registry,
  });
  const request = {
    stage: 'release',
    domain: cfg.domain,
    scope: cfg.scope,
    devMode: true,
    validity: cfg.validity,
    originalQuery,
  };
  return { source: 'fresh' as const, request, proofs, queryResult: JSON.parse(JSON.stringify(queryResult)) };
}

if (import.meta.main) {
  const { values: v } = parseArgs({
    options: {
      person: { type: 'string' },
      'deal-id': { type: 'string' },
      'presence-msg': { type: 'string' },
      out: { type: 'string' },
      recorded: { type: 'boolean' },
    },
  });
  const person = v.person as keyof typeof PEOPLE;
  if (!(person in PEOPLE)) throw new Error('--person alice|bob');
  let out: unknown;
  if (v.recorded) out = loadRecorded(`${person}-release`, 'demo');
  else {
    if (!v['deal-id'] || !/^[0-9a-f]{64}$/.test(v['presence-msg'] ?? ''))
      throw new Error('--deal-id and --presence-msg (64 hex) required');
    try {
      out = await proveFresh(person, v['deal-id'], hexToBytes(v['presence-msg'] as string));
    } catch (e) {
      process.stderr.write(`fresh proof failed (${(e as Error).message}); falling back to the recorded proof\n`);
      out = loadRecorded(`${person}-release`, 'demo');
    }
  }
  const text = `${JSON.stringify(out)}\n`;
  if (v.out) writeFileSync(v.out, text);
  else process.stdout.write(text);
  process.stderr.write(`zk-prove: ${(out as { source: string }).source} proof for ${person}\n`);
}
