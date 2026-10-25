// Records the mock-passport fixtures in packages/zk/fixtures/ (IMPLEMENTATION 1.17 "Test first").
// Run on demand and in the nightly job, never on a pull request: it needs Sepolia RPC and ZKPassport's CDN.
//   node packages/zk/tools/record.ts            (SEPOLIA_RPC_URL replaces the registry's built-in endpoint)
// It makes ZKR mock passports with createMockPassport (@zkpassport/utils 0.40.0-beta.2), builds each request with
// src/request.ts, proves it with the vendored headless prover (tools/zk-prove/), verifies it with the SDK while
// recording the registry answers and circuit files (src/verify.ts), and writes one file per proof set.
import { createHash } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { tupleHash } from '@legx/core/dealcore';
import { hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import {
  type Builder,
  type ContractFacts,
  offlineQuery,
  onboardingQuery,
  releaseQuery,
  requestConfig,
} from '../src/request.ts';
import { installedVersions, PINNED, type Query } from '../src/sdk.ts';
import { verifyAndRecord } from '../src/verify.ts';
import { fileName, FIXTURE_INPUTS as IN } from '../test/fixtures.ts';
import { proveFastMode } from './zk-prove/prove.ts';

const require = createRequire(import.meta.url);
const { createRegistryClient } = require('@zkpassport/registry');
const { createMockPassport } = require('@zkpassport/utils/mock-passports');

const OUT = join(import.meta.dirname, '../fixtures');
const FACTS: ContractFacts = { minAge: 18 };

const presenceMsg = (dealSeal: string, side: string) =>
  tupleHash('legx/passport-presence/v1', [
    hexToBytes(dealSeal),
    utf8ToBytes(side),
    hexToBytes(IN.ledgerHash),
    hexToBytes(IN.lawyerNonce),
  ]);

const PASSPORTS = {
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
  expired: {
    firstName: 'EVE',
    lastName: 'OLD',
    dateOfBirth: new Date('1980-02-02'),
    expiryDate: new Date('2020-01-01'),
    documentNumber: 'E3333333',
  },
} as const;

type Spec = {
  name: string;
  note: string;
  passport: keyof typeof PASSPORTS;
  stage: 'onboarding' | 'release';
  dealId: string;
  domain?: string;
  query: (b: Builder) => Builder;
  provedAt?: number;
};

const release = (dealSeal: string, faceMatch: boolean) => (b: Builder) =>
  releaseQuery(b, { facts: FACTS, presenceMsg: presenceMsg(dealSeal, 'A'), faceMatch, dealAllowsNoFaceMatch: true });

const SPECS: Spec[] = [
  {
    name: 'alice-onboarding',
    note: 'onboarding proof: age, the four disclosed facts, expiry after CancelAfter + 30 days, bound contractRoot and slotPub',
    passport: 'alice',
    stage: 'onboarding',
    dealId: IN.deal1,
    query: (b) =>
      onboardingQuery(b, {
        facts: FACTS,
        contractRoot: hexToBytes(IN.contractRoot),
        slotPub: hexToBytes(IN.slotPub),
        cancelAfter: IN.cancelAfter,
      }),
  },
  {
    name: 'alice-release',
    note: 'release proof, same passport, domain and scope; the face match is off because no headless prover can make one',
    passport: 'alice',
    stage: 'release',
    dealId: IN.deal1,
    query: release(IN.dealSeal1, false),
  },
  {
    name: 'alice-release-facematch',
    note: 'release request with the strict face match; the proof set has no face match proof, so verification fails',
    passport: 'alice',
    stage: 'release',
    dealId: IN.deal1,
    query: release(IN.dealSeal1, true),
  },
  {
    name: 'alice-deal2',
    note: 'same passport and domain, second scope',
    passport: 'alice',
    stage: 'release',
    dealId: IN.deal2,
    query: release(IN.dealSeal2, false),
  },
  {
    name: 'bob-release',
    note: 'second passport, same domain and scope as alice',
    passport: 'bob',
    stage: 'release',
    dealId: IN.deal1,
    query: release(IN.dealSeal1, false),
  },
  {
    name: 'alice-other-domain',
    note: 'same passport and scope under a second domain (other.app), verified under that domain',
    passport: 'alice',
    stage: 'release',
    dealId: IN.deal1,
    domain: 'other.app',
    query: release(IN.dealSeal1, false),
  },
  {
    name: 'expired',
    note: 'passport expired on 2020-01-01, proved with the clock at 2019-06-01; the stale expiry check fails',
    passport: 'expired',
    stage: 'release',
    dealId: IN.deal1,
    query: release(IN.dealSeal1, false),
    provedAt: Date.UTC(2019, 5, 1) / 1000,
  },
];

async function main() {
  const versions = installedVersions();
  if (JSON.stringify(versions) !== JSON.stringify(PINNED)) throw new Error(`installed ${JSON.stringify(versions)}`);
  const registry = createRegistryClient('ethereum_sepolia');
  const rpcUrl = process.env.SEPOLIA_RPC_URL ?? (registry as { rpcUrl: string }).rpcUrl;
  const manifest = await registry.getCircuitManifest();
  for (const dir of ['sets', 'files']) {
    rmSync(join(OUT, dir), { recursive: true, force: true });
    mkdirSync(join(OUT, dir), { recursive: true });
  }
  for (const spec of SPECS) {
    const cfg = requestConfig({ dealId: spec.dealId, devMode: true });
    const domain = spec.domain ?? cfg.domain; // only the other-domain fixture leaves legx.app
    // The stored form: JSON, as the request record keeps it
    const originalQuery = JSON.parse(JSON.stringify(spec.query(offlineQuery(domain)).done().query)) as Query;
    const t0 = Date.now();
    const { proofs, queryResult } = await proveFastMode({
      passport: createMockPassport(PASSPORTS[spec.passport]),
      query: originalQuery,
      domain,
      scope: cfg.scope,
      circuitVersion: manifest.version,
      registry,
      ...(spec.provedAt ? { now: spec.provedAt } : {}),
    });
    const request = {
      stage: spec.stage,
      domain,
      scope: cfg.scope,
      devMode: cfg.devMode,
      validity: cfg.validity,
      originalQuery,
    };
    const set = { request, proofs, queryResult: JSON.parse(JSON.stringify(queryResult)) };
    const { verification, loaders, bodies } = await verifyAndRecord(set, rpcUrl);
    for (const [key, body] of bodies) writeFileSync(join(OUT, 'files', fileName(key)), body);
    const recordedAt = new Date().toISOString();
    const record = {
      name: spec.name,
      note: spec.note,
      recordedAt,
      versions,
      inputs: IN,
      ...set,
      verification,
      loaders,
    };
    writeFileSync(join(OUT, 'sets', `${spec.name}.json`), `${JSON.stringify(record, null, 1)}\n`);
    process.stdout.write(`${spec.name}: ${Date.now() - t0} ms, verified=${verification.verified}\n`);
  }
  const sums = ['sets', 'files'].flatMap((dir) =>
    readdirSync(join(OUT, dir))
      .sort()
      .map(
        (f) =>
          `${createHash('sha256')
            .update(readFileSync(join(OUT, dir, f)))
            .digest('hex')}  ${dir}/${f}`,
      ),
  );
  writeFileSync(join(OUT, 'SHA256SUMS'), `${sums.join('\n')}\n`);
}

await main();
process.exit(0); // bb.js keeps worker handles open
