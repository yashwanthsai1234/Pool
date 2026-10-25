// ZK tools for the ledger flow (task 2.9): fresh mock-passport proofs from the vendored headless prover (task 1.17),
// verified through the services adapter (task 3.11) with the real SDK in devMode. The ZKPassport packages are loaded
// from @legx/zk's own node_modules, through CommonJS (a plain ESM import of the SDK fails under Node).
// Source: IMPLEMENTATION.md 2.9; packages/zk/tools/record.ts (the same recipe, with fresh bound values)
import { createRequire } from 'node:module';
import { ZK_DOMAIN, type ZkVerification, type ZkVerifyRequest } from '@legx/contracts/records';
import type { Profile } from '@legx/core/attest';
import { type Builder, offlineQuery, requestConfig } from '@legx/zk/request';
import type { ProofResult, Query, QueryResult } from '@legx/zk/sdk';
import { type ProofSet, proofSetBytes } from '@legx/zk/verify';
import { createZkAdapter, type ZkAdapter } from '@legx/zk-verifier';
import { proveFastMode } from '../../../zk/tools/zk-prove/prove.ts';

const require = createRequire(new URL('../../../zk/package.json', import.meta.url));
const { createRegistryClient } = require('@zkpassport/registry');
const { createMockPassport } = require('@zkpassport/utils/mock-passports');

export interface MockPerson {
  readonly firstName: string;
  readonly lastName: string;
  readonly dateOfBirth: Date;
  readonly expiryDate: Date;
  readonly documentNumber: string;
}
export const MOCK_ALICE: MockPerson = {
  firstName: 'ALICE',
  lastName: 'ONE',
  dateOfBirth: new Date('1990-01-01'),
  expiryDate: new Date('2035-12-31'),
  documentNumber: 'A1111111',
};
export const MOCK_BOB: MockPerson = {
  firstName: 'BOB',
  lastName: 'TWO',
  dateOfBirth: new Date('1985-05-05'),
  expiryDate: new Date('2036-12-31'),
  documentNumber: 'B2222222',
};

export interface Prover {
  readonly rpcUrl: string;
  readonly adapter: ZkAdapter;
  readonly productionAdapter: ZkAdapter;
  readonly passports: Map<MockPerson, unknown>;
  prove(o: {
    person: MockPerson;
    dealId: string;
    stage: 'onboarding' | 'release';
    build: (b: Builder) => Builder;
  }): Promise<ProofSet>;
}

/** The registry client, the demo-profile adapter (devMode on) and a production-profile adapter (devMode off). */
export async function openProver(): Promise<Prover> {
  const registry = createRegistryClient('ethereum_sepolia') as {
    rpcUrl: string;
    getCircuitManifest(): Promise<{ version: string }>;
  };
  const rpcUrl = process.env.SEPOLIA_RPC_URL ?? registry.rpcUrl;
  const manifest = await registry.getCircuitManifest();
  const base = { domain: ZK_DOMAIN, rpcUrls: [rpcUrl], sdkVersion: '0.19.2' } as const;
  const passports = new Map<MockPerson, unknown>();
  return {
    rpcUrl,
    adapter: createZkAdapter({ ...base, profile: 'demo', devMode: true }),
    productionAdapter: createZkAdapter({
      ...base,
      profile: 'production',
      devMode: false,
      rpcUrls: [rpcUrl, 'https://second-provider.legx.invalid/'],
    }),
    passports,
    async prove({ person, dealId, stage, build }) {
      if (!passports.has(person)) passports.set(person, createMockPassport(person));
      const cfg = requestConfig({ dealId, devMode: true });
      const originalQuery = JSON.parse(JSON.stringify(build(offlineQuery(cfg.domain)).done().query)) as Query;
      const { proofs, queryResult } = await proveFastMode({
        passport: passports.get(person) as never,
        query: originalQuery,
        domain: cfg.domain,
        scope: cfg.scope,
        circuitVersion: manifest.version,
        registry: registry as never,
      });
      return {
        request: {
          stage,
          domain: cfg.domain,
          scope: cfg.scope,
          devMode: cfg.devMode,
          validity: cfg.validity,
          originalQuery,
        },
        proofs,
        queryResult: JSON.parse(JSON.stringify(queryResult)) as QueryResult,
      };
    },
  };
}

/** The port request for a proof set. */
export const portRequest = (s: ProofSet, over: Partial<ZkVerifyRequest> = {}): ZkVerifyRequest =>
  ({
    stage: s.request.stage,
    domain: s.request.domain,
    scope: s.request.scope,
    devMode: s.request.devMode,
    proofs: s.proofs as unknown as ProofResult[],
    originalQuery: s.request.originalQuery,
    queryResult: s.queryResult,
    ...over,
  }) as unknown as ZkVerifyRequest;

export type { Profile, ProofSet, ZkVerification };
export { proofSetBytes };
