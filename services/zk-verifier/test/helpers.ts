import type { ObjectStorePort } from '@legx/contracts/ports';
import type { ZkVerifyRequest } from '@legx/contracts/records';
import { tupleHash } from '@legx/core/dealcore';
import type { ZkExpectation } from '@legx/core/zkIdentity';
import { onboardingBoundValue, releaseBoundValue, zkIdentityCommitment } from '@legx/core/zkIdentity';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { vi } from 'vitest';
import { loadSet, type RecordedSet } from '../../../packages/zk/test/fixtures.ts';
import { portRequest } from '../../../packages/zk/test/zkVerifierPort.contract.ts';
import { createZkAdapter } from '../src/adapter.ts';
import { fakeNetwork, RECORDED_AT, RPC_A, RPC_B } from './network.ts';

export { loadSet };

export const SALT = new Uint8Array(32).fill(0x61);
export const demo = {
  profile: 'demo',
  domain: 'legx.app',
  devMode: true,
  rpcUrls: [RPC_A, RPC_B],
  sdkVersion: '0.19.2',
} as const;

/** Installs the fake network as the global fetch and the recorded day as the date. */
export function useFakeNetwork() {
  const net = fakeNetwork();
  const real = globalThis.fetch;
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(RECORDED_AT);
  globalThis.fetch = net.fetch;
  return {
    net,
    restore() {
      globalThis.fetch = real;
      vi.useRealTimers();
    },
  };
}

export const noSleep: { sleep: (ms: number) => Promise<void> } = { sleep: async () => undefined };
export const adapter = (cfg: Record<string, unknown> = {}, deps = noSleep) =>
  createZkAdapter({ ...demo, ...cfg } as never, deps);

const presence = (s: RecordedSet, seal: string) =>
  tupleHash('legx/passport-presence/v1', [
    hexToBytes(seal),
    utf8ToBytes('A'),
    hexToBytes(s.inputs.ledgerHash),
    hexToBytes(s.inputs.lawyerNonce),
  ]);

/** What the deal data requires, for each recorded stage (as core's own tests build them). */
export function expectation(s: RecordedSet, salt = SALT): ZkExpectation {
  const id = loadSet('alice-onboarding').verification.uniqueIdentifier as string;
  return s.request.stage === 'onboarding'
    ? {
        stage: 'onboarding',
        dealId: s.inputs.deal1,
        profile: 'demo',
        cancelAfter: s.inputs.cancelAfter,
        boundValue: onboardingBoundValue(hexToBytes(s.inputs.contractRoot), hexToBytes(s.inputs.slotPub)),
      }
    : {
        stage: 'release',
        dealId: s.inputs.deal1,
        profile: 'demo',
        boundValue: releaseBoundValue(presence(s, s.inputs.dealSeal1)),
        identity: { zkSalt32: salt, commitment: bytesToHex(zkIdentityCommitment(salt, id)) },
        faceMatchOptional: true,
      };
}

export const request = (s: RecordedSet, over: Partial<ZkVerifyRequest> = {}) => portRequest(s, over);

/** An in-memory write-once object store with the port's semantics. */
export function memoryStore(): ObjectStorePort & { readonly objects: Map<string, Uint8Array> } {
  const objects = new Map<string, Uint8Array>();
  return {
    objects,
    async put(key, bytes) {
      const sha = bytesToHex(sha256(bytes)) as never;
      const had = objects.get(key);
      if (had && bytesToHex(sha256(had)) !== sha) return { status: 'conflict' };
      objects.set(key, bytes);
      return { status: had ? 'exists' : 'created', sha256: sha };
    },
    async get(key) {
      return objects.get(key);
    },
    async delete() {
      return { status: 'retained' };
    },
  };
}
