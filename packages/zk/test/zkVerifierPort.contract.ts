// The ZkVerifierPort contract (IMPLEMENTATION P1.17-09): the same cases for the replay fake, the offline SDK adapter
// (test/port.test.ts) and the networked adapter of task 3.11, which imports this file.

import type { ZkVerifierPort } from '@legx/contracts/ports';
import { ZkTrust, type ZkVerifyRequest } from '@legx/contracts/records';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { proofSetBytes } from '../src/verify.ts';
import { loadSet, type RecordedSet } from './fixtures.ts';

/** The port request for a recorded proof set: the stored proofs plus the original query. */
export const portRequest = (s: RecordedSet, over: Partial<ZkVerifyRequest> = {}): ZkVerifyRequest =>
  ({
    stage: s.request.stage,
    domain: s.request.domain,
    scope: s.request.scope,
    devMode: s.request.devMode,
    proofs: s.proofs,
    originalQuery: s.request.originalQuery,
    queryResult: s.queryResult,
    ...over,
  }) as ZkVerifyRequest;

/** A port either returns `verified: false` or rejects for a proof set it cannot accept. */
const outcome = (p: Promise<{ verified: boolean }>) =>
  p.then(
    (r) => (r.verified ? 'verified' : 'not verified'),
    () => 'not verified',
  );

export function zkVerifierPortContract(name: string, makePort: () => ZkVerifierPort) {
  describe(`ZkVerifierPort contract: ${name}`, () => {
    const onboarding = loadSet('alice-onboarding');
    const release = loadSet('alice-release');

    it('a good release proof: verified, with the identifier, the stored scope and domain, and a full trust record', async () => {
      const v = await makePort().verify(portRequest(release));
      expect(v.verified).toBe(true);
      expect(v.uniqueIdentifier).toBe(release.verification.uniqueIdentifier);
      expect(v.uniqueIdentifierType).toBe('NON_SALTED_MOCK');
      expect([v.scope, v.domain]).toEqual([release.request.scope, 'legx.app']);
      expect(v.committedInputs.custom_data).toBe(
        (release.request.originalQuery.bind as { custom_data: string }).custom_data,
      );
      expect(v.proofSha256).toBe(bytesToHex(sha256(proofSetBytes(release.proofs))));
      expect(ZkTrust.safeParse(v.trust).success).toBe(true);
      expect(v.queryResultErrors).toEqual({});
    });

    it('the onboarding proof of the same passport and scope gives the same identifier', async () => {
      const v = await makePort().verify(portRequest(onboarding));
      expect(v.verified).toBe(true);
      expect(v.uniqueIdentifier).toBe(release.verification.uniqueIdentifier);
    });

    it('the same proofs under another deal scope are not verified', async () => {
      const r = portRequest(release, { scope: `legx/v1/${release.inputs.deal2}` });
      expect(await outcome(makePort().verify(r))).toBe('not verified');
    });

    it('one flipped proof byte is not verified (a forged proof)', async () => {
      const proofs = release.proofs.map((p) => ({ ...p }));
      const bind = proofs.find((p) => p.name === 'bind') as { proof: string };
      bind.proof = `${bind.proof.slice(0, 100)}${bind.proof[100] === 'a' ? 'b' : 'a'}${bind.proof.slice(101)}`;
      expect(await outcome(makePort().verify(portRequest(release, { proofs } as never)))).toBe('not verified');
    });
  });
}
