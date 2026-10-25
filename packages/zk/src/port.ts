// ZkVerifierPort implementations without a network (IMPLEMENTATION P1.17-09; the port is in @legx/contracts):
// the replay fake serves recorded results; the offline adapter runs the real SDK on recorded loaders. Task 3.11
// builds the networked production adapter on verifyAndRecord and runs the same contract test against it.

import type { ZkVerifierPort } from '@legx/contracts/ports';
import type { ZkVerification, ZkVerifyRequest } from '@legx/contracts/records';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import type { ProofResult, Query, QueryResult } from './sdk.ts';
import {
  type FileBodies,
  type ProofSet,
  proofSetBytes,
  type RecordedLoaders,
  sdkVerifyOffline,
  toVerification,
} from './verify.ts';

/** One day, as requestConfig sets it; the port request does not carry the validity. */
const VALIDITY_SECONDS = 86400;

// The port request types proofs without `committedInputs`, which the SDK needs (see the status file's request to
// task 1.2); the objects carry them at run time.
const proofSetOf = (r: ZkVerifyRequest): ProofSet => ({
  request: {
    stage: r.stage,
    domain: r.domain,
    scope: r.scope,
    devMode: r.devMode,
    validity: VALIDITY_SECONDS,
    originalQuery: r.originalQuery as Query,
  },
  proofs: r.proofs as unknown as ProofResult[],
  queryResult: r.queryResult as unknown as QueryResult,
});

const keyOf = (r: { proofSha256: string; scope: string; domain: string }) => `${r.proofSha256}|${r.scope}|${r.domain}`;

/** The fake: the recorded result for the same proof set, scope and domain; anything else is not a recorded result. */
export function replayZkVerifier(recorded: readonly ZkVerification[]): ZkVerifierPort {
  const byKey = new Map(recorded.map((v) => [keyOf(v), v]));
  return {
    async verify(r) {
      const proofSha256 = bytesToHex(sha256(proofSetBytes(proofSetOf(r).proofs)));
      const hit = byKey.get(keyOf({ proofSha256, scope: r.scope, domain: r.domain }));
      if (!hit) throw new Error('ZK_RESULT_MISSING');
      return hit;
    },
  };
}

/** The real SDK, offline: every registry answer and circuit file comes from one recording. */
export function offlineZkVerifier(
  loaders: RecordedLoaders,
  bodies: FileBodies,
  now: () => number = Date.now,
): ZkVerifierPort {
  return {
    async verify(r) {
      const set = proofSetOf(r);
      return toVerification(set, await sdkVerifyOffline(set, loaders, bodies, now()), loaders);
    },
  };
}
