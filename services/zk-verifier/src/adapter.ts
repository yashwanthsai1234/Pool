// The production ZkVerifierPort: the pinned SDK in local mode, registry roots from at least two RPC providers that
// must agree, retries when the CDN or an RPC is down, and the profile rules. The proof work is task 1.17's
// verifyAndRecord; the result checks are core's checkTrustRecord / checkZkResult. This file adds only the network
// policy around them (DESIGN 6.10 "Trust anchors").
// Source: https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_call (the second provider repeats the recorded calls)

import type { ZkVerifierPort } from '@legx/contracts/ports';
import { ZK_DOMAIN, type ZkVerification, type ZkVerifyRequest } from '@legx/contracts/records';
import { checkTrustRecord } from '@legx/core/attest';
import { trustRecordOf } from '@legx/core/zkIdentity';
import type { ProofResult, Query, QueryResult } from '@legx/zk/sdk';
import { type FileBodies, type ProofSet, type RecordedLoaders, verifyAndRecord } from '@legx/zk/verify';
import { type CheckedConfig, checkConfig, type ZkVerifierConfig } from './config.ts';
import { ZkVerifierError } from './errors.ts';
import { type Egress, guardedFetch } from './guard.ts';
import { withRetry } from './retry.ts';

export interface Verified {
  readonly set: ProofSet;
  readonly verification: ZkVerification;
  readonly loaders: RecordedLoaders;
  readonly bodies: FileBodies;
}

export interface ZkAdapter extends ZkVerifierPort {
  /** The port result plus what the trust record store needs. */
  verifyDetailed(request: ZkVerifyRequest): Promise<Verified>;
  readonly config: CheckedConfig;
}

export interface AdapterDeps {
  readonly sleep?: (ms: number) => Promise<void>;
  readonly now?: () => number;
}

/** One day, as task 1.17's requestConfig sets it; the port request does not carry the validity. */
const VALIDITY_SECONDS = 86400;

const toSet = (r: ZkVerifyRequest): ProofSet => ({
  request: {
    stage: r.stage,
    domain: r.domain,
    scope: r.scope,
    devMode: r.devMode,
    validity: VALIDITY_SECONDS,
    originalQuery: r.originalQuery as Query,
  },
  // The port types omit `committedInputs`, which the SDK needs (1.17 request to task 1.2); they are present at run time.
  proofs: r.proofs as unknown as ProofResult[],
  queryResult: r.queryResult as unknown as QueryResult,
});

async function rpc(url: string, method: string, params: unknown[]): Promise<unknown> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const body = (await res.json()) as { result?: unknown; error?: { message: string } };
  if (body.error || body.result === undefined) throw new Error(`${method}: ${body.error?.message ?? 'no result'}`);
  return body.result;
}

/** A second provider must give the same chain, the same block hash and the same answer to every recorded call. */
async function confirm(url: string, l: RecordedLoaders): Promise<void> {
  const at = `0x${l.block.number.toString(16)}`;
  const block = (await rpc(url, 'eth_getBlockByNumber', [at, false])) as { hash?: string } | null;
  const same =
    Number(await rpc(url, 'eth_chainId', [])) === l.chainId &&
    block?.hash === l.block.hash &&
    (await Promise.all(l.rpc.map((c) => rpc(url, 'eth_call', [{ to: c.to, data: c.data }, at])))).every(
      (r, i) => r === l.rpc[i]?.result,
    );
  if (!same) throw new ZkVerifierError('ZK_ROOTS_DISAGREE', `${new URL(url).host} disagrees with the first provider`);
}

// verify() reads through the global fetch, so one verification runs at a time (as verifyAndRecord does too).
let queue: Promise<unknown> = Promise.resolve();
const exclusive = <T>(f: () => Promise<T>): Promise<T> => {
  const run = queue.then(f, f);
  queue = run.catch(() => undefined);
  return run;
};

export function createZkAdapter(cfg: ZkVerifierConfig, deps: AdapterDeps = {}): ZkAdapter {
  const config = checkConfig(cfg);
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const [primary, ...others] = config.rpcUrls as [string, ...string[]];

  const unavailable = (kind: 'cdn' | 'registry', cause: unknown) =>
    new ZkVerifierError(
      kind === 'cdn' ? 'ZK_CDN_UNAVAILABLE' : 'ZK_REGISTRY_UNAVAILABLE',
      kind === 'cdn' ? 'the circuit file host did not answer' : 'the registry RPC did not answer',
      undefined,
      cause,
    );

  async function verifyDetailed(r: ZkVerifyRequest): Promise<Verified> {
    if (r.domain !== ZK_DOMAIN)
      throw new ZkVerifierError('ZK_REFUSED', 'proof made under another domain', 'WRONG_DOMAIN');
    if (config.profile === 'production' && r.devMode)
      throw new ZkVerifierError('ZK_REFUSED', 'devMode proof in production', 'DEVMODE_REFUSED');
    const set = toSet(r);
    return withRetry(() => exclusive(() => attempt(set)), {
      attempts: config.attempts,
      baseMs: config.baseMs,
      sleep,
    });
  }

  /** The SDK swallows a failed registry or file read and reports verified:false; the guard saw the real cause. */
  async function attempt(set: ProofSet): Promise<Verified> {
    const egress: Egress = { failure: undefined };
    const real = globalThis.fetch;
    globalThis.fetch = guardedFetch(real, config.rpcHosts, config.allowedHosts, egress);
    try {
      const out = await verifyAndRecord(set, primary, deps.now?.());
      if (egress.failure) throw unavailable(egress.failure, undefined);
      for (const url of others) await confirm(url, out.loaders);
      const trust = checkTrustRecord(trustRecordOf(out.verification), config.profile);
      if (out.verification.verified && !trust.ok)
        throw new ZkVerifierError('ZK_REFUSED', 'the trust record is refused in this profile', trust.code);
      return { set, ...out };
    } catch (e) {
      if (e instanceof ZkVerifierError) throw e;
      if (egress.failure) throw unavailable(egress.failure, e);
      throw e;
    } finally {
      globalThis.fetch = real;
    }
  }

  return {
    config,
    verifyDetailed,
    async verify(r) {
      return (await verifyDetailed(r)).verification;
    },
  };
}
