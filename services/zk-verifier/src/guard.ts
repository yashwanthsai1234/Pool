// The egress guard: during a verification the global fetch may reach only the configured RPC hosts and the circuit
// file hosts. Anything else (the hosted verifier above all) is refused in code; a failure of an allowed host is
// recorded as "the CDN" or "the RPC" so the adapter can retry and name it (P3.11-02, -03, -10, -11).
import { HOSTED_VERIFIER_HOST } from './config.ts';
import { ZkVerifierError } from './errors.ts';

export interface Egress {
  failure: 'cdn' | 'registry' | undefined;
}

export function guardedFetch(
  real: typeof fetch,
  rpcHosts: ReadonlySet<string>,
  allowed: ReadonlySet<string>,
  egress: Egress,
): typeof fetch {
  return async (input, init) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    const host = url.host.toLowerCase();
    if (host === HOSTED_VERIFIER_HOST || !allowed.has(host))
      throw new ZkVerifierError('ZK_EGRESS_BLOCKED', `a request to ${host} is not allowed`);
    const kind = rpcHosts.has(host) ? 'registry' : 'cdn';
    try {
      const res = await real(input, init);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res;
    } catch (e) {
      egress.failure ??= kind;
      throw e;
    }
  };
}
