// Profiles and ports (IMPLEMENTATION 3.7, P3.7-05, P3.7-07). Every outside dependency of the server is a named port with
// an implementation. A demo implementation in the production profile is a silent security hole, so the production
// profile refuses to start when ANY demo port is configured: by a `LEGX_DEMO_*` variable, by a port marked `demo`, by a
// ZK adapter in dev mode, with a Sepolia RPC, or with a mock identifier type.
// Source: IMPLEMENTATION 3.6 "Think hard" (demo implementations refuse to exist outside the demo profile)
import { Profile } from '@legx/contracts/values';
import type { z } from 'zod';

export type ProfileName = z.infer<typeof Profile>;

/** One port of the composed server, as `GET /health` reports it. */
export interface PortSpec {
  /** The implementation in use, for example `file` or `kms`. */
  readonly impl: string;
  /** True for an implementation that exists only for the demo profile. */
  readonly demo: boolean;
  /** Probes the port; omitted means "configured is enough". A throw or `false` reports `down`. */
  readonly check?: () => Promise<boolean> | boolean;
}

/** The ZK adapter's settings that production forbids (P3.7-07). */
export interface ZkSettings {
  readonly devMode: boolean;
  readonly rpcUrls: readonly string[];
  /** The identifier type of the proofs the deployment accepts, if it is pinned (`NON_SALTED_MOCK` is a mock). */
  readonly identifierType?: string;
}

export const DEMO_ENV_PREFIX = 'LEGX_DEMO_';

export type ProfileViolationCode =
  | 'DEMO_PORT'
  | 'DEMO_ENV'
  | 'ZK_DEV_MODE'
  | 'ZK_SEPOLIA'
  | 'ZK_MOCK'
  | 'AGENTS_IN_PROCESS';

export class ProfileViolation extends Error {
  override readonly name = 'ProfileViolation';
  readonly code: ProfileViolationCode;
  readonly detail: readonly string[];
  constructor(code: ProfileViolationCode, detail: readonly string[]) {
    super(`production profile refuses to start: ${code} (${detail.join(', ')})`);
    this.code = code;
    this.detail = detail;
  }
}

export interface ProfileInput {
  readonly profile: ProfileName;
  readonly ports: Readonly<Record<string, PortSpec>>;
  readonly zk?: ZkSettings;
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** True when the recovery agent or the firm co-signer would run inside this process. */
  readonly agentsMounted?: boolean;
}

/** Throws `ProfileViolation` when the production profile meets any demo setting. The demo profile accepts everything. */
export function assertProfile(i: ProfileInput): void {
  if (i.profile !== 'production') return;
  const demoEnv = Object.keys(i.env ?? {}).filter((k) => k.startsWith(DEMO_ENV_PREFIX) && i.env?.[k] !== undefined);
  if (demoEnv.length > 0) throw new ProfileViolation('DEMO_ENV', demoEnv);
  const demoPorts = Object.entries(i.ports)
    .filter(([, p]) => p.demo)
    .map(([name, p]) => `${name}=${p.impl}`);
  if (demoPorts.length > 0) throw new ProfileViolation('DEMO_PORT', demoPorts);
  if (i.zk?.devMode) throw new ProfileViolation('ZK_DEV_MODE', ['zk.devMode']);
  const sepolia = (i.zk?.rpcUrls ?? []).filter((u) => /sepolia/i.test(u));
  if (sepolia.length > 0) throw new ProfileViolation('ZK_SEPOLIA', sepolia);
  if (i.zk?.identifierType !== undefined && /mock/i.test(i.zk.identifierType))
    throw new ProfileViolation('ZK_MOCK', [i.zk.identifierType]);
  // The agent holds share 3 and the firm HSM holds share 2: running them in the coordinator's process defeats the split.
  if (i.agentsMounted) throw new ProfileViolation('AGENTS_IN_PROCESS', ['recovery-agent', 'firm-cosigner']);
}

/** Reads `LEGX_PROFILE`. An unset or unknown value is production (the safe default, as `assertDemoProfile` treats it). */
export function profileFromEnv(env: Readonly<Record<string, string | undefined>>): ProfileName {
  const p = Profile.safeParse(env.LEGX_PROFILE);
  return p.success ? p.data : 'production';
}

const SEPOLIA_CHAIN_ID = 11155111n;

/**
 * Production asks each ZK RPC for `eth_chainId` and refuses Sepolia, so a Sepolia node behind a URL without the word
 * "sepolia" is caught too. An unreachable node or a malformed answer fails closed.
 * Source: https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_chainid
 */
export async function assertNotSepoliaChain(
  profile: ProfileName,
  rpcUrls: readonly string[],
  doFetch: typeof fetch = fetch,
): Promise<void> {
  if (profile !== 'production') return;
  const bad: string[] = [];
  for (const url of rpcUrls) {
    const res = await doFetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }),
    });
    const { result } = (await res.json()) as { result?: unknown };
    if (typeof result !== 'string' || !/^0x[0-9a-f]+$/i.test(result))
      throw new Error(`eth_chainId from ${url}: malformed`);
    if (BigInt(result) === SEPOLIA_CHAIN_ID) bad.push(url);
  }
  if (bad.length > 0) throw new ProfileViolation('ZK_SEPOLIA', bad);
}
