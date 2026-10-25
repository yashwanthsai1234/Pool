// The production adapter's settings, checked once at start-up (DESIGN 6.10 "Trust anchors", IMPLEMENTATION P3.11-04/05/17).
import { ZK_DOMAIN } from '@legx/contracts/records';
import type { Profile } from '@legx/core/attest';
import { installedVersions, PINNED } from '@legx/zk/sdk';
import { ZkVerifierError } from './errors.ts';

/** ZKPassport's hosted verification service: using it sends proofs to a third party. */
export const HOSTED_VERIFIER_HOST = 'verifier.zkpassport.id';

/**
 * The hosts the SDK reads circuit and certificate files from by default.
 * Source: @zkpassport/registry 0.15.3 dist/cjs/index.cjs (circuits2, certificates, sanctions, ipfs URL bases)
 */
export const DEFAULT_CDN_HOSTS = [
  'circuits2.zkpassport.id',
  'certificates.zkpassport.id',
  'sanctions.zkpassport.id',
  'ipfs.zkpassport.id',
] as const;

export interface ZkVerifierConfig {
  readonly profile: Profile;
  /** Required and always "legx.app": a page origin or no domain stops start-up (the identifier depends on it). */
  readonly domain: string | undefined;
  readonly devMode: boolean;
  /** Ethereum JSON-RPC endpoints for the registry roots; production needs at least two on different hosts. */
  readonly rpcUrls: readonly string[];
  /** The SDK version the operator expects; it must equal the pinned one and the installed one. */
  readonly sdkVersion: string;
  readonly cdnHosts?: readonly string[];
  readonly retry?: { readonly attempts?: number; readonly baseMs?: number };
}

export interface CheckedConfig {
  readonly profile: Profile;
  readonly devMode: boolean;
  readonly rpcUrls: readonly string[];
  readonly rpcHosts: ReadonlySet<string>;
  readonly allowedHosts: ReadonlySet<string>;
  readonly attempts: number;
  readonly baseMs: number;
}

const hostOf = (url: string) => new URL(url).host.toLowerCase();

export function checkConfig(c: ZkVerifierConfig): CheckedConfig {
  const fail = (code: ConstructorParameters<typeof ZkVerifierError>[0], msg: string): never => {
    throw new ZkVerifierError(code, msg);
  };
  if (c.domain !== ZK_DOMAIN) fail('ZK_CONFIG_WRONG_DOMAIN', `the domain must be "${ZK_DOMAIN}" (never a page origin)`);
  if (c.profile === 'production' && c.devMode) fail('ZK_CONFIG_DEVMODE_REFUSED', 'devMode in the production profile');
  const installed = installedVersions().sdk;
  if (c.sdkVersion !== PINNED.sdk || installed !== c.sdkVersion)
    fail('ZK_CONFIG_SDK_VERSION', `expected ${c.sdkVersion}, pinned ${PINNED.sdk}, installed ${installed}`);
  const rpcHosts = new Set(c.rpcUrls.map(hostOf));
  if (rpcHosts.has(HOSTED_VERIFIER_HOST))
    fail('ZK_CONFIG_HOSTED_VERIFIER', 'the hosted verifier is not an RPC provider');
  if (c.profile === 'production' && rpcHosts.size < 2)
    fail('ZK_CONFIG_RPC_PROVIDERS', 'production needs at least two RPC providers on different hosts');
  if (rpcHosts.size < 1) fail('ZK_CONFIG_RPC_PROVIDERS', 'no RPC provider');
  const cdn = c.cdnHosts ?? DEFAULT_CDN_HOSTS;
  if (cdn.includes(HOSTED_VERIFIER_HOST)) fail('ZK_CONFIG_HOSTED_VERIFIER', 'the hosted verifier is not a file host');
  return {
    profile: c.profile,
    devMode: c.devMode,
    rpcUrls: c.rpcUrls,
    rpcHosts,
    allowedHosts: new Set([...rpcHosts, ...cdn]),
    attempts: c.retry?.attempts ?? 3,
    baseMs: c.retry?.baseMs ?? 250,
  };
}
