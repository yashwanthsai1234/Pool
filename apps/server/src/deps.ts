// The dependencies `buildServer` composes (kept apart from compose.ts so routes.ts can name them without a cycle).
import type { Principal } from '@legx/coordinator/auth';
import type { CoordinatorDeps, PinnedKey } from '@legx/coordinator/deps';
import type { RelayOptions } from '@legx/coordinator/frost/relay';
import type { BundleDeps } from '@legx/evidence/bundle';
import type { RecordsDeps } from '@legx/evidence/records';
import type { FirmCosigner } from '@legx/firm-cosigner';
import type { AgentHttpDeps } from '@legx/recovery-agent/routes';
import type { Verifier } from '@legx/verifier/service';
import type { FastifyInstance } from 'fastify';
import type { PortSpec, ProfileName, ZkSettings } from './config.ts';
import type { LiveOptions } from './live.ts';
import type { ZkVerifyDeps } from './zk.ts';

export interface ServerDeps {
  readonly profile: ProfileName;
  /** The process environment, checked for `LEGX_DEMO_*` in the production profile (P3.7-05). */
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** Ports the composition cannot see by itself (ledger, signer, store, log, registry, ZK, watcher, post-quantum). */
  readonly ports: Readonly<Record<string, PortSpec>>;
  readonly zk?: ZkSettings;
  readonly coordinator: CoordinatorDeps;
  readonly relay?: RelayOptions;
  readonly verifier?: {
    readonly service: Pick<Verifier, 'verify'> & Partial<Pick<Verifier, 'link'>>;
    readonly enqueue?: (opsAccount: string) => Promise<void>;
    /** The operator path of bar.manualEvidence: the adapter that `upload` feeds (production, or a demo jurisdiction). */
    readonly manual?: {
      upload(u: {
        jurisdiction: string;
        barNumber: string;
        status: 'active' | 'not_active' | 'not_found';
        page: Uint8Array;
        url: string;
      }): void;
    };
  };
  /** `ledger.snapshot`: the release gate's input of a deal, from one validated ledger. */
  readonly releaseInput?: (dealId: string) => Promise<Record<string, unknown>>;
  /** What `zk.verify` needs (OD-32: public proofs only). */
  readonly zkVerify?: ZkVerifyDeps;
  readonly evidence?: { readonly records: RecordsDeps; readonly bundle?: BundleDeps };
  /** Mounted in the demo profile only. In production they are separate processes (their own `register`). */
  readonly agents?: {
    readonly recovery?: AgentHttpDeps;
    /** With a `cosigner`, `firmHsm.sign` is served at its contract path (the recovery routes of the firm stay under `/firm`). */
    readonly firm?: AgentHttpDeps & { readonly cosigner?: FirmCosigner; readonly onError?: (e: unknown) => void };
  };
  readonly operatorKeys?: (pairId: string) => PinnedKey | undefined;
  readonly live: LiveOptions;
  /** Which deal may this authenticated key read. Default: the key is pinned to that deal. */
  readonly canRead?: (principal: Principal, dealId: string) => Promise<boolean>;
  readonly csp?: string;
  /**
   * The demo hook (task 4.5): routes that exist only in the demo profile. Naming it makes the composition list a demo
   * port, so the production profile refuses to start with it (P3.7-05, P4.5-04). Its paths skip the auth-header guard.
   */
  readonly demo?: { readonly pathPrefix: string; register(app: FastifyInstance): Promise<void> };
}
