export type ZkVerifierErrorCode =
  | 'ZK_CONFIG_WRONG_DOMAIN'
  | 'ZK_CONFIG_DEVMODE_REFUSED'
  | 'ZK_CONFIG_RPC_PROVIDERS'
  | 'ZK_CONFIG_SDK_VERSION'
  | 'ZK_CONFIG_HOSTED_VERIFIER'
  | 'ZK_CDN_UNAVAILABLE'
  | 'ZK_REGISTRY_UNAVAILABLE'
  | 'ZK_ROOTS_DISAGREE'
  | 'ZK_EGRESS_BLOCKED'
  | 'ZK_REFUSED'
  | 'ZK_NOT_VERIFIED'
  | 'ZK_STORE_FAILED';

/** One error class with a code, so callers branch on `code` and tests name the reason. */
export class ZkVerifierError extends Error {
  readonly code: ZkVerifierErrorCode;
  /** The core or trust code behind a ZK_REFUSED. */
  readonly reason: string | undefined;
  constructor(code: ZkVerifierErrorCode, message: string, reason?: string, cause?: unknown) {
    super(`${code}: ${message}`, { cause });
    this.name = code === 'ZK_CDN_UNAVAILABLE' ? 'ZkCdnUnavailable' : 'ZkVerifierError';
    this.code = code;
    this.reason = reason;
  }
}

export const isUnavailable = (e: unknown): e is ZkVerifierError =>
  e instanceof ZkVerifierError && (e.code === 'ZK_CDN_UNAVAILABLE' || e.code === 'ZK_REGISTRY_UNAVAILABLE');
