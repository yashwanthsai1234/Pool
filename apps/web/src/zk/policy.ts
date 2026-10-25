// Pure rules of the ZKPassport flow: profile guard, ledger-anchor freshness, single-use lawyer nonces.
// Source: DESIGN 6.10 (devMode, Sepolia and mock identifiers refused in production) and 6.15 (freshness, nonce)
import { attestConfig, checkFreshNonce, type Profile } from '@legx/core/attest';

const bytesToHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

export type ZkWebCode =
  | 'DEVMODE_OUTSIDE_DEMO'
  | 'LEDGER_STALE'
  | 'LEDGER_TOO_OLD'
  | 'NONCE_UNKNOWN'
  | 'NONCE_REUSED'
  | 'NONCE_LENGTH'
  | 'BOUND_TOO_LONG'
  | 'FACE_MATCH_REQUIRED';

export class ZkWebError extends Error {
  readonly code: ZkWebCode;
  constructor(code: ZkWebCode) {
    super(code);
    this.code = code;
  }
}

/** devMode accepts mock certificates, so it exists only in the demo profile (the adapter refuses it too, task 3.11). */
export function assertDevModeAllowed(profile: Profile, devMode: boolean): void {
  if (devMode && profile !== 'demo') throw new ZkWebError('DEVMODE_OUTSIDE_DEMO');
}

const HARD_LIMIT_SECONDS = 86_400;

/**
 * The ledger anchor in presenceMsg: older than the window (1 hour by default) is stale; older than 24 hours is
 * refused for any setting. Times are ledger close times in unix seconds.
 * Source: DESIGN 6.15 (freshness by ledger time)
 */
export function checkAnchorAge(anchorTime: number, nowTime: number, maxAgeSeconds?: number): ZkWebCode | undefined {
  const age = nowTime - anchorTime;
  if (age > HARD_LIMIT_SECONDS) return 'LEDGER_TOO_OLD';
  const { maxAgeSeconds: window } = attestConfig(maxAgeSeconds === undefined ? {} : { maxAgeSeconds });
  return age > window ? 'LEDGER_STALE' : undefined;
}

/** The lawyer console's nonces: random, issued once, consumed once. A replayed release proof meets a used nonce. */
export class LawyerNonces {
  readonly #issued = new Set<string>();
  readonly #used = new Set<string>();
  readonly #random: (n: number) => Uint8Array;

  constructor(random: (n: number) => Uint8Array = (n) => crypto.getRandomValues(new Uint8Array(n))) {
    this.#random = random;
  }

  issue(): Uint8Array {
    const nonce = this.#random(32);
    this.#issued.add(bytesToHex(nonce));
    return nonce;
  }

  /** Marks the nonce used, or says why not. */
  consume(nonce: Uint8Array): ZkWebCode | undefined {
    const fresh = checkFreshNonce(nonce, this.#used);
    if (!fresh.ok) return fresh.code;
    const hex = bytesToHex(nonce);
    if (!this.#issued.has(hex)) return 'NONCE_UNKNOWN';
    this.#used.add(hex);
    return undefined;
  }
}
