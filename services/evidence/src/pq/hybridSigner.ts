// The hybrid signer the services call (DESIGN 6.13): a `SignerPort` around any implementation (KMS, Node, file) that
// retries a failed signing and refuses to return anything but a complete pair. A half-signed envelope can therefore never
// be built, stored or counted as success: the append that wanted the signature simply fails, and is tried again.
// Source: https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html (Sign errors marked "can be retried":
//   DependencyTimeoutException, KeyUnavailableException, KMSInternalException)
import type { HybridSignature, SignerPort } from '@legx/contracts/ports';

const ED25519_SIG = 64;
const MLDSA65_SIG = 3309;

export class HybridSigningFailed extends Error {
  readonly attempts: number;
  constructor(attempts: number, cause: unknown) {
    super(
      `hybrid signing failed after ${attempts} attempt(s): ${cause instanceof Error ? cause.message : String(cause)}`,
      {
        cause,
      },
    );
    this.name = 'HybridSigningFailed';
    this.attempts = attempts;
  }
}

export interface ResilientOptions {
  /** Total tries per signature (default 3). */
  readonly attempts?: number;
  /** Milliseconds before try n (1-based) after the first; default doubles from 100 ms. */
  readonly delayMs?: (retry: number) => number;
  readonly sleep?: (ms: number) => Promise<void>;
}

const complete = (s: HybridSignature | undefined): s is HybridSignature =>
  s !== undefined && s.ed25519?.length === ED25519_SIG && s.mlDsa65?.length === MLDSA65_SIG;

export function resilientSigner(inner: SignerPort, options: ResilientOptions = {}): SignerPort {
  const attempts = options.attempts ?? 3;
  const delay = options.delayMs ?? ((n: number) => 100 * 2 ** (n - 1));
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  return {
    publicKeys: () => inner.publicKeys(),
    async signHybrid(msg, ctx) {
      let last: unknown;
      for (let n = 1; n <= attempts; n++) {
        if (n > 1) await sleep(delay(n - 1));
        try {
          const sig = await inner.signHybrid(msg, ctx);
          if (complete(sig)) return sig;
          last = new Error('the signer returned an incomplete signature pair');
        } catch (e) {
          last = e;
        }
      }
      throw new HybridSigningFailed(attempts, last);
    },
  };
}
