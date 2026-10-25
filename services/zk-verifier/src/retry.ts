import { isUnavailable } from './errors.ts';

export interface RetryOptions {
  readonly attempts: number;
  readonly baseMs: number;
  readonly sleep: (ms: number) => Promise<void>;
}

/**
 * Runs `f`; an Unavailable error (CDN or RPC down) is retried with exponential backoff, and the last one is thrown.
 * Any other error is final: a bad proof does not get better with time.
 * Source: https://aws.amazon.com/builders-library/timeouts-retries-and-backoff-with-jitter/ (backoff; no jitter here
 * because one verification runs at a time and the tests need exact delays)
 */
export async function withRetry<T>(f: (attempt: number) => Promise<T>, o: RetryOptions): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await f(attempt);
    } catch (e) {
      if (!isUnavailable(e) || attempt >= o.attempts) throw e;
      await o.sleep(o.baseMs * 2 ** (attempt - 1));
    }
  }
}
