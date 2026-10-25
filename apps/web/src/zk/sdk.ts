// The ZKPassport SDK behind a small port, so screens and tests never touch the network. The real SDK loads lazily
// (about 4 MB with its WASM), only when a request is shown. The demo profile replays a recording with devMode.
// Source: @zkpassport/sdk 0.19.2 typings (request() -> QueryBuilder -> done() -> RequestSuccess with url and callbacks)
import type { ZkVerifyRequest } from '@legx/contracts/records';

/** What the SDK hands back once the phone has proven (the proofs and the result, as the server route takes them). */
export interface ZkOutcome {
  readonly proofs: ZkVerifyRequest['proofs'];
  readonly queryResult: Record<string, unknown>;
  readonly originalQuery: Record<string, unknown>;
}

export interface ZkCallbacks {
  onRequestReceived(cb: () => void): void;
  onGeneratingProof(cb: () => void): void;
  onProofGenerated(cb: () => void): void;
  onResult(cb: (outcome: ZkOutcome) => void): void;
  onReject(cb: () => void): void;
  onError(cb: (message: string) => void): void;
}

/** The builder calls the flow needs; the SDK's QueryBuilder has all of them. */
export interface ZkBuilder {
  gte(key: 'age', value: number): ZkBuilder;
  in(key: 'nationality', value: string[]): ZkBuilder;
  disclose(key: 'firstname' | 'lastname' | 'birthdate' | 'nationality'): ZkBuilder;
  gt(key: 'expiry_date', value: Date): ZkBuilder;
  facematch(mode: 'strict' | 'regular'): ZkBuilder;
  bind(key: 'custom_data', value: string): ZkBuilder;
  done(): ZkCallbacks & { url: string };
}

export interface ZkRequestSettings {
  readonly domain: string;
  readonly scope: string;
  readonly devMode: boolean;
  readonly validity: number;
  readonly verifierMode: 'local';
}

export interface ZkSdk {
  request(settings: ZkRequestSettings): Promise<ZkBuilder>;
}

/** A recorded session replayed as callbacks (demo profile and tests). */
export interface ZkScript {
  readonly url: string;
  readonly events: readonly (
    | { readonly type: 'received' | 'generating' | 'generated' | 'reject' }
    | { readonly type: 'result'; readonly outcome: ZkOutcome }
    | { readonly type: 'error'; readonly message: string }
  )[];
}

export function scriptedSdk(
  script: ZkScript,
  onRequest?: (s: ZkRequestSettings, calls: [string, unknown][]) => void,
): ZkSdk {
  return {
    request: async (settings) => {
      const calls: [string, unknown][] = [];
      const builder = new Proxy({} as ZkBuilder, {
        get: (_t, name: string) => {
          if (name === 'then') return undefined; // the builder is awaited, and must not look like a promise
          if (name !== 'done')
            return (...args: unknown[]) => {
              calls.push([name, args]);
              return builder;
            };
          return () => {
            onRequest?.(settings, calls);
            return playback(script);
          };
        },
      });
      return builder;
    },
  };
}

function playback(script: ZkScript): ZkCallbacks & { url: string } {
  const handlers: Record<string, ((arg?: never) => void) | undefined> = {};
  const on =
    <A = never>(name: string) =>
    (cb: (arg: A) => void) =>
      void Object.assign(handlers, { [name]: cb });
  setTimeout(() => {
    for (const e of script.events) {
      if (e.type === 'result') handlers.result?.(e.outcome as never);
      else if (e.type === 'error') handlers.error?.(e.message as never);
      else handlers[e.type]?.();
    }
  }, 0);
  return {
    url: script.url,
    onRequestReceived: on('received'),
    onGeneratingProof: on('generating'),
    onProofGenerated: on('generated'),
    onResult: on<ZkOutcome>('result'),
    onReject: on('reject'),
    onError: on<string>('error'),
  };
}

/** A recorded mock-passport session (packages/zk/fixtures/sets) as a script, for the demo profile with devMode. */
export function scriptFromRecording(set: {
  request: { originalQuery: Record<string, unknown> };
  proofs: unknown;
  queryResult: Record<string, unknown>;
}): ZkScript {
  const outcome = { proofs: set.proofs, queryResult: set.queryResult, originalQuery: set.request.originalQuery };
  return {
    url: 'https://zkpassport.id/r?demo=recorded',
    events: [
      { type: 'received' },
      { type: 'generating' },
      { type: 'generated' },
      { type: 'result', outcome: outcome as ZkOutcome },
    ],
  };
}
