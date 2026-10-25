// P4.8-08: the console re-verifies a proof set locally with the SDK (`verifierMode: "local"`), so a failure here blocks the
// attestation even when the adapter said PASS. bb.js 5.0.0 starts in Chromium and WebKit without SharedArrayBuffer (one
// thread, no COOP/COEP needed), so the check runs in the page. The SDK reads the registry and circuit files through the
// global `fetch`, so one verification runs at a time with `fetch` swapped for the duration (as packages/zk/src/verify.ts).
// Source: @zkpassport/sdk 0.19.2 `verify({ config })`; https://github.com/AztecProtocol/aztec-packages (bb.js browser build)
import type { ProofResult, Query, QueryResult } from '@zkpassport/sdk';

export interface ReverifySet {
  readonly request: {
    readonly domain: string;
    readonly scope: string;
    readonly devMode: boolean;
    readonly validity: number;
    readonly originalQuery: Query;
  };
  readonly proofs: readonly ProofResult[];
  readonly queryResult: QueryResult;
}
export interface RecordedLoaders {
  readonly rpc: readonly { readonly to: string; readonly data: string; readonly result: string }[];
  /** Local midnight (unix seconds) when the set was recorded: the SDK's date check counts whole days from it. */
  readonly verifiedDay: number;
}
export interface ReverifyOptions {
  /** `verify({ config })`: where the registry and the circuit files are read from. */
  config: Record<string, unknown>;
  /** Answers the SDK's reads. Default: the page's own `fetch`. */
  fetcher?: typeof fetch;
  /** Overrides `request.validity` (a replay shifts it by the days since the recording). */
  validity?: number;
}
export type ReverifyResult = { ok: true; uniqueIdentifier: string | null } | { ok: false; code: 'PROOF_NOT_VERIFIED' };

let queue: Promise<unknown> = Promise.resolve();

export function reverifyInBrowser(set: ReverifySet, o: ReverifyOptions): Promise<ReverifyResult> {
  const run = queue.then(async (): Promise<ReverifyResult> => {
    const original = globalThis.fetch;
    if (o.fetcher) globalThis.fetch = o.fetcher;
    try {
      const { ZKPassport } = await import('@zkpassport/sdk');
      const result = await new ZKPassport(set.request.domain).verify({
        proofs: [...set.proofs],
        originalQuery: set.request.originalQuery,
        queryResult: set.queryResult,
        scope: set.request.scope,
        devMode: set.request.devMode,
        verifierMode: 'local',
        validity: o.validity ?? set.request.validity,
        config: o.config,
      });
      return result.verified
        ? { ok: true, uniqueIdentifier: result.uniqueIdentifier ?? null }
        : { ok: false, code: 'PROOF_NOT_VERIFIED' };
    } catch {
      return { ok: false, code: 'PROOF_NOT_VERIFIED' }; // the SDK throws on a malformed set or an unreadable file: not verified
    } finally {
      globalThis.fetch = original;
    }
  });
  queue = run.catch(() => undefined);
  return run;
}

const CRS_HOST = 'https://crs.aztec-labs.com/';
const RPC_URL = 'http://rpc.legx-recorded.invalid/'; // RFC 2606 .invalid: never resolves
const FILES_URL = 'http://files.legx-recorded.invalid';
const midnight = (ms: number) => {
  const d = new Date(ms);
  return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime() / 1000;
};

/** Options that serve every registry answer and circuit file from a recording (tests, arbitrators); nothing leaves the page. */
export function replayConfig(
  set: ReverifySet,
  loaders: RecordedLoaders,
  bodies: ReadonlyMap<string, string>,
  now: number,
  /** bb.js reads the BN254 and Grumpkin points (the CRS) from crs.aztec-labs.com: the recorded files by name (`g2.dat`, ...). */
  crs: ReadonlyMap<string, Uint8Array>,
): ReverifyOptions {
  const real = globalThis.fetch;
  const fetcher: typeof fetch = async (input, init) => {
    const url = String((input as { url?: string })?.url ?? input);
    // bb.js carries its WASM as a gzip `data:` URL and reads it with fetch: that is the page's own code, not the network
    if (url.startsWith('data:')) return real(input, init);
    const crsFile = url.startsWith(CRS_HOST) ? crs.get(url.slice(CRS_HOST.length)) : undefined;
    if (crsFile) {
      // the SDK asks for a byte range of the points files: answer exactly that range
      const range = /bytes=(\d+)-(\d+)?/.exec(new Headers(init?.headers).get('range') ?? '');
      const from = range ? Number(range[1]) : 0;
      const to = range?.[2] ? Number(range[2]) + 1 : crsFile.length;
      return new Response(crsFile.slice(from, to) as BodyInit, { status: range ? 206 : 200 });
    }
    if (url === RPC_URL && init?.method === 'POST') {
      const req = JSON.parse(String(init.body)) as { id?: number; params: [{ to: string; data: string }] };
      const [call] = req.params;
      const hit = loaders.rpc.find((c) => c.to === call.to.toLowerCase() && c.data === call.data.toLowerCase());
      if (!hit) throw new Error('offline: no recorded answer');
      return Response.json({ jsonrpc: '2.0', id: req.id, result: hit.result });
    }
    const body = url.startsWith(`${FILES_URL}/`) ? bodies.get(url.slice(FILES_URL.length + 1)) : undefined;
    if (body === undefined) throw new Error(`offline: fetch blocked: ${url}`);
    return new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });
  };
  return {
    fetcher,
    validity: set.request.validity + (midnight(now) - loaders.verifiedDay),
    config: {
      rpcUrl: RPC_URL,
      circuitManifestUrlGenerator: (_c: number, o: { version?: string }) => `${FILES_URL}/manifest/${o.version}`,
      packagedCircuitUrlGenerator: (_c: number, hash: string) => `${FILES_URL}/circuit/${hash}`,
      packagedCertsUrlGenerator: (_c: number, root: string) => `${FILES_URL}/certificates/${root}`,
      sanctionsTreeUrlGenerator: (_c: number, root: string) => `${FILES_URL}/sanctions/${root}`,
    },
  };
}
