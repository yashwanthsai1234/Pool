// A fake network for the adapter tests: Ethereum JSON-RPC hosts and the circuit file host, served from task 1.17's
// recorded sets. Nothing leaves the process; every request is logged so tests can assert on hosts.
import { bodiesOf, loadSet, SET_NAMES } from '../../../packages/zk/test/fixtures.ts';

const sets = SET_NAMES.map(loadSet);
const [first] = sets as [(typeof sets)[number]];
const recorded = sets;
const loaders = {
  ...first.loaders,
  rpc: sets.flatMap((s) => s.loaders.rpc),
  files: Object.assign({}, ...sets.map((s) => s.loaders.files)) as Record<string, string>,
};
const bodies = new Map(sets.flatMap((s) => [...bodiesOf(s)]));
/** The day the sets were recorded: the SDK's date check counts from local midnight. */
export const RECORDED_AT = Date.parse(first.recordedAt);

export const RPC_A = 'https://rpc-a.example.org/v1';
export const RPC_B = 'https://rpc-b.example.net/v1';
export const CDN = 'https://circuits2.zkpassport.id';

export interface FakeNetwork {
  readonly calls: { host: string; method: string }[];
  /** Per host: 'down' throws, 'busy' answers 503, a function overrides an RPC answer. */
  readonly behaviour: Map<string, 'down' | 'busy'>;
  readonly blockHash: Map<string, string>;
  fetch: typeof fetch;
}

export function fakeNetwork(): FakeNetwork {
  const net: FakeNetwork = {
    calls: [],
    behaviour: new Map(),
    blockHash: new Map(),
    fetch: async (input, init) => {
      const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
      const method = init?.method === 'POST' ? (JSON.parse(String(init.body)).method as string) : 'GET';
      net.calls.push({ host: url.host, method });
      const mode = net.behaviour.get(url.host);
      if (mode === 'down') throw new TypeError('fetch failed');
      if (mode === 'busy') return new Response('unavailable', { status: 503 });
      if (init?.method === 'POST') return rpcAnswer(net, url.host, JSON.parse(String(init.body)));
      const m = /\/by-version\/([0-9.]+)\/manifest\.json$/.exec(url.pathname);
      const c = /\/by-hash\/(0x[0-9a-f]{64})\.json$/.exec(url.pathname);
      const body = bodies.get(m ? `manifest/${m[1]}` : `circuit/${c?.[1]}`);
      return body === undefined ? new Response('not found', { status: 404 }) : new Response(body, { status: 200 });
    },
  };
  return net;
}

function rpcAnswer(net: FakeNetwork, host: string, req: { id: number; method: string; params: unknown[] }) {
  const ok = (result: unknown) => Response.json({ jsonrpc: '2.0', id: req.id, result });
  if (req.method === 'eth_chainId') return ok(`0x${loaders.chainId.toString(16)}`);
  if (req.method === 'eth_getBlockByNumber')
    return ok({
      number: `0x${loaders.block.number.toString(16)}`,
      hash: net.blockHash.get(host) ?? loaders.block.hash,
    });
  const [call] = req.params as [{ to: string; data: string }];
  const hit = loaders.rpc.find((c) => c.to === call.to.toLowerCase() && c.data === call.data.toLowerCase());
  return hit ? ok(hit.result) : Response.json({ jsonrpc: '2.0', id: req.id, error: { message: 'execution reverted' } });
}
