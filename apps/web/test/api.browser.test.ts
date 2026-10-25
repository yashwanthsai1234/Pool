import { API_AUTH_HEADER, ApiAuth } from '@legx/contracts/api';
import { listRoutes } from '@legx/contracts/catalog';
import { afterAll, beforeAll, describe, expect, expectTypeOf, it } from 'vitest';
import { type ApiClient, createApiClient, type SignableRequest } from '../src/lib/api.ts';
import { startMocks } from '../src/mocks/browser.ts';
import { examplesOf } from '../src/mocks/examples.ts';
import { type RecordedRequest, restHandlers } from '../src/mocks/handlers.ts';

const AUTH = ApiAuth.parse(examplesOf('ApiAuth')[0]);
const sha256Hex = async (bytes: Uint8Array) =>
  Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource)), (b) =>
    b.toString(16).padStart(2, '0'),
  ).join('');

const seen: RecordedRequest[] = [];
const signed: SignableRequest[] = [];
let worker: Awaited<ReturnType<typeof startMocks>>;
beforeAll(async () => {
  worker = await startMocks(...restHandlers({ onRequest: (r) => seen.push(r) }));
});
afterAll(() => worker.stop());

const client = createApiClient({
  signRequest: async (req) => {
    signed.push(req);
    return AUTH;
  },
});

// P4.1-02: a wrong request shape must not compile. `tsc -p apps/web` is the check; the function is never called.
function wrongShapes(c: ApiClient) {
  // @ts-expect-error `id` is not a field; the route wants `dealId`
  void c.deals.get({ id: 'x' });
  // @ts-expect-error `amountDrops` must be a string of drops, not a number
  void c.deals.setWallet({ dealId: 'x', walletAddress: 'r', amountDrops: 5 });
  // @ts-expect-error no such route
  void c.deals.delete({ dealId: 'x' });
  // @ts-expect-error the input is required
  void c.deals.get();
}

describe('P4.1-02 the client is generated from the route table', () => {
  it('has a typed procedure for every route of the table', () => {
    expect(wrongShapes).toBeTypeOf('function'); // never called: each wrong call inside it is a compile error under `tsc`
    expectTypeOf<ApiClient['deals']['get']>().toBeFunction();
    const routes = listRoutes();
    expect(routes).toHaveLength(38);
    for (const { name } of routes) {
      const fn = name.split('.').reduce<unknown>((node, key) => (node as Record<string, unknown>)[key], client);
      expect(fn, name).toBeTypeOf('function');
    }
  });

  it.each(listRoutes().map((r) => r.name))(
    '%s: signs the exact request it sends and parses the answer',
    async (name) => {
      seen.length = 0;
      signed.length = 0;
      const input = examplesOf(`route.${name}.input`)[0];
      const fn = name.split('.').reduce<unknown>((node, key) => (node as Record<string, unknown>)[key], client);
      const output = await (fn as (i: unknown) => Promise<unknown>)(input);
      expect(output).toEqual(JSON.parse(JSON.stringify(examplesOf(`route.${name}.output`)[0])));
      expect(seen).toHaveLength(1);
      expect(signed).toHaveLength(1);
      const [got, asked] = [seen[0] as RecordedRequest, signed[0] as SignableRequest];
      // what the signer saw is what the server received: method, path with query, and the raw body bytes
      expect([asked.method, asked.path]).toEqual([got.method, got.path.slice('/api'.length)]);
      expect(await sha256Hex(asked.body)).toBe(await sha256Hex(got.body));
      expect(got.path.startsWith('/api/')).toBe(true);
      expect(got.auth).toEqual(AUTH);
    },
  );
});

describe('every request is signed', () => {
  it('a signer that fails sends nothing', async () => {
    seen.length = 0;
    const failing = createApiClient({
      signRequest: () => Promise.reject(new Error('vault locked')),
    });
    await expect(failing.health({})).rejects.toThrow('vault locked');
    expect(seen).toHaveLength(0);
  });

  it('the mock refuses a request with no or a malformed auth header (so an unsigned client cannot pass)', async () => {
    for (const header of [undefined, 'not json', JSON.stringify({ ...AUTH, nonce: 'zz' })]) {
      const res = await fetch('/api/health', header === undefined ? {} : { headers: { [API_AUTH_HEADER]: header } });
      expect(res.status).toBe(401);
    }
  });

  it('the client sends the auth header as JSON that parses as ApiAuth', async () => {
    seen.length = 0;
    await client.health({});
    expect(ApiAuth.safeParse(seen[0]?.auth).success).toBe(true);
  });
});
