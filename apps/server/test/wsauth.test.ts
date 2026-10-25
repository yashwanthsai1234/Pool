// The live feed on the composed server: the upgrade is a signed GET (OD-5), a socket reads only deals its key belongs to.
import { API_AUTH_HEADER } from '@legx/contracts/api';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { uuid7 } from '../../../services/coordinator/src/uuid.ts';
import { holderOf, newDeal, signRequest } from '../../../services/coordinator/test/support/world.ts';
import { Client, range } from './support/feed.ts';
import { type Composed, compose } from './support/server.ts';

let c: Composed;
let url: string;
beforeAll(async () => {
  c = await compose();
  await c.server.app.listen({ port: 0, host: '127.0.0.1' });
  url = `ws://127.0.0.1:${(c.server.app.server.address() as { port: number }).port}/ws`;
});
afterAll(async () => {
  await c.close();
});

type W = Parameters<typeof signRequest>[1];
/** The URL a browser would use: the header value moves into `?auth=`, and the signed path is `/ws` alone. */
const signedUrl = (holder: W) =>
  `${url}?auth=${encodeURIComponent(signRequest(c.w, holder, 'GET', '/ws').headers[API_AUTH_HEADER] as string)}`;

describe('the upgrade is authenticated', () => {
  it('an unsigned upgrade is refused with HTTP 401 before any socket exists', async () => {
    const status = await new Promise<number>((resolve) => {
      const ws = new WebSocket(url);
      ws.on('unexpected-response', (_req, res) => resolve(res.statusCode ?? 0));
      ws.on('error', () => undefined);
    });
    expect(status).toBe(401);
  });

  it('a signed upgrade by a key of the deal gets the replay and then live rows', async () => {
    for (let i = 0; i < 8; i++) c.source.append(c.dealId);
    const client = new Client(signedUrl(holderOf(c.w, 'alice')), c.dealId, 5);
    await client.waitSeq(7);
    c.source.append(c.dealId);
    await client.waitSeq(8);
    expect(client.rows).toEqual(range(6, 8));
    client.close();
  });

  it('the same signed upgrade cannot be replayed (single-use nonce)', async () => {
    const u = signedUrl(holderOf(c.w, 'bob'));
    const first = new Client(u, c.dealId, -1);
    await first.waitFor(() => first.ws.readyState === 1);
    first.close();
    const status = await new Promise<number>((resolve) => {
      const ws = new WebSocket(u);
      ws.on('unexpected-response', (_req, res) => resolve(res.statusCode ?? 0));
      ws.on('error', () => undefined);
    });
    expect(status).toBe(401);
  });

  it('a key of another deal, and a deal nobody asked for, close with 4403', async () => {
    const alice1 = holderOf(c.w, 'alice');
    const deal2 = await newDeal(c.w);
    c.source.append(deal2);
    const other = new Client(signedUrl(alice1), deal2, -1);
    expect(await other.closed).toBe(4403);
    expect(other.rows).toEqual([]);
    const stranger = new Client(signedUrl(holderOf(c.w, 'alice')), uuid7(), -1);
    expect(await stranger.closed).toBe(4403);
  });

  it('a pinned lawyer key that belongs to no deal reads nothing', async () => {
    const lawyer = c.w.lawyerCreator as unknown as W;
    const client = new Client(signedUrl(lawyer), c.dealId, -1);
    expect(await client.closed).toBe(4403);
  });
});
