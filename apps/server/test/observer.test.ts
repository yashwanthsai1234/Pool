// OD-31 (I-S-X1): the observer key reads the live feed of every deal and the read routes, and can never post.
import { API_AUTH_HEADER } from '@legx/contracts/api';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { newDeal, signRequest } from '../../../services/coordinator/test/support/world.ts';
import { Client } from './support/feed.ts';
import { type Composed, compose } from './support/server.ts';

let c: Composed;
let base: string;
beforeAll(async () => {
  c = await compose();
  await c.server.app.listen({ port: 0, host: '127.0.0.1' });
  base = `127.0.0.1:${(c.server.app.server.address() as { port: number }).port}`;
});
afterAll(async () => {
  await c.close();
});

describe('the observer key (OD-31) on the composed server', () => {
  it('subscribes to the feed of every deal, including a deal it belongs to none of', async () => {
    const deal2 = await newDeal(c.w);
    c.source.append(c.dealId);
    c.source.append(deal2);
    for (const id of [c.dealId, deal2]) {
      const auth = signRequest(c.w, c.w.observer, 'GET', '/ws').headers[API_AUTH_HEADER] as string;
      const client = new Client(`ws://${base}/ws?auth=${encodeURIComponent(auth)}`, id, -1);
      await client.waitFor(() => client.rows.length > 0);
      client.close();
    }
  });

  it('can never post: a write route answers 403 over HTTP', async () => {
    const { headers } = signRequest(c.w, c.w.observer, 'POST', `/deals/${c.dealId}/signature-requests`, {
      purpose: 'pay_bob',
    });
    const res = await c.server.app.inject({
      method: 'POST',
      url: `/deals/${c.dealId}/signature-requests`,
      headers,
      payload: { purpose: 'pay_bob' },
    });
    expect(res.statusCode).toBe(403);
  });
});
