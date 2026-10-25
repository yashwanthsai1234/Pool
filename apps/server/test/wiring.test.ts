// The wiring test (IMPLEMENTATION 3.7 "Think"): every Phase 3 service passes alone and can still fail composed.
// Here: every route of the contract's route table is mounted on the one process and refuses an unsigned request;
// a signed request reaches the service; the signature covers the exact raw bytes; the CSP carries frame-ancestors;
// and `GET /health` lists each composed port with its profile (P3.7-01, P3.7-06).
import { listRoutes } from '@legx/contracts/catalog';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { z } from 'zod';
import { uuid7 } from '../../../services/coordinator/src/uuid.ts';
import { holderOf, signRequest } from '../../../services/coordinator/test/support/world.ts';
import { type Composed, compose, sha } from './support/server.ts';

let c: Composed;
beforeAll(async () => {
  c = await compose();
});
afterAll(async () => {
  await c.close();
});

const fill = (path: string) =>
  path
    .replace('{dealId}', c.dealId)
    .replace('{requestId}', uuid7())
    .replace('{recoveryId}', uuid7())
    .replace('{sha256}', sha('x'))
    .replace('{keyId}', 'some-key')
    .replace('{sessionId}', sha('session'))
    .replace(/\{(\w+)\}/g, 'x');
const routes = listRoutes().filter((r) => r.name !== 'health');
const isUnmounted = (r: { statusCode: number; body: string }) => {
  if (r.statusCode !== 404) return false;
  try {
    return String(JSON.parse(r.body).message).startsWith('Route ');
  } catch {
    return false;
  }
};

describe('GET /health (P3.7-01, P3.7-06)', () => {
  it('lists each port and the profile, in the shape of the contract', async () => {
    const res = await c.server.app.inject({ method: 'GET', url: '/health' });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    const out = listRoutes().find((r) => r.name === 'health')?.output as z.ZodType;
    expect(out.safeParse(body).success, JSON.stringify(body)).toBe(true);
    expect(body.profile).toBe('demo');
    for (const port of [
      'coordinator',
      'frost-relay',
      'evidence',
      'verifier',
      'recovery-agent',
      'firm-cosigner',
      'live-feed',
      'database',
      'ledger',
      'signer',
    ])
      expect(body.ports[port], port).toEqual({ impl: expect.any(String), status: 'ok' });
  });

  it('a port whose probe fails reports down, and a throwing probe too', async () => {
    const c2 = await compose({
      ports: {
        zk: { impl: 'adapter', demo: true, check: () => false },
        watcher: {
          impl: 'service',
          demo: false,
          check: () => {
            throw new Error('boom');
          },
        },
      },
    });
    try {
      const body = (await c2.server.app.inject({ method: 'GET', url: '/health' })).json();
      expect(body.ports.zk.status).toBe('down');
      expect(body.ports.watcher.status).toBe('down');
      expect(body.ports.coordinator.status).toBe('ok');
    } finally {
      await c2.close();
    }
  });

  it('an unknown route is refused (401 unsigned, 404 signed), never a crash', async () => {
    expect((await c.server.app.inject({ method: 'GET', url: '/nope' })).statusCode).toBe(401);
    const res = await c.server.app.inject(signRequest(c.w, holderOf(c.w, 'alice'), 'GET', '/nope') as never);
    expect(isUnmounted(res)).toBe(true);
  });
});

describe('every route of the contract is mounted and authenticated', () => {
  it('the table has the 38 routes this test knows (a new route must be wired on purpose)', () => {
    expect(listRoutes().length).toBe(38);
  });

  it.each(routes.map((r) => [r.name, r] as const))('%s: an unsigned request is 401', async (_name, r) => {
    const res = await c.server.app.inject({
      method: r.method as 'GET' | 'POST',
      url: fill(r.path as string),
      ...(r.method === 'POST' ? { payload: '{}', headers: { 'content-type': 'application/json' } } : {}),
    });
    expect(res.statusCode, `${r.name}: ${res.body}`).toBe(401);
  });

  it.each(routes.map((r) => [r.name, r] as const))(
    '%s: a signed request gets past authentication',
    async (_name, r) => {
      const body = r.method === 'POST' ? { side: 'A' } : undefined;
      const signed = signRequest(c.w, holderOf(c.w, 'alice'), r.method as 'GET' | 'POST', fill(r.path as string), body);
      const res = await c.server.app.inject(signed as never);
      expect(isUnmounted(res), `${r.name} is not mounted`).toBe(false);
      expect(res.statusCode, `${r.name}: ${res.body}`).not.toBe(401);
    },
  );

  it('the firm co-signer routes (mounted under /firm in the demo) are guarded too', async () => {
    const un = await c.server.app.inject({ method: 'GET', url: `/firm/recoveries/${uuid7()}` });
    expect(un.statusCode).toBe(401);
    const ok = await c.server.app.inject(
      signRequest(c.w, holderOf(c.w, 'alice'), 'GET', `/firm/recoveries/${uuid7()}`) as never,
    );
    expect(ok.statusCode).not.toBe(401);
  });

  it('the signature covers the exact raw bytes: odd whitespace passes, one changed byte is refused', async () => {
    const url = `/deals/${c.dealId}/wallet`;
    const raw = '{ "walletAddress" :   "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh" }\n';
    const good = signRequest(c.w, holderOf(c.w, 'alice'), 'POST', url, undefined, { rawBody: raw });
    expect((await c.server.app.inject(good as never)).statusCode).not.toBe(401);
    const tampered = signRequest(c.w, holderOf(c.w, 'alice'), 'POST', url, undefined, { rawBody: raw });
    tampered.payload = raw.replace('rHb9', 'rHb8');
    const res = await c.server.app.inject(tampered as never);
    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe('bad_signature');
  });

  it('a nonce is single use across the composed process', async () => {
    const url = `/deals/${c.dealId}`;
    const req = signRequest(c.w, holderOf(c.w, 'alice'), 'GET', url);
    expect((await c.server.app.inject(req as never)).statusCode).toBe(200);
    const again = await c.server.app.inject(req as never);
    expect(again.statusCode).toBe(401);
    expect(again.json().error).toBe('nonce_reused');
  });

  it('the signed path is pathname + search as sent (OD-8): a query changes the message', async () => {
    const signed = signRequest(c.w, holderOf(c.w, 'alice'), 'GET', `/deals/${c.dealId}/events?afterSeq=-1&limit=5`);
    const swapped = { ...signed, url: `/deals/${c.dealId}/events?afterSeq=-1&limit=500` };
    expect((await c.server.app.inject(swapped as never)).statusCode).toBe(401);
    expect((await c.server.app.inject(signed as never)).statusCode).toBe(200);
  });
});

describe('response headers', () => {
  it.each([
    ['health', 'GET', '/health'],
    ['a refused request', 'GET', '/deals/x'],
    ['an unknown route', 'GET', '/nope'],
  ])('%s carries frame-ancestors and the other security headers', async (_n, method, url) => {
    const res = await c.server.app.inject({ method: method as 'GET', url });
    expect(res.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['cache-control']).toBe('no-store');
  });
});
