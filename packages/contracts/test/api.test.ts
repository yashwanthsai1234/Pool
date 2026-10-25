import { readFileSync } from 'node:fs';
import { oc } from '@orpc/contract';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { API_AUTH_HEADER, API_MAX_LEDGER_AGE, API_REQUEST_TAG, ApiAuth, AuthRule, contract } from '../src/api.ts';
import { listRoutes, type RouteEntry, SCHEMAS } from '../src/catalog.ts';
import { secretPaths } from '../src/secret.ts';
import { WS_CLOSE, WsClientMessage, WsServerMessage } from '../src/ws.ts';

const isSchema = (s: unknown) =>
  typeof (s as { '~standard'?: { validate?: unknown } })?.['~standard']?.validate === 'function';

/** Every problem with a route table: a missing method, path, schema or auth rule, or a duplicate route. */
function routeProblems(routes: RouteEntry[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const r of routes) {
    if (!r.method || !r.path) out.push(`${r.name}: no method or path`);
    if (!isSchema(r.input)) out.push(`${r.name}: no request schema`);
    if (!isSchema(r.output)) out.push(`${r.name}: no response schema`);
    if (!AuthRule.safeParse(r.auth).success) out.push(`${r.name}: no auth rule`);
    const key = `${r.method} ${r.path}`;
    if (seen.has(key)) out.push(`${r.name}: duplicate ${key}`);
    seen.add(key);
    // Every path parameter must be a field of the request schema (of every branch, for a union).
    type Obj = { shape?: Record<string, unknown>; options?: Obj[] };
    const input = r.input as Obj;
    const shapes = input?.options?.map((o) => o.shape ?? {}) ?? [input?.shape ?? {}];
    for (const [, p] of (r.path ?? '').matchAll(/\{(\w+)\}/g))
      if (p && !shapes.every((s) => p in s)) out.push(`${r.name}: no input field ${p}`);
  }
  return out;
}

describe('P1.2-05 route table', () => {
  const routes = listRoutes();

  it('every route has a request schema, a response schema and an auth rule', () => {
    expect(routes.length).toBeGreaterThanOrEqual(28);
    expect(routeProblems(routes)).toEqual([]);
  });

  it('the walker fails on a route without an auth rule, schemas or path', () => {
    const bad = { a: { b: oc.input(z.strictObject({})) } };
    expect(routeProblems(listRoutes(bad))).toEqual([
      'a.b: no method or path',
      'a.b: no response schema',
      'a.b: no auth rule',
    ]);
  });

  it('only signed-request routes, and the two verifier inputs and the ZK request, take a Secret field', () => {
    const withSecrets = routes
      .filter((r) => secretPaths(r.input as z.ZodType).length > 0)
      .map((r) => `${r.name} ${secretPaths(r.input as z.ZodType).join(',')}`);
    expect(withSecrets).toEqual([
      'bar.verify /barNumber',
      'bar.manualEvidence /barNumber',
      'bar.dealLink /barNumber,/barSalt',
      'zk.verify /request/proofs/*/committedInputs,/request/queryResult,/zkSalt32',
    ]);
  });

  it('no response, event, record or relay message carries a Secret field', () => {
    const leaks = Object.entries(SCHEMAS)
      .filter(([name]) => !name.endsWith('.input') && name !== 'DisclosedFacts' && name !== 'ZkVerifyRequest')
      .filter(([, s]) => secretPaths(s).length > 0)
      .map(([name]) => name);
    expect(leaks).toEqual([]);
    expect(secretPaths(SCHEMAS.DisclosedFacts as z.ZodType)).toEqual([
      '/birthdate',
      '/firstname',
      '/lastname',
      '/nationality',
    ]);
  });

  it('the client records view and the bundle accept only the client of that side or its own lawyer (DESIGN 8.10)', () => {
    for (const r of [contract.records.list, contract.records.bundle])
      expect(r['~orpc'].meta.auth).toEqual({
        kind: 'signed-request',
        callers: ['alice', 'lawyerA', 'bob', 'lawyerB'],
        ownSideOnly: true,
      });
  });

  it('every route is a signed request (DESIGN 8.10 access rule)', () => {
    expect(new Set(routes.map((r) => (r.auth as AuthRule).kind))).toEqual(new Set(['signed-request']));
  });
});

describe('API request signature', () => {
  it('pins the tag, the header and the 20-ledger freshness limit', () => {
    expect(API_REQUEST_TAG).toBe('legx/api-request/v1');
    expect(API_AUTH_HEADER).toBe('x-legx-auth');
    expect(API_MAX_LEDGER_AGE).toBe(20);
  });

  it('the auth header needs both hybrid signatures, a 32-byte nonce and a ledger index', () => {
    const [auth] = JSON.parse(readFileSync(new URL('../examples/ApiAuth.json', import.meta.url), 'utf8'));
    expect(ApiAuth.safeParse(auth).success).toBe(true);
    expect(ApiAuth.safeParse({ ...auth, signatures: [auth.signatures[0]] }).success).toBe(false);
    expect(ApiAuth.safeParse({ ...auth, nonce: auth.nonce.slice(2) }).success).toBe(false);
    expect(ApiAuth.safeParse({ ...auth, ledgerIndex: 0 }).success).toBe(false);
  });
});

describe('WebSocket messages', () => {
  it('the client subscribes with { subscribe, after }', () => {
    expect(WsClientMessage.parse({ subscribe: '0192f0c8-3c4e-7a2b-8c3d-4e5f6a7b8c9d', after: 5 }).after).toBe(5);
    expect(WsClientMessage.safeParse({ subscribe: '0192f0c8-3c4e-7a2b-8c3d-4e5f6a7b8c9d', after: -2 }).success).toBe(
      false,
    );
  });

  it('the server pushes outbox rows or an error code', () => {
    expect(WsServerMessage.safeParse({ type: 'error', code: 'FORBIDDEN' }).success).toBe(true);
    expect(WS_CLOSE.FORBIDDEN).toBe(4403);
  });
});
