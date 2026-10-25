// The Fastify side: one plain route per implemented contract route, a raw-body JSON parser, hybrid-signature
// authentication on the raw bytes, then the oRPC procedure through `call` (which validates input and output).
// Why not the oRPC Fastify adapter: it bypasses Fastify's body parsing and `bodyLimit`, and every route here needs
// the exact body bytes for SHA-256(body) in the signed message (IMPLEMENTATION 4.3; DESIGN 8.10).
// Source: https://fastify.dev/docs/latest/Reference/ContentTypeParser/ (parseAs: 'buffer' hands over the bytes)
// Source: https://orpc.dev/docs/adapters/fastify  Source: https://orpc.dev/docs/client/server-side (`call`)
import type { AuthRule } from '@legx/contracts/api';
import { listRoutes } from '@legx/contracts/catalog';
import { type AnyProcedure, call, ORPCError } from '@orpc/server';
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import { authenticate } from './auth.ts';
import type { CoordinatorDeps } from './deps.ts';
import { ApiError, badRequest, forbidden } from './errors.ts';
import { procedures } from './routes.ts';

/** Largest request body the API reads. Envelopes are at most 64 KiB (contracts), base64 makes them a third larger. */
export const BODY_LIMIT = 192 * 1024;

const issuesOf = (data: unknown): { path: string; message: string }[] => {
  const issues =
    (data as { issues?: { path?: PropertyKey[]; keys?: string[]; message: string }[] } | undefined)?.issues ?? [];
  return issues.flatMap((i) =>
    i.keys && i.keys.length > 0
      ? i.keys.map((k) => ({ path: [...(i.path ?? []), k].map(String).join('.'), message: i.message }))
      : [{ path: (i.path ?? []).map(String).join('.'), message: i.message }],
  );
};

const SIDE_ROLES: Readonly<Record<string, readonly string[]>> = { A: ['alice', 'lawyerA'], B: ['bob', 'lawyerB'] };

/** `/deals/{dealId}/x` to `/deals/:dealId/x`. */
const fastifyPath = (p: string) => p.replace(/\{(\w+)\}/g, ':$1');

const toNumbers = (q: Record<string, unknown>): Record<string, unknown> =>
  Object.fromEntries(
    Object.entries(q).map(([k, v]) => [k, typeof v === 'string' && /^-?\d{1,15}$/.test(v) ? Number(v) : v]),
  );

export function buildApp(deps: CoordinatorDeps): FastifyInstance {
  const app = Fastify({ logger: false, bodyLimit: BODY_LIMIT });
  // Keep the exact bytes: the signature covers SHA-256(body), so the body must never be re-serialized.
  app.addContentTypeParser('application/json', { parseAs: 'buffer' }, (_req, body, done) => done(null, body));

  app.setErrorHandler((err: unknown, _req, reply) => {
    if (err instanceof ApiError)
      return reply
        .code(err.status)
        .send({ error: err.code, message: err.message, ...(err.issues ? { issues: err.issues } : {}) });
    if (err instanceof ORPCError && err.code === 'BAD_REQUEST')
      return reply
        .code(400)
        .send({ error: 'invalid_request', message: 'request does not match the contract', issues: issuesOf(err.data) });
    const status = (err as { statusCode?: number }).statusCode;
    if (typeof status === 'number' && status >= 400 && status < 500)
      return reply.code(status).send({ error: 'invalid_request', message: (err as Error).message });
    // Never echo internals to a caller.
    return reply.code(500).send({ error: 'internal', message: 'internal error' });
  });

  for (const r of listRoutes()) {
    const procedure = (procedures as Record<string, AnyProcedure>)[r.name];
    if (!procedure) continue; // the route belongs to another service
    const rule = r.auth as AuthRule;
    app.route({
      method: r.method as 'GET' | 'POST',
      url: fastifyPath(r.path as string),
      handler: async (req: FastifyRequest, reply) => {
        const params = req.params as Record<string, string | undefined>;
        const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
        const principal = await authenticate(deps, rule, {
          method: req.method,
          path: req.raw.url as string, // pathname + search exactly as sent (OD-8)
          body: raw,
          header: req.headers['x-legx-auth'] as string | undefined,
          dealId: params.dealId,
        });
        let body: Record<string, unknown> = {};
        if (raw.length > 0) {
          try {
            const parsed: unknown = JSON.parse(raw.toString('utf8'));
            if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed))
              throw new Error('not an object');
            body = parsed as Record<string, unknown>;
          } catch {
            throw badRequest('the body is not a JSON object');
          }
        }
        for (const [k, v] of Object.entries(params))
          if (k in body && body[k] !== v)
            throw badRequest(`${k} differs between path and body`, [{ path: k, message: 'differs from the path' }]);
        const input = { ...toNumbers(req.query as Record<string, unknown>), ...body, ...params };
        // DESIGN 8.10: only the client of `side`, or that client's own lawyer.
        if (rule.ownSideOnly && principal.kind === 'deal' && !SIDE_ROLES[String(input.side)]?.includes(principal.role))
          throw forbidden('other_side', 'only the client of this side or its own lawyer');
        const out = await call(procedure, input, { context: { deps, principal } });
        return reply.send(out);
      },
    });
  }
  return app;
}
