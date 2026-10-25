// @legx/coordinator: the persisted deal state machine and its API (IMPLEMENTATION 3.2).
// `register(app, deps)` is the shape every service has (Phase 3 "Shape"); `buildApp` makes a stand-alone instance.
import type { FastifyInstance } from 'fastify';
import { buildApp } from './app.ts';
import type { CoordinatorDeps } from './deps.ts';

export type { CoordinatorDeps, GateInput, GatePort, GateResult, PinnedKey } from './deps.ts';
export { pinEnrollmentKey } from './enroll.ts';
export { recoverDeal } from './signatures.ts';
export { buildApp };

/** Mounts the coordinator on a Fastify instance the caller owns, under no prefix. */
export async function register(app: FastifyInstance, deps: CoordinatorDeps): Promise<void> {
  await app.register(async (child) => {
    const inner = buildApp(deps);
    child.route({
      method: ['GET', 'POST'],
      url: '*',
      handler: async (req, reply) => {
        const res = await inner.inject({
          method: req.method as 'GET' | 'POST',
          url: req.raw.url as string,
          headers: req.headers as Record<string, string>,
          payload: req.body as Buffer,
        });
        reply.code(res.statusCode).headers(res.headers).send(res.rawPayload);
      },
    });
  });
}
