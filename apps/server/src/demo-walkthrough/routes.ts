// `POST /demo/walkthrough` creates a walkthrough, `POST /demo/walkthrough/:id/next` runs its next step, `GET
// /demo/walkthrough/:id` reads it. Mounted only through the server's demo hook, so a production process never has them
// (P4.5-04, P3.7-05). Steps run one at a time across walkthroughs: they share the ledger and its closer.
// Source: build/WALKTHROUGH.md
import type { FastifyInstance, FastifyReply } from 'fastify';
import { z } from 'zod';
import { WALKTHROUGH_PATH } from './types.ts';
import { Walkthrough, type WalkthroughDeps, WalkthroughError } from './walkthrough.ts';

const Body = z.strictObject({
  amountXrp: z.number().min(0.000001).max(1000),
  identity: z.enum(['zk', 'chip']),
  delivery: z.enum(['none', 'physical']).optional(), // OD-38: delivery is mandatory; an old client's value is ignored
});

export async function registerWalkthroughRoutes(app: FastifyInstance, deps: WalkthroughDeps): Promise<void> {
  const walks = new Map<string, Walkthrough>();
  let queue: Promise<unknown> = Promise.resolve();
  const serial = <T>(f: () => Promise<T>): Promise<T> => {
    const run = queue.then(f);
    queue = run.catch(() => undefined);
    return run;
  };
  const answer = async (reply: FastifyReply, f: () => Promise<unknown>) => {
    try {
      return await f();
    } catch (e) {
      if (e instanceof WalkthroughError) return reply.code(e.status).send({ error: e.code, message: e.message });
      return reply.code(500).send({ error: 'walkthrough_failed', message: e instanceof Error ? e.message : String(e) });
    }
  };
  app.addHook('onClose', async () => {
    await Promise.all([...walks.values()].map((w) => w.close().catch(() => undefined)));
  });

  app.post(WALKTHROUGH_PATH, async (req, reply) => {
    const raw = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '';
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return reply.code(400).send({ error: 'invalid_request', message: 'the body is not JSON' });
    }
    const body = Body.safeParse(parsed);
    if (!body.success) return reply.code(400).send({ error: 'invalid_request', message: body.error.message });
    return answer(reply, () =>
      serial(async () => {
        const w = await Walkthrough.create(app, deps, { amountXrp: body.data.amountXrp, identity: body.data.identity });
        walks.set(w.id, w);
        const { id, dealId, steps } = w.state();
        return { id, dealId, steps };
      }),
    );
  });
  app.get<{ Params: { id: string } }>(`${WALKTHROUGH_PATH}/:id`, async (req, reply) => {
    const w = walks.get(req.params.id);
    return w ? w.state() : reply.code(404).send({ error: 'unknown_walkthrough', message: req.params.id });
  });
  app.post<{ Params: { id: string } }>(`${WALKTHROUGH_PATH}/:id/next`, async (req, reply) => {
    const w = walks.get(req.params.id);
    if (!w) return reply.code(404).send({ error: 'unknown_walkthrough', message: req.params.id });
    return answer(reply, () => serial(() => w.next()));
  });
}
