// `GET /demo/attack` lists the scenes, `POST /demo/attack/:name` runs one. These routes are mounted only through the
// server's demo hook, so a production process never has them (P4.5-04, P3.7-05). Scenes run one at a time: they share
// the standalone ledger and each opens its own deal.
import type { FastifyInstance } from 'fastify';
import { ATTACKS, type AttackResult, isAttack, type Scenes } from './types.ts';

export const ATTACK_PATH = '/demo/attack';

export async function registerAttackRoutes(app: FastifyInstance, scenes: Scenes): Promise<void> {
  let queue: Promise<unknown> = Promise.resolve();
  app.get(ATTACK_PATH, async () => ({ attacks: ATTACKS }));
  app.post<{ Params: { name: string } }>(`${ATTACK_PATH}/:name`, async (req, reply) => {
    const { name } = req.params;
    if (!isAttack(name)) return reply.code(404).send({ error: 'unknown_attack', message: name });
    const run = queue.then(async (): Promise<AttackResult> => ({ attack: name, ...(await scenes[name]()) }));
    queue = run.catch(() => undefined);
    try {
      return await run;
    } catch (e) {
      return reply.code(500).send({ error: 'scene_failed', message: e instanceof Error ? e.message : String(e) });
    }
  });
}
