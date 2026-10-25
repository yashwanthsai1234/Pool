import type { ServerDeps } from '../deps.ts';
import { ATTACK_PATH, registerAttackRoutes } from './routes.ts';
import type { Scenes } from './types.ts';

export { ATTACK_PATH } from './routes.ts';
export * from './types.ts';

/** The value for `ServerDeps.demo`. `scenes` is `realScenes(...)` from `./scenes.ts`, or a stub in a test. */
export function demoAttacks(scenes: Scenes): NonNullable<ServerDeps['demo']> {
  return { pathPrefix: ATTACK_PATH, register: (app) => registerAttackRoutes(app, scenes) };
}
