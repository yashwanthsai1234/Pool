// The FROST relay as a library: `register(app, deps)` is the shape every service has (Phase 3 "Shape").
import type { FastifyInstance } from 'fastify';
import type { CoordinatorDeps } from '../deps.ts';
import { FrostRelay, type RelayOptions } from './relay.ts';
import { registerFrostRoutes } from './routes.ts';
import { RelayStore } from './store.ts';

export { DEFAULT_SIGN_TIMEOUT_MS, FrostRelay, type RelayCode, type SessionStatusView } from './relay.ts';
export { decodeSigned, type RelayMessage, signedBytes, toCore } from './schema.ts';
export { RelayStore } from './store.ts';

/** Mounts the relay routes on `app` (the queue tables come from the db migrations). */
export async function register(
  app: FastifyInstance,
  deps: CoordinatorDeps,
  opts: RelayOptions = {},
): Promise<FrostRelay> {
  const relay = new FrostRelay(deps, new RelayStore(deps.db), opts);
  registerFrostRoutes(app, deps, relay);
  return relay;
}
