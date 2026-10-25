import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { registerProductRoutes } from '../demo-product/routes.ts';
import type { ServerDeps } from '../deps.ts';
import { registerWalkthroughRoutes } from './routes.ts';
import type { WalkthroughDeps } from './walkthrough.ts';

export * from './types.ts';
export type { WalkthroughDeps } from './walkthrough.ts';

type DemoHook = NonNullable<ServerDeps['demo']>;

/**
 * The server has one demo hook: this adds the walkthrough routes to another hook (attack mode), under the common
 * `/demo` prefix, and the product demo's routes next to them. The value for `ServerDeps.demo`, demo profile only.
 */
export function withWalkthrough(
  inner: DemoHook,
  o: { env: Readonly<Record<string, string | undefined>>; ledgerWs: string; pgUrl: string },
): DemoHook {
  const deps: WalkthroughDeps = {
    ledgerWs: o.ledgerWs,
    network: 'standalone', // the demo profile's ledger (demo.ts standaloneEnv)
    pgUrl: o.pgUrl,
    statePath: o.env.LEGX_DEMO_STATE ?? 'demo/state.json', // as demo.ts pinnedFromSeed reads it
    shipReadyFlag: resolve(import.meta.dirname, '../../../../build/tmp/ship-core-ready'),
  };
  return {
    pathPrefix: '/demo/',
    register: async (app) => {
      if (existsSync(deps.statePath))
        deps.seed = JSON.parse(readFileSync(deps.statePath, 'utf8')) as NonNullable<WalkthroughDeps['seed']>;
      await inner.register(app);
      await registerWalkthroughRoutes(app, deps);
      // the product demo (build/PRODUCT_DEMO.md) on the same engine; PDFs go under the demo data folder (demo.ts)
      await registerProductRoutes(app, { ...deps, dataDir: o.env.LEGX_DATA_DIR ?? '.legx-data' });
    },
  };
}
