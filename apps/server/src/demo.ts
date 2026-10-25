// The demo profile's adapters (DESIGN 14, IMPLEMENTATION 5.6): a standalone ledger, key files in the data folder, a
// local object store, the in-process log, the mock bar registry. Every port is marked `demo: true`, so the production
// profile refuses the whole set (P3.7-05). Nothing here is reachable from a production start. Everything else is the
// shared composition of `stack.ts`.
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileCheckpointSigner, fileSigner } from '@legx/signer';
import { inProcessLog } from '@legx/storage/inProcessLog';
import { localObjectStore } from '@legx/storage/localStore';
import { demoAdapter, manualAdapter } from '@legx/verifier';
import { standaloneEnv } from '@legx/xrpl/env';
import { fundAccount } from '@legx/xrpl/fund';
import { advanceLedgers } from '@legx/xrpl/ledger';
import { demoAgentDeps, demoFirmDeps } from './agents.ts';
import { demoAttacks } from './demo-attacks/index.ts';
import { realScenes } from './demo-attacks/scenes.ts';
import { type Adapters, type Built, buildStack } from './stack.ts';
import { verifyScriptText } from './verifyScript.ts';

export type { Built } from './stack.ts';

export const DEFAULTS = {
  pg: 'postgres://postgres:pw@127.0.0.1:5510/postgres',
  ledger: 'ws://127.0.0.1:6113',
  registry: 'http://127.0.0.1:7070',
  data: '.legx-data',
  sepoliaRpc: 'https://ethereum-sepolia-rpc.publicnode.com',
} as const;

interface StateKey {
  keyId: string;
  ed25519Public: string;
  mlDsa65Public: string;
}

/**
 * The demo enrollment keys that `scripts/demo/seed.ts` wrote to `demo/state.json` (OD-31: the observer key is made at
 * seeding), as the pinned-key variables the shared composition reads. A variable the caller already set wins.
 */
function pinnedFromSeed(env: Readonly<Record<string, string | undefined>>): Record<string, string> {
  const path = env.LEGX_DEMO_STATE ?? 'demo/state.json';
  if (!existsSync(path)) return {};
  const st = JSON.parse(readFileSync(path, 'utf8')) as { observer?: StateKey; keys?: Record<string, StateKey> };
  const pin = (keys: (StateKey | undefined)[]) =>
    JSON.stringify(
      Object.fromEntries(
        keys.flatMap((k) =>
          k
            ? [
                [
                  k.keyId,
                  {
                    ed25519: k.ed25519Public.slice(-64),
                    mlDsa65: Buffer.from(k.mlDsa65Public.slice(-3904), 'hex').toString('base64'),
                  },
                ],
              ]
            : [],
        ),
      ),
    );
  return {
    ...(env.LEGX_LAWYER_KEYS === undefined
      ? { LEGX_LAWYER_KEYS: pin([st.keys?.['lawyer-a'], st.keys?.['lawyer-b']]) }
      : {}),
    ...(env.LEGX_OBSERVER_KEYS === undefined ? { LEGX_OBSERVER_KEYS: pin([st.observer]) } : {}),
    ...(env.LEGX_OPERATOR_KEYS === undefined ? { LEGX_OPERATOR_KEYS: pin([st.keys?.operator]) } : {}),
  };
}

export async function buildDemo(env: Readonly<Record<string, string | undefined>>): Promise<Built> {
  const dir = env.LEGX_DATA_DIR ?? DEFAULTS.data;
  mkdirSync(dir, { recursive: true });
  const ledgerWs = env.LEGX_LEDGER_WS ?? DEFAULTS.ledger;
  const ledgerEnv = standaloneEnv(ledgerWs);
  const registryUrl = env.LEGX_BAR_REGISTRY ?? DEFAULTS.registry;
  const demoEnv = { ...env, LEGX_PROFILE: 'demo' }; // the key files refuse to open under any other profile
  // Keys live in files, so the service and checkpoint keys survive a restart (I-W-12).
  const signer = fileSigner(join(dir, 'service-keys.json'), demoEnv);
  const checkpointSigner = fileCheckpointSigner(join(dir, 'checkpoint-keys.json'), demoEnv);
  const objects = localObjectStore({ dir });
  const stops: (() => Promise<void>)[] = [];
  const funded = (xrp: number) => async (client: Parameters<Adapters['issuer']>[0]) => {
    const w = await fundAccount(ledgerEnv, client, xrp);
    return { address: w.classicAddress, sign: async (tx: Record<string, unknown>) => w.sign(tx as never).tx_blob };
  };
  const manual = manualAdapter();
  const adapters: Adapters = {
    profile: 'demo',
    ledgerEnv,
    signer,
    checkpointSigner,
    objects,
    origin: 'legx.local/demo',
    makeLog: async (clock, pool) => {
      const log = inProcessLog({ origin: 'legx.local/demo', signer: checkpointSigner, clock });
      // The log lives in memory: put back the leaves of the events it already held, in their old order, so the tree
      // extends the checkpoints already published (an empty tree would contradict them).
      const held = await pool.query<{ envelope: Buffer }>(
        'select e.envelope from evidence_log_entry l join evidence_event e using (event_id) order by l.log_index',
      );
      for (const e of held.rows) await log.add(new Uint8Array(e.envelope));
      return log;
    },
    issuer: async (client) => {
      // A standalone ledger closes only when asked: close one every second so the validated index moves.
      const closer = setInterval(
        () => void advanceLedgers(client, 1).catch(() => undefined),
        Number(env.LEGX_LEDGER_CLOSE_MS ?? 1000),
      );
      stops.push(async () => clearInterval(closer));
      return funded(100)(client);
    },
    anchor: funded(50),
    barAdapters: new Map([
      ['XA', demoAdapter({ baseUrl: registryUrl, jurisdictions: { XA: 'XA-DM' } })],
      ['XM', manual],
    ]),
    manual,
    zk: {
      profile: 'demo',
      devMode: true,
      rpcUrls: [env.LEGX_ZK_RPC ?? DEFAULTS.sepoliaRpc],
    },
    ports: {
      ledger: { impl: 'standalone', demo: true },
      signer: { impl: 'file', demo: true },
      'checkpoint-signer': { impl: 'file', demo: true },
      'object-store': { impl: 'local', demo: true },
      'transparency-log': { impl: 'in-process', demo: true },
      'bar-registry': {
        impl: 'demo-mock',
        demo: true,
        check: async () => (await fetch(registryUrl, { signal: AbortSignal.timeout(2000) })).status < 500,
      },
      'zk-verifier': { impl: 'adapter-dev-mode', demo: true },
    },
    verifyScript: await verifyScriptText(),
    agents: async (c) => ({
      recovery: demoAgentDeps(c, { dir }),
      firm: await demoFirmDeps(c, {
        dir,
        signer: fileSigner(join(dir, 'firm-hsm-signer.json'), demoEnv), // the HSM's own key, not the coordinator's
        rp: {
          rpId: env.LEGX_RP_ID ?? 'localhost',
          origin: env.LEGX_RP_ORIGIN ?? 'http://localhost:5173',
        },
      }),
    }),
    demo: demoAttacks(realScenes(ledgerWs)), // attack mode (task 4.5), demo profile only
    stops,
  };
  return await buildStack({ ...pinnedFromSeed(env), ...env, LEGX_PG: env.LEGX_PG ?? DEFAULTS.pg }, adapters);
}
