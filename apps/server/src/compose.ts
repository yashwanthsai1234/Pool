// One Fastify 5 process from the Phase 3 services (IMPLEMENTATION 3.7). Each service brings a `register(app, deps)`;
// this file only decides which ports go where, by profile, and refuses a profile that does not fit.
//   coordinator (3.2) + FROST relay (3.9)   mounted at the root, signed requests on the raw body
//   evidence (3.4) + post-quantum parts (3.12), verifier (3.3), ZK verifier (3.11), watcher (3.5): their ports,
//       their routes, their health
//   recovery agent (3.9), firm co-signer (3.10): separate optional processes in production, mounted in the demo
// Source: https://fastify.dev/docs/latest/Reference/Plugins/  Source: https://github.com/fastify/fastify-websocket

import websocket from '@fastify/websocket';
import { API_AUTH_HEADER, type AuthRule } from '@legx/contracts/api';
import { authenticate, canReadDeal, type Principal } from '@legx/coordinator/auth';
import type { CoordinatorDeps, PinnedKey } from '@legx/coordinator/deps';
import { ApiError, unauthorized } from '@legx/coordinator/errors';
import { register as registerRelay } from '@legx/coordinator/frost/index';
import type { RelayOptions } from '@legx/coordinator/frost/relay';
import { register as registerCoordinator } from '@legx/coordinator/index';
import type { BundleDeps } from '@legx/evidence/bundle';
import type { RecordsDeps } from '@legx/evidence/records';
import { type FirmCosigner, register as registerFirm, registerFirmRoutes } from '@legx/firm-cosigner';
import { register as registerAgent } from '@legx/recovery-agent';
import type { AgentHttpDeps } from '@legx/recovery-agent/routes';
import type { Verifier } from '@legx/verifier/service';
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import { CHIP_LINK_PREFIX, registerChipLink } from './chipLink.ts';
import { assertProfile, type PortSpec, type ProfileName, type ZkSettings } from './config.ts';
import type { ServerDeps } from './deps.ts';
import { LiveHub, type LiveOptions } from './live.ts';
import { mountRoutes } from './routes.ts';

/** Largest request body. Envelopes are at most 64 KiB, base64 makes them a third larger (the coordinator's limit). */
export const BODY_LIMIT = 192 * 1024;
export const LIVE_PATH = '/ws';
/** `frame-ancestors 'none'`: no page may frame the API. The web app's own host sets its own policy (apps/web/csp.ts). */
export const DEFAULT_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

export interface Server {
  readonly app: FastifyInstance;
  readonly hub: LiveHub;
  health(): Promise<HealthBody>;
  close(): Promise<void>;
}

export interface HealthBody {
  profile: ProfileName;
  ports: Record<string, { impl: string; status: 'ok' | 'down' }>;
}

const WS_RULE: AuthRule = { kind: 'signed-request', callers: ['enrolled', 'lawyer', 'observer'] };

export async function buildServer(d: ServerDeps): Promise<Server> {
  const mounted: Record<string, PortSpec> = {
    coordinator: { impl: 'mounted', demo: false },
    'frost-relay': { impl: 'mounted', demo: false },
    ...(d.evidence ? { evidence: { impl: 'mounted', demo: false } } : {}),
    ...(d.verifier ? { verifier: { impl: 'mounted', demo: false } } : {}),
    ...(d.agents?.recovery ? { 'recovery-agent': { impl: 'mounted', demo: true } } : {}),
    ...(d.agents?.firm ? { 'firm-cosigner': { impl: 'mounted', demo: true } } : {}),
    ...(d.demo ? { 'demo-routes': { impl: 'mounted', demo: true } } : {}),
    'live-feed': { impl: 'websocket', demo: false },
    database: {
      impl: 'postgres',
      demo: false,
      check: async () => {
        await d.coordinator.db.repos.outbox.listAfter('00000000-0000-0000-0000-000000000000', 0, 1);
        return true;
      },
    },
  };
  const ports: Record<string, PortSpec> = { ...mounted, ...d.ports };
  assertProfile({
    profile: d.profile,
    ports,
    zk: d.zk,
    env: d.env,
    agentsMounted: d.agents?.recovery !== undefined || d.agents?.firm !== undefined,
  });

  const app = Fastify({ logger: false, bodyLimit: BODY_LIMIT });
  // The signature covers SHA-256(body): keep the exact bytes, never re-serialize.
  app.addContentTypeParser('application/json', { parseAs: 'buffer' }, (_req, body, done) => done(null, body));
  // Defence in depth for the service libraries that read the body before they authenticate: no header, no further.
  app.addHook('onRequest', async (req) => {
    const path = req.raw.url?.split('?')[0];
    if (path === '/health' || path === LIVE_PATH) return; // the upgrade is authenticated by its own hook
    if (path?.startsWith(CHIP_LINK_PREFIX)) return; // the phone has no signing key (chipLink.ts)
    if (d.demo && path?.startsWith(d.demo.pathPrefix)) return; // demo-only routes (assertProfile refused them in production)
    if (req.headers[API_AUTH_HEADER] === undefined)
      throw unauthorized('auth_malformed', `missing ${API_AUTH_HEADER} header`);
  });
  app.addHook('onSend', async (_req, reply, payload) => {
    reply.header('content-security-policy', d.csp ?? DEFAULT_CSP);
    reply.header('x-content-type-options', 'nosniff');
    reply.header('referrer-policy', 'no-referrer');
    reply.header('cache-control', 'no-store');
    return payload;
  });
  app.setErrorHandler((err: unknown, _req, reply) => {
    if (err instanceof ApiError)
      return reply
        .code(err.status)
        .send({ error: err.code, message: err.message, ...(err.issues ? { issues: err.issues } : {}) });
    const e = err as { statusCode?: number; status?: number; code?: string; message?: string };
    const status = e.statusCode ?? e.status;
    if (typeof status === 'number' && status >= 400 && status < 500)
      return reply.code(status).send({ error: e.code ?? 'invalid_request', message: e.message });
    if ((err as Error).name === 'VerifierError') return reply.code(422).send({ error: e.code, message: e.message });
    // The client learns nothing; the operator gets the error's name, message and stack (never the request body).
    process.stderr.write(
      `legx server: 500 ${_req.method} ${_req.url.split('?')[0]}: ${(err as Error).stack ?? String(err)}\n`,
    );
    return reply.code(500).send({ error: 'internal', message: 'internal error' }); // never echo internals
  });

  const health = async (): Promise<HealthBody> => {
    const out: HealthBody['ports'] = {};
    for (const [name, p] of Object.entries(ports)) {
      let ok = true;
      try {
        ok = p.check ? await p.check() : true;
      } catch {
        ok = false;
      }
      out[name] = { impl: p.impl, status: ok ? 'ok' : 'down' };
    }
    return { profile: d.profile, ports: out };
  };

  mountRoutes(app, d, health);
  registerChipLink(app);
  await registerRelay(app, d.coordinator, d.relay);
  if (d.agents?.recovery) await registerAgent(app, d.agents.recovery);
  const firm = d.agents?.firm;
  if (firm) {
    const { cosigner, onError, ...recovery } = firm;
    await app.register(async (child) => registerFirm(child, recovery), { prefix: '/firm' });
    if (cosigner) registerFirmRoutes(app, { auth: firm.auth, cosigner, ...(onError ? { onError } : {}) });
  }
  if (d.demo) await d.demo.register(app);
  await registerCoordinator(app, d.coordinator); // last: its wildcard answers whatever nobody else claimed

  const hub = new LiveHub(d.live);
  await app.register(websocket);
  const principals = new WeakMap<FastifyRequest, Principal>();
  app.get(
    LIVE_PATH,
    {
      websocket: true,
      // The upgrade is a signed GET on the path alone; browsers cannot set headers, so `?auth=` carries the header value.
      preValidation: async (req) => {
        const url = new URL(req.raw.url as string, 'http://x');
        const auth = (req.headers[API_AUTH_HEADER] as string | undefined) ?? url.searchParams.get('auth') ?? undefined;
        url.searchParams.delete('auth');
        const raw = {
          method: 'GET',
          path: url.pathname + url.search,
          body: new Uint8Array(),
          header: auth,
          dealId: undefined,
        };
        principals.set(req, await authenticate(d.coordinator, WS_RULE, raw));
      },
    },
    (socket, req) => {
      const p = principals.get(req);
      hub.attach(socket, async (dealId) => (p ? await canRead(d, p, dealId) : false));
    },
  );
  await hub.start();

  return {
    app,
    hub,
    health,
    close: async () => {
      await hub.stop();
      await app.close();
    },
  };
}

const canRead = (d: ServerDeps, p: Principal, dealId: string): Promise<boolean> =>
  d.canRead ? d.canRead(p, dealId) : canReadDeal(d.coordinator, p, dealId);
