// The relay's HTTP routes: the three `frost.*` routes of the contract plus a `status` read (not in the contract).
// Every holder of the slot uses them (`share-holder`, I-S-A1): the recovery agent and the firm HSM act only here. Authentication is the same signed request as every other route (OD-5), run on the raw body
// bytes; the message inside is authenticated again, by the sender's enrollment keys, in the relay itself.
// Source: https://fastify.dev/docs/latest/Reference/ContentTypeParser/ (a child context may replace the JSON parser)
import { API_AUTH_HEADER, type AuthRule } from '@legx/contracts/api';
import { listRoutes } from '@legx/contracts/catalog';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { z } from 'zod';
import { authenticate, type Principal } from '../auth.ts';
import type { CoordinatorDeps } from '../deps.ts';
import { ApiError, badRequest, forbidden } from '../errors.ts';
import type { FrostRelay } from './relay.ts';

/** `share-holder` is the contract's name for "a participant of the session"; the session check below enforces it. */
const HOLDER_RULE: AuthRule = {
  kind: 'signed-request',
  callers: ['share-holder', 'enrolled'],
};

const inputOf = (name: string): z.ZodType => {
  const r = listRoutes().find((x) => x.name === name);
  if (!r) throw new Error(`contract has no route ${name}`);
  return r.input as z.ZodType;
};

function parseBody(raw: Buffer): Record<string, unknown> {
  if (raw.length === 0) return {};
  try {
    const parsed: unknown = JSON.parse(raw.toString('utf8'));
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
    return parsed as Record<string, unknown>;
  } catch {
    throw badRequest('the body is not a JSON object');
  }
}

export function registerFrostRoutes(app: FastifyInstance, deps: CoordinatorDeps, relay: FrostRelay): void {
  void app.register(async (child) => {
    child.removeContentTypeParser('application/json');
    child.addContentTypeParser('application/json', { parseAs: 'buffer' }, (_req, body, done) => done(null, body));
    child.setErrorHandler((err: unknown, _req, reply) => {
      if (err instanceof ApiError) return reply.code(err.status).send({ error: err.code, message: err.message });
      const status = (err as { statusCode?: number }).statusCode;
      if (typeof status === 'number' && status >= 400 && status < 500)
        return reply.code(status).send({ error: 'invalid_request', message: (err as Error).message });
      return reply.code(500).send({ error: 'internal', message: 'internal error' });
    });

    const principalOf = async (req: FastifyRequest, dealId?: string): Promise<Principal> => {
      const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
      return await authenticate(deps, HOLDER_RULE, {
        method: req.method,
        path: req.raw.url as string, // pathname + search as sent (OD-8)
        body: raw,
        header: req.headers[API_AUTH_HEADER] as string | undefined,
        dealId,
      });
    };
    const parse = <T>(name: string, value: unknown): T => {
      const r = inputOf(name).safeParse(value);
      if (!r.success) throw badRequest('request does not match the contract');
      return r.data as T;
    };
    /** The caller must be a participant of the session: its key pair is one of the three. */
    const mustBeParticipant = async (sessionId: string, p: Principal) => {
      const s = await relay.status(sessionId);
      const members = await relay.participants(sessionId);
      if (!members.some((m) => m.keyId === p.pairId))
        throw forbidden('not_a_participant', 'not a holder of this session');
      return s;
    };

    child.post('/deals/:dealId/frost-sessions', async (req, reply) => {
      const { dealId } = req.params as { dealId: string };
      const principal = await principalOf(req, dealId);
      const input = parse<{
        dealId: string;
        slot: string;
        purpose: 'dkg' | 'sign' | 'refresh' | 'repair';
        participants: { identifier: string; keyId: string; role: string }[];
        pair?: [string, string];
      }>('frost.openSession', { ...parseBody(req.body as Buffer), dealId });
      if (!input.participants.some((p) => p.keyId === principal.pairId))
        throw forbidden('not_a_participant', 'the opener must be a holder of the session');
      const sessionId = await relay.openSession(input);
      return reply.send({ sessionId });
    });

    child.post('/frost/sessions/:sessionId/messages', async (req, reply) => {
      const { sessionId } = req.params as { sessionId: string };
      const principal = await principalOf(req);
      const input = parse<{ sessionId: string; message: Parameters<FrostRelay['send']>[0] }>('frost.send', {
        ...parseBody(req.body as Buffer),
        sessionId,
      });
      if (input.message.key_id !== principal.pairId)
        throw forbidden('wrong_sender', 'the message is signed by another key');
      return reply.send(await relay.send(input.message));
    });

    child.get('/frost/sessions/:sessionId/messages', async (req, reply) => {
      const { sessionId } = req.params as { sessionId: string };
      const principal = await principalOf(req);
      const q = req.query as Record<string, string>;
      const input = parse<{ recipient: string; afterSeq: number }>('frost.receive', {
        sessionId,
        recipient: q.recipient,
        afterSeq: Number(q.afterSeq),
      });
      const members = await relay.participants(sessionId);
      const me = members.find((m) => m.identifier === input.recipient);
      if (!me || me.keyId !== principal.pairId)
        throw forbidden('not_a_participant', 'recipient is not your identifier');
      return reply.send({ messages: await relay.receive(sessionId, input.recipient, input.afterSeq) });
    });

    child.get('/frost/sessions/:sessionId/status', async (req, reply) => {
      const { sessionId } = req.params as { sessionId: string };
      const principal = await principalOf(req);
      return reply.send(await mustBeParticipant(sessionId, principal));
    });
  });
}
