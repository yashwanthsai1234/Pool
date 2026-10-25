// The agent's HTTP surface: the well-known key list, and the recovery routes of the contract (`recovery.start`,
// `recovery.cancel`, `recovery.get`). Callers are authenticated with the same signed request as every other route
// (OD-5). Recovery has two more proofs of its own: a client start carries the fresh zero-knowledge proof and is signed
// by the NEW key it enrolls; a lawyer start carries the operations account's signature over LAWYER_RECOVERY_TAG
// (deal, slot, new key, fresh ledger index; I-S-F1); a cancel carries the old device's signature over the cancel
// statement.
// Source: DESIGN 6.4 "Recovery rules", 8.10 (API authentication)
import { API_AUTH_HEADER, API_MAX_LEDGER_AGE, type AuthRule } from '@legx/contracts/api';
import { listRoutes } from '@legx/contracts/catalog';
import { authenticate, type Principal } from '@legx/coordinator/auth';
import type { CoordinatorDeps } from '@legx/coordinator/deps';
import { ApiError, badRequest, forbidden, unauthorized } from '@legx/coordinator/errors';
import { RecoveryError } from '@legx/core/frostRules';
import type { ServiceKeyList } from '@legx/core/frostSetup';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { z } from 'zod';
import { AgentRefusal } from './agent.ts';
import { type RecoveryService, type RecoveryView, Refusal } from './recovery.ts';

const RIPPLE_EPOCH = 946_684_800;
const DEAL_ROLES: AuthRule = { kind: 'signed-request', callers: ['alice', 'lawyerA', 'bob', 'lawyerB'] };

export interface AgentHttpDeps {
  /** What request authentication reads: pinned enrollment keys, the validated ledger, the lawyer directory. */
  readonly auth: Pick<CoordinatorDeps, 'db' | 'ledger' | 'lawyerKeys'>;
  readonly recoveries: RecoveryService;
  readonly keyList: () => ServiceKeyList & { anchorTx?: string };
}

const input = (name: string): z.ZodType => (listRoutes().find((r) => r.name === name) as { input: z.ZodType }).input;
const unhex = (s: string) => new Uint8Array(Buffer.from(s, 'hex'));

const status = (v: RecoveryView) => ({
  recoveryId: v.recoveryId,
  dealId: v.dealId,
  slot: v.slot,
  state: v.state,
  readyAt: Math.floor(v.readyAt / 1000) - RIPPLE_EPOCH,
});

export function registerAgentRoutes(app: FastifyInstance, deps: AgentHttpDeps): void {
  void app.register(async (child) => {
    child.removeContentTypeParser('application/json');
    child.addContentTypeParser('application/json', { parseAs: 'buffer' }, (_req, body, done) => done(null, body));
    child.setErrorHandler((err: unknown, _req, reply) => {
      if (err instanceof ApiError) return reply.code(err.status).send({ error: err.code, message: err.message });
      if (err instanceof RecoveryError || err instanceof Refusal || err instanceof AgentRefusal)
        return reply.code(422).send({ error: err.code, message: err.message });
      const s = (err as { statusCode?: number }).statusCode;
      if (typeof s === 'number' && s >= 400 && s < 500)
        return reply.code(s).send({ error: 'invalid_request', message: (err as Error).message });
      return reply.code(500).send({ error: 'internal', message: 'internal error' });
    });

    const principal = async (req: FastifyRequest, dealId?: string): Promise<Principal> =>
      await authenticate(deps.auth as CoordinatorDeps, DEAL_ROLES, {
        method: req.method,
        path: req.raw.url as string,
        body: Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0),
        header: req.headers[API_AUTH_HEADER] as string | undefined,
        dealId,
      });
    const body = (req: FastifyRequest): Record<string, unknown> => {
      try {
        return JSON.parse((req.body as Buffer).toString('utf8')) as Record<string, unknown>;
      } catch {
        throw badRequest('the body is not a JSON object');
      }
    };

    child.get('/.well-known/legx/recovery-agent-keys.json', async (_req, reply) => {
      const l = deps.keyList();
      return reply.send({
        list: Buffer.from(l.bytes).toString('base64'),
        signerPub: Buffer.from(l.signerPub).toString('hex'),
        sig: Buffer.from(l.sig).toString('hex'),
        ...(l.anchorTx ? { anchorTx: l.anchorTx } : {}),
      });
    });

    child.post('/deals/:dealId/recoveries', async (req, reply) => {
      const { dealId } = req.params as { dealId: string };
      const who = await principal(req, dealId);
      const parsed = input('recovery.start').safeParse({ ...body(req), dealId });
      if (!parsed.success) throw badRequest('request does not match the contract');
      const r = parsed.data as
        | { kind: 'client'; slot: 'A' | 'B'; newKeyId: string; proof: never }
        | {
            kind: 'lawyer';
            slot: 'LA' | 'LB';
            newKeyId: string;
            ledgerIndex: number;
            opsSig: { opsPub: string; sig: string };
          };
      if (who.pairId !== r.newKeyId) throw forbidden('wrong_key', 'a recovery is requested by the new key it enrolls');
      if (r.kind === 'client')
        return reply.send(
          status(await deps.recoveries.startClient({ dealId, slot: r.slot, newKeyId: r.newKeyId, proof: r.proof })),
        );
      // The signed ledger index must be fresh, like an API request's (OD-5), so an old signature is useless.
      const validated = (await deps.auth.ledger.validatedLedger()).ledgerIndex;
      if (r.ledgerIndex < validated - API_MAX_LEDGER_AGE || r.ledgerIndex > validated)
        throw unauthorized('stale_ledger_index', 'the recovery request names a stale ledger index');
      return reply.send(
        status(
          await deps.recoveries.startLawyer({
            dealId,
            slot: r.slot,
            newKeyId: r.newKeyId,
            ledgerIndex: r.ledgerIndex,
            opsPub: unhex(r.opsSig.opsPub),
            sig: unhex(r.opsSig.sig),
          }),
        ),
      );
    });

    // The deal of a recovery comes from the recovery itself, so the routes need no dealId in the path or the query.
    // An unknown recovery is authenticated against no deal: a signed stranger gets 403, an unsigned one 401 (I-3.7-f).
    const ownRecovery = async (req: FastifyRequest, recoveryId: string): Promise<RecoveryView> => {
      const view = await deps.recoveries.get(recoveryId).catch(() => undefined);
      await principal(req, view?.dealId ?? '');
      if (view === undefined) throw forbidden('wrong_deal', 'not this deal');
      return view;
    };

    child.post('/recoveries/:recoveryId/cancel', async (req, reply) => {
      const { recoveryId } = req.params as { recoveryId: string };
      const who = await ownRecovery(req, recoveryId);
      const parsed = input('recovery.cancel').safeParse({
        ...body(req),
        recoveryId,
        dealId: who.dealId,
      }) as z.ZodSafeParseResult<{ cancelSig: string; oldDevicePub: string }>;
      if (!parsed.success) throw badRequest('request does not match the contract');
      return reply.send(
        status(
          await deps.recoveries.cancel({
            recoveryId,
            sig: unhex(parsed.data.cancelSig),
            oldDevicePub: unhex(parsed.data.oldDevicePub),
          }),
        ),
      );
    });

    child.get('/recoveries/:recoveryId', async (req, reply) => {
      const { recoveryId } = req.params as { recoveryId: string };
      return reply.send(status(await ownRecovery(req, recoveryId)));
    });
  });
}
