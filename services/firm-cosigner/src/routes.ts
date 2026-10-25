// The firm HSM's signing route (contracts `firmHsm.sign`; I-26, I-28): the lawyer's console asks the HSM to join a
// signing session of its slot as holder 2. The caller is authenticated with the signed request of OD-5 and must be
// the slot's own lawyer; the operations account's signature, the seal, the pair and the message are then checked by
// `FirmCosigner.sign`, which logs every decision. The session runs after the answer: the console sends its round
// messages next, so waiting for the signature here would stall both sides.
// Source: DESIGN 6.4 "Signing rules"; https://fastify.dev/docs/latest/Reference/ContentTypeParser/
import { API_AUTH_HEADER, type AuthRule } from '@legx/contracts/api';
import { listRoutes } from '@legx/contracts/catalog';
import { authenticate } from '@legx/coordinator/auth';
import type { CoordinatorDeps } from '@legx/coordinator/deps';
import { ApiError, badRequest, forbidden } from '@legx/coordinator/errors';
import { hexToBytes } from '@legx/core/dealcore';
import type { FastifyInstance } from 'fastify';
import type { z } from 'zod';
import type { WireApproval } from './approval.ts';
import type { FirmCosigner } from './cosigner.ts';

const LAWYER_OF: Readonly<Record<string, string>> = { LA: 'lawyerA', LB: 'lawyerB' };
const RULE: AuthRule = { kind: 'signed-request', callers: ['lawyerA', 'lawyerB'] };
const INPUT = listRoutes().find((r) => r.name === 'firmHsm.sign')?.input as z.ZodType;

type Body = {
  dealId: string;
  slot: 'LA' | 'LB';
  sessionId: string;
  pair: [number, number];
  seal: string;
  operator: { opsPub: string; sig: string };
  message?: string;
  request?: { kind: 'xrpl-multisign' | 'tagged' | 'gate-record'; tag?: string; parts?: string[] };
  approval?: WireApproval;
};

export interface FirmHttpDeps {
  readonly auth: Pick<CoordinatorDeps, 'db' | 'ledger' | 'lawyerKeys'>;
  readonly cosigner: FirmCosigner;
  /** Where a session that fails after the answer is reported (it is in the audit log already). */
  readonly onError?: (e: unknown) => void;
}

export function registerFirmRoutes(app: FastifyInstance, deps: FirmHttpDeps): void {
  void app.register(async (child) => {
    child.removeContentTypeParser('application/json');
    child.addContentTypeParser('application/json', { parseAs: 'buffer' }, (_req, body, done) => done(null, body));
    child.setErrorHandler((err: unknown, _req, reply) => {
      if (err instanceof ApiError) return reply.code(err.status).send({ error: err.code, message: err.message });
      return reply.code(500).send({ error: 'internal', message: 'internal error' });
    });
    child.post('/deals/:dealId/firm-hsm/sign', async (req, reply) => {
      const { dealId } = req.params as { dealId: string };
      const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
      const who = await authenticate(deps.auth as CoordinatorDeps, RULE, {
        method: req.method,
        path: req.raw.url as string,
        body: raw,
        header: req.headers[API_AUTH_HEADER] as string | undefined,
        dealId,
      });
      let json: unknown;
      try {
        json = JSON.parse(raw.toString('utf8'));
      } catch {
        throw badRequest('the body is not JSON');
      }
      const parsed = INPUT.safeParse({ ...(json as object), dealId });
      if (!parsed.success) throw badRequest('request does not match the contract');
      const b = parsed.data as Body;
      if (who.kind !== 'deal' || who.role !== LAWYER_OF[b.slot])
        throw forbidden('not_this_lawyer', 'only the lawyer of this slot asks its firm HSM');
      if ((b.message === undefined) !== (b.request === undefined))
        throw badRequest('message and request travel together');
      const sign = deps.cosigner.sign({
        dealId,
        slot: b.slot,
        sessionId: b.sessionId,
        pair: b.pair,
        seal: b.seal,
        operator: { opsPub: hexToBytes(b.operator.opsPub), sig: hexToBytes(b.operator.sig) },
        ...(b.message && b.request
          ? {
              message: {
                msg: hexToBytes(b.message),
                kind: b.request.kind === 'xrpl-multisign' ? 'xrpl-multisign' : 'tagged',
                ...(b.request.kind === 'tagged'
                  ? { tagged: { tag: b.request.tag as string, parts: (b.request.parts ?? []).map(hexToBytes) } }
                  : {}),
                ...(b.approval ? { approval: b.approval } : {}),
              },
            }
          : {}),
      });
      sign.catch((e: unknown) => deps.onError?.(e));
      return reply.send({ status: 'started' });
    });
  });
}
