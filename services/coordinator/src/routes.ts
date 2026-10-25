// The oRPC implementation of the coordinator's routes. Contract-first: the route table, input and output schemas
// come from `@legx/contracts/api`; oRPC validates every input and every output against them. The HTTP side is plain
// Fastify (app.ts) because every route is a signed request over the raw body.
// Source: https://orpc.dev/docs/contract-first/implement-contract

import { contract } from '@legx/contracts/api';
import { KeyNotRecorded } from '@legx/db';
import { implement } from '@orpc/server';
import type { Principal } from './auth.ts';
import { createDeal, loadConfig, requireDeal, setContract, setWallet, viewOf } from './deal.ts';
import type { CoordinatorDeps } from './deps.ts';
import { myDeals, registerKey } from './enroll.ts';
import { forbidden, notFound } from './errors.ts';
import { appendEvent, headOf } from './events.ts';
import { getIdentityBoxes, putIdentityBox } from './identityBox.ts';
import { accountInfo, submitBlob } from './ledgerRelay.ts';
import { getPresence, openPresence, submitPresence } from './presence.ts';
import { dealKeys, derivePublicData } from './publicData.ts';
import { createRequest, listRequests, submitSignature } from './signatures.ts';

export interface Ctx {
  deps: CoordinatorDeps;
  principal: Principal;
}

const os = implement(contract).$context<Ctx>();

function dealRole(c: Ctx) {
  if (c.principal.kind !== 'deal') throw forbidden('role_not_allowed', 'a deal role is required');
  return c.principal;
}

const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');

/** Every route this service implements, by route name. Routes of other services are absent on purpose. */
export const procedures = {
  'deals.create': os.deals.create.handler(({ input, context }) => createDeal(context.deps, input)),
  'deals.mine': os.deals.mine.handler(({ context }) => myDeals(context.deps, context.principal)),
  'deals.get': os.deals.get.handler(({ input, context }) => viewOf(context.deps.db.repos, input.dealId)),
  'deals.setWallet': os.deals.setWallet.handler(({ input, context }) =>
    setWallet(context.deps, input.dealId, input.walletAddress),
  ),
  'deals.setContract': os.deals.setContract.handler(({ input, context }) =>
    setContract(context.deps, input.dealId, input.contractRoot),
  ),
  'deals.keys': os.deals.keys.handler(async ({ input, context }) => {
    await requireDeal(context.deps.db.repos, input.dealId);
    return { keys: await dealKeys(context.deps.db.repos, input.dealId) };
  }),
  'deals.publicData': os.deals.publicData.handler(async ({ input, context }) => {
    const repos = context.deps.db.repos;
    const deal = await requireDeal(repos, input.dealId);
    const r = await derivePublicData(repos, deal, (await loadConfig(repos, input.dealId)).identity_policy);
    return r.status === 'complete'
      ? { status: 'complete' as const, publicData: r.publicData, dealSeal: r.dealSeal, domain: r.domain }
      : { status: 'incomplete' as const, missing: r.missing };
  }),
  'events.head': os.events.head.handler(async ({ input, context }) => {
    await requireDeal(context.deps.db.repos, input.dealId);
    return await headOf(context.deps.db.repos, input.dealId);
  }),
  'events.append': os.events.append.handler(async ({ input, context }) => {
    const p = dealRole(context);
    return await appendEvent(context.deps, p, input.dealId, input.envelope);
  }),
  'events.list': os.events.list.handler(async ({ input, context }) => {
    await requireDeal(context.deps.db.repos, input.dealId);
    const rows = await context.deps.db.repos.evidenceEvents.listAfter(input.dealId, input.afterSeq, input.limit);
    return { events: rows.map((r) => ({ seq: r.seq, envelope: b64(r.envelope) })) };
  }),
  'signatures.create': os.signatures.create.handler(({ input, context }) =>
    createRequest(context.deps, input.dealId, input.purpose),
  ),
  'signatures.list': os.signatures.list.handler(async ({ input, context }) => ({
    requests: await listRequests(context.deps, input.dealId),
  })),
  'signatures.submit': os.signatures.submit.handler(({ input, context }) =>
    submitSignature(context.deps, dealRole(context).role, input),
  ),
  'keys.register': os.keys.register.handler(({ input, context }) =>
    registerKey(context.deps, context.principal, input),
  ),
  'presence.open': os.presence.open.handler(({ input, context }) =>
    openPresence(context.deps, input.dealId, input.side, input.request),
  ),
  'presence.get': os.presence.get.handler(({ input, context }) => getPresence(context.deps, input.dealId, input.side)),
  'presence.submit': os.presence.submit.handler(({ input, context }) =>
    submitPresence(context.deps, input.dealId, input.side, input.lawyerNonce, input.signature),
  ),
  'identityBox.put': os.identityBox.put.handler(({ input, context }) =>
    putIdentityBox(context.deps, input.dealId, input.side, input.kind, input.box),
  ),
  'identityBox.get': os.identityBox.get.handler(
    ({ input, context }) => getIdentityBoxes(context.deps, input.dealId, input.side) as never,
  ),
  'ledger.accountInfo': os.ledger.accountInfo.handler(({ input, context }) =>
    accountInfo(context.deps.ledger, input.address),
  ),
  'ledger.submit': os.ledger.submit.handler(({ input, context }) => submitBlob(context.deps.ledger, input.txBlob)),
  'keys.get': os.keys.get.handler(async ({ input, context }) => {
    try {
      const k = await context.deps.db.repos.enrollmentKeys.getUsable(input.keyId);
      const { deal_id: _d, evidence_event_id: _e, ...key } = k;
      return key;
    } catch (e) {
      if (e instanceof KeyNotRecorded) throw notFound('no such enrollment key');
      throw e;
    }
  }),
};
