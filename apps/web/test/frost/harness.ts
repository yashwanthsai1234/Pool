// The FROST screens' test world: the typed API client (task 4.1b) over MSW, whose `frost.*` routes run an in-memory relay
// with task 3.9's checks, a stateful `recovery.*` mock (the 72-hour delay by ledger time, cancel), and a mock of the
// firm HSM co-signer endpoint (task 3.10 is not built yet).
import { ApiAuth } from '@legx/contracts/api';
import { type RecoveryStatus, RIPPLE_EPOCH_MS } from '@legx/vault/frost/text';
import { apiRelay, type RelayPort } from '@legx/vault/frost/transport';
import { HttpResponse, http } from 'msw';
import { type MemoryRelay, RelayRefused } from '../../../../packages/vault/test/frost/world.ts';
import { createApiClient } from '../../src/lib/api.ts';
import type { startMocks } from '../../src/mocks/browser.ts';
import { examplesOf } from '../../src/mocks/examples.ts';
import { restHandlers } from '../../src/mocks/handlers.ts';

const AUTH = ApiAuth.parse(examplesOf('ApiAuth')[0]);
export const api = createApiClient({ signRequest: async () => AUTH });
export type Worker = Awaited<ReturnType<typeof startMocks>>;

const refuse = (e: unknown) =>
  HttpResponse.json(
    { code: 'FORBIDDEN', message: e instanceof Error ? e.message : String(e) },
    { status: e instanceof RelayRefused ? 403 : 500 },
  );

/** MSW handlers that put `relay` behind the contract's three `frost.*` routes. */
export function relayHandlers(relay: MemoryRelay) {
  return [
    http.post('*/api/deals/:dealId/frost-sessions', async ({ request }) => {
      const body = (await request.json()) as {
        purpose: 'dkg' | 'sign' | 'refresh' | 'repair';
        participants: { keyId: string }[];
      };
      try {
        const holders = body.participants.map((p) => {
          const h = relay.pinned.get(p.keyId);
          if (!h) throw new RelayRefused(`key_not_pinned ${p.keyId}`);
          return h;
        });
        return HttpResponse.json({ sessionId: await relay.openSession({ purpose: body.purpose, holders }) });
      } catch (e) {
        return refuse(e);
      }
    }),
    http.post('*/api/frost/sessions/:sessionId/messages', async ({ request }) => {
      try {
        const body = (await request.json()) as { message: Parameters<MemoryRelay['send']>[0] };
        return HttpResponse.json(await relay.send(body.message));
      } catch (e) {
        return refuse(e);
      }
    }),
    http.get('*/api/frost/sessions/:sessionId/messages', async ({ request, params }) => {
      const q = new URL(request.url).searchParams;
      try {
        const messages = await relay.receive(
          String(params.sessionId),
          String(q.get('recipient')),
          Number(q.get('afterSeq')),
        );
        return HttpResponse.json({ messages });
      } catch (e) {
        return refuse(e);
      }
    }),
  ];
}

/** The phone's relay: the API client through MSW. */
export const phoneRelay = (dealId: string, slot: string): RelayPort => apiRelay(api as never, { dealId, slot });

/** Ledger time the tests move by hand (ms). */
export const ledger = { now: Date.UTC(2026, 9, 24, 12) };
const toRipple = (ms: number) => Math.floor((ms - RIPPLE_EPOCH_MS) / 1000);

/** The coordinator's recovery routes as a small state machine (the agent's checks are task 3.9's). */
export function recoveryHandlers() {
  const recoveries = new Map<string, RecoveryStatus & { startedAt: number }>();
  const view = (r: RecoveryStatus & { startedAt: number }): RecoveryStatus => {
    const state = r.state === 'waiting' && ledger.now >= r.startedAt + 72 * 3600_000 ? 'ready' : r.state;
    r.state = state;
    const { startedAt: _s, ...out } = r;
    return out;
  };
  const handlers = [
    http.post('*/api/deals/:dealId/recoveries', async ({ request, params }) => {
      const body = (await request.json()) as { slot: string };
      const r = {
        recoveryId: '0192f3a0-0000-7000-8000-0000000000aa',
        dealId: String(params.dealId),
        slot: body.slot,
        state: 'waiting' as const,
        readyAt: toRipple(ledger.now + 72 * 3600_000),
        startedAt: ledger.now,
      };
      recoveries.set(r.recoveryId, r);
      return HttpResponse.json(view(r));
    }),
    http.get('*/api/recoveries/:id', ({ params }) => {
      const r = recoveries.get(String(params.id));
      return r ? HttpResponse.json(view(r)) : HttpResponse.json({ code: 'NOT_FOUND' }, { status: 404 });
    }),
    http.post('*/api/recoveries/:id/cancel', ({ params }) => {
      const r = recoveries.get(String(params.id));
      if (!r) return HttpResponse.json({ code: 'NOT_FOUND' }, { status: 404 });
      if (view(r).state === 'waiting') r.state = 'cancelled';
      return HttpResponse.json(view(r));
    }),
  ];
  return { handlers, recoveries };
}

/** Every other route answers with its golden example, after the handlers above. */
export const fallback = () => restHandlers();
