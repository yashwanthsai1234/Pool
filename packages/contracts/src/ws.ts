// Live updates over WebSocket (IMPLEMENTATION 3.7, 4.1): the client sends `{ subscribe, after }`; the server
// replays every outbox row of that deal after `after` and then pushes new rows. WebSocket, not server-sent
// events, because the cloudflared backup tunnel does not carry server-sent events (IMPLEMENTATION 4.7).
// Source: https://www.rfc-editor.org/rfc/rfc6455 (close codes 4000-4999 are for applications)
import { z } from 'zod';
import { Base64, DealId, LedgerIndex, RippleTime, XrplHash } from './values.ts';

/** Client to server. `after: -1` replays from the first row; `seq` is gap-free per deal. */
export const WsClientMessage = z.strictObject({ subscribe: DealId, after: z.int().min(-1) });

/**
 * Outbox topics (DESIGN 9 `outbox.topic`). A `deal.event` payload is the exact envelope bytes (OD-9).
 * `ledger.validated` is `{index, hash, close_time}` of every validated ledger the server sees (OD-9, OD-10).
 * `frost.session` announces an opened FROST session to the slot's other holders: `{sessionId, slot, purpose, pair?}`.
 */
export const OutboxTopic = z.enum([
  'deal.event',
  'deal.state',
  'signature.request',
  'ledger.observation',
  'ledger.validated',
  'frost.session',
  'alert',
]);

/** The `ledger.validated` payload (OD-9). */
export const LedgerValidated = z.strictObject({
  index: LedgerIndex,
  hash: XrplHash,
  close_time: RippleTime,
});

/** Server to client: one pushed outbox row, or an error before the server closes the socket. */
export const WsServerMessage = z.discriminatedUnion('type', [
  z.strictObject({
    type: z.literal('row'),
    dealId: DealId,
    seq: z.int().min(0),
    topic: OutboxTopic,
    payload: Base64(65536),
  }),
  z.strictObject({ type: z.literal('error'), code: z.enum(['BAD_REQUEST', 'FORBIDDEN', 'OVERFLOW']) }),
]);

/** Close codes: 4400 bad message, 4403 not allowed to read this deal, 4408 send queue overflowed (resubscribe). */
export const WS_CLOSE = { BAD_REQUEST: 4400, FORBIDDEN: 4403, OVERFLOW: 4408 } as const;
