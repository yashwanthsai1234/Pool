// An in-memory stand-in for the coordinator's WebSocket: the same protocol as `@legx/contracts/ws`.
// A client sends `{ subscribe, after }`; the mock replays every outbox row after `after`, then pushes new rows.
// It can also misbehave on purpose (drop sockets, overlap a replay, skip a row), for the reconnect tests.
// Source: https://mswjs.io/docs/api/ws (ws.link, the `connection` event, client.send / client.close)
import { WS_CLOSE, WsClientMessage, WsServerMessage } from '@legx/contracts/ws';
import { ws } from 'msw/ws';
import type { z } from 'zod';
import { LIVE_PATH } from '../lib/paths.ts';

type Row = Extract<z.infer<typeof WsServerMessage>, { type: 'row' }>;
type Topic = Row['topic'];

interface Subscription {
  readonly dealId: string;
  readonly send: (data: string) => void;
}

export function createLiveMock() {
  const link = ws.link(new RegExp(`${LIVE_PATH}(\\?.*)?$`));
  const outbox = new Map<string, Row[]>();
  const clients = new Map<{ close: (code?: number, reason?: string) => void }, Subscription | undefined>();
  const requests: z.infer<typeof WsClientMessage>[] = [];
  const urls: string[] = [];
  const faults = { overlapReplay: 0, skipNext: 0 };

  const rowsOf = (dealId: string) => outbox.get(dealId) ?? [];
  const frame = (row: Row) => JSON.stringify(row);

  const handler = link.addEventListener('connection', ({ client }) => {
    urls.push(String(client.url));
    clients.set(client, undefined);
    client.addEventListener('message', (event) => {
      let parsed: ReturnType<typeof WsClientMessage.safeParse>;
      try {
        parsed = WsClientMessage.safeParse(JSON.parse(String(event.data)));
      } catch {
        return client.close(WS_CLOSE.BAD_REQUEST);
      }
      if (!parsed.success) return client.close(WS_CLOSE.BAD_REQUEST);
      requests.push(parsed.data);
      const { subscribe: dealId, after } = parsed.data;
      const from = faults.overlapReplay > 0 ? Math.max(after - faults.overlapReplay, -1) : after;
      faults.overlapReplay = 0;
      for (const row of rowsOf(dealId)) if (row.seq > from) client.send(frame(row));
      clients.set(client, { dealId, send: (data) => client.send(data) });
    });
    client.addEventListener('close', () => {
      clients.delete(client);
    });
  });

  return {
    handler,
    /** The URL of every socket a client opened, in order (the query carries `auth`). */
    urls,
    /** Pushes a frame the contract does not list, such as the server's `{type:'ledger'}` push (OD-9). */
    pushRaw(dealId: string, body: object) {
      for (const sub of clients.values()) if (sub?.dealId === dealId) sub.send(JSON.stringify(body));
    },
    /** Every `{ subscribe, after }` a client sent, in order. */
    requests,
    /** Appends an outbox row with the next gap-free `seq` and pushes it to subscribers. */
    publish(dealId: string, topic: Topic, payload: string): Row {
      const rows = outbox.get(dealId) ?? [];
      outbox.set(dealId, rows);
      const row = WsServerMessage.parse({ type: 'row', dealId, seq: rows.length, topic, payload }) as Row;
      rows.push(row);
      if (faults.skipNext > 0) {
        faults.skipNext -= 1;
        return row;
      }
      for (const sub of clients.values()) if (sub?.dealId === dealId) sub.send(frame(row));
      return row;
    },
    /** Drops every socket as a network failure would (close code 1006). */
    drop() {
      for (const client of [...clients.keys()]) client.close(1006, 'dropped');
      clients.clear();
    },
    /** The next replay starts `n` rows too early, so the client sees repeats. */
    overlapNextReplay(n: number) {
      faults.overlapReplay = n;
    },
    /** The next `n` pushed rows are stored but never sent, so the client sees a gap. */
    skipNextPush(n: number) {
      faults.skipNext = n;
    },
    /** Closes every socket with an application close code, as the real server does. */
    reject(code: keyof typeof WS_CLOSE) {
      for (const client of clients.keys()) client.close(WS_CLOSE[code], code);
    },
  };
}

/** `deal.state` payload: UTF-8 JSON `{ state }`, base64 (see DQ-4.1b in build/status/4.1b.md). */
export const statePayload = (state: string) => btoa(JSON.stringify({ state }));
