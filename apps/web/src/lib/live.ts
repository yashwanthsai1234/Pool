// Live updates over WebSocket into the TanStack Query cache (P4.1-03, P4.1-04). The client sends
// `{ subscribe, after }`; the server replays every outbox row after `after`, then pushes new rows. Each row
// carries a gap-free per-deal `seq`, so the client applies row `lastSeq + 1`, drops anything older (a repeat)
// and reconnects when it sees a jump (a gap), asking again from its own `lastSeq`.
// Source: https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API (events open, message, close)
// Source: https://www.rfc-editor.org/rfc/rfc6455#section-7.4 (close codes; 4000-4999 are for applications)
// Source: https://tanstack.com/query/latest/docs/reference/QueryClient#queryclientsetquerydata

import { DealState } from '@legx/contracts/values';
import type { OutboxTopic } from '@legx/contracts/ws';
import { LedgerValidated, WS_CLOSE, WsClientMessage, WsServerMessage } from '@legx/contracts/ws';
import { type QueryClient, skipToken, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import type { z } from 'zod';
import { LIVE_PATH } from './paths.ts';

type DealStateName = z.infer<typeof DealState>;
export type LiveStatus = 'connecting' | 'open' | 'reconnecting' | 'closed';
export interface LiveRow {
  readonly seq: number;
  readonly topic: z.infer<typeof OutboxTopic>;
  /** Base64 payload exactly as the server sent it. */
  readonly payload: string;
}
export interface LiveRows {
  readonly lastSeq: number;
  readonly rows: readonly LiveRow[];
}

/** Cache keys. The rows (and the last applied `seq`) live in the cache, so a remounted screen resumes without a gap. */
export const liveRowsKey = (dealId: string) => ['deal', dealId, 'live'] as const;
export const dealStateKey = (dealId: string) => ['deal', dealId, 'state'] as const;

export interface LiveFeedOptions {
  dealId: string;
  queryClient: QueryClient;
  onStatus?: (status: LiveStatus) => void;
  /** Default: same origin, `LIVE_PATH`. */
  url?: string;
  /**
   * The signed `x-legx-auth` header value (JSON) for the upgrade `GET /ws`. Browsers cannot set headers on a socket, so
   * it travels in `?auth=` and is made again on every (re)connect (the nonce is single use). Source: build/DECISIONS.md OD-5.
   */
  auth?: () => Promise<string>;
  /** Every validated ledger the server pushes (OD-9, OD-10): the clients' source for the signed-request ledger index. */
  onLedger?: (ledger: z.infer<typeof LedgerValidated>) => void;
  /** Delay before reconnect attempt `n` (0-based). Default: 250 ms doubling up to 5 s. */
  backoffMs?: (attempt: number) => number;
}

const defaultUrl = () => `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}${LIVE_PATH}`;
const defaultBackoff = (attempt: number) => Math.min(250 * 2 ** attempt, 5000);
const EMPTY: LiveRows = { lastSeq: -1, rows: [] };
// Errors the server will repeat on every retry; the feed stops instead of looping.
const TERMINAL_CLOSE: readonly number[] = [WS_CLOSE.BAD_REQUEST, WS_CLOSE.FORBIDDEN];

// `deal.state` rows carry `{ "state": <DealState> }` as UTF-8 JSON (DQ-4.1b: the contracts do not type the payload yet).
function decodeState(payload: string): DealStateName | undefined {
  try {
    const bytes = Uint8Array.from(atob(payload), (c) => c.charCodeAt(0));
    const json: unknown = JSON.parse(new TextDecoder().decode(bytes));
    const parsed = DealState.safeParse((json as { state?: unknown } | null)?.state);
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}

/** Starts the feed for one deal. Returns `stop`, which closes the socket and cancels any pending reconnect. */
export function startLiveFeed(options: LiveFeedOptions): { stop: () => void } {
  const { dealId, queryClient, onStatus } = options;
  const url = options.url ?? defaultUrl();
  const backoff = options.backoffMs ?? defaultBackoff;
  let socket: WebSocket | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let attempt = 0;
  let stopped = false;
  let status: LiveStatus | undefined;

  const setStatus = (next: LiveStatus) => {
    if (next === status) return;
    status = next;
    onStatus?.(next);
  };
  const current = () => queryClient.getQueryData<LiveRows>(liveRowsKey(dealId)) ?? EMPTY;

  const apply = (row: LiveRow) => {
    const state = row.topic === 'deal.state' ? decodeState(row.payload) : undefined;
    queryClient.setQueryData<LiveRows>(liveRowsKey(dealId), (old = EMPTY) => ({
      lastSeq: row.seq,
      rows: [...old.rows, row],
    }));
    if (state) queryClient.setQueryData(dealStateKey(dealId), state);
  };

  const scheduleReconnect = () => {
    if (stopped) return;
    setStatus('reconnecting');
    timer = setTimeout(connect, backoff(attempt++));
  };

  async function connect() {
    if (stopped) return;
    let target = url;
    if (options.auth) {
      try {
        target = `${url}?auth=${encodeURIComponent(await options.auth())}`;
      } catch {
        return scheduleReconnect(); // nothing is sent without a signature
      }
      if (stopped) return;
    }
    const ws = new WebSocket(target);
    socket = ws;
    let terminal = false;
    ws.addEventListener('open', () => {
      attempt = 0;
      setStatus('open');
      ws.send(JSON.stringify(WsClientMessage.parse({ subscribe: dealId, after: current().lastSeq })));
    });
    ws.addEventListener('message', (event) => {
      const raw = safeJson(event.data);
      // The server also pushes `{type:'ledger', topic:'ledger.validated', payload}` (OD-9): read it. Any other `type` the
      // contract does not know yet is skipped, not fatal (I-3.7-b).
      const type = (raw as { type?: unknown } | null)?.type;
      if (type === 'ledger') {
        const ledger = LedgerValidated.safeParse((raw as { payload?: unknown }).payload);
        if (ledger.success) options.onLedger?.(ledger.data);
        return;
      }
      if (typeof type === 'string' && type !== 'row' && type !== 'error') return;
      const parsed = WsServerMessage.safeParse(raw);
      if (!parsed.success) return ws.close(WS_CLOSE.BAD_REQUEST); // a malformed frame: drop the socket and resync
      const msg = parsed.data;
      if (msg.type === 'error') {
        terminal = msg.code !== 'OVERFLOW';
        return;
      }
      if (msg.dealId !== dealId) return;
      const last = current().lastSeq;
      if (msg.seq <= last) return; // a repeat
      if (msg.seq > last + 1) return ws.close(); // a gap: reconnect and ask again from `last`
      apply({ seq: msg.seq, topic: msg.topic, payload: msg.payload });
    });
    ws.addEventListener('close', (event) => {
      if (socket !== ws) return;
      if (terminal || TERMINAL_CLOSE.includes(event.code)) return setStatus('closed');
      scheduleReconnect();
    });
  }

  setStatus('connecting');
  connect();
  return {
    stop: () => {
      stopped = true;
      clearTimeout(timer);
      const ws = socket;
      socket = undefined;
      ws?.close();
      setStatus('closed');
    },
  };
}

function safeJson(data: unknown): unknown {
  try {
    return typeof data === 'string' ? JSON.parse(data) : undefined;
  } catch {
    return undefined;
  }
}

/** The live status and the newest deal state for one deal. Mount it where the deal is shown. */
export function useLiveDeal(
  dealId: string,
  options: Pick<LiveFeedOptions, 'url' | 'backoffMs' | 'auth' | 'onLedger'> = {},
) {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<LiveStatus>('connecting');
  const { url, backoffMs, auth, onLedger } = options;
  useEffect(() => {
    const feed = startLiveFeed({
      dealId,
      queryClient,
      onStatus: setStatus,
      ...(url === undefined ? {} : { url }),
      ...(backoffMs === undefined ? {} : { backoffMs }),
      ...(auth === undefined ? {} : { auth }),
      ...(onLedger === undefined ? {} : { onLedger }),
    });
    return feed.stop;
  }, [dealId, queryClient, url, backoffMs, auth, onLedger]);
  const state = useQuery<DealStateName>({ queryKey: dealStateKey(dealId), queryFn: skipToken });
  const rows = useQuery<LiveRows>({ queryKey: liveRowsKey(dealId), queryFn: skipToken });
  return { status, state: state.data, lastSeq: rows.data?.lastSeq ?? -1 };
}
