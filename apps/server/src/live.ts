// The live feed (IMPLEMENTATION 3.7). A client sends `{subscribe, after}`; the server replays every outbox row of that
// deal after `after`, then pushes new rows as Postgres NOTIFY wakes it. NOTIFY only wakes the pump; the data always
// comes from the outbox table, so a lost or duplicated NOTIFY can neither lose nor repeat a row.
//   - one serialized pump per socket (replay and live are the same code path),
//   - a bounded send queue per socket: a client that does not read is closed with 4408 and subscribes again from its
//     last `seq`; one slow client never blocks another,
//   - `ledger.validated` pushes (OD-9) go to every subscribed socket.
// Source: https://www.rfc-editor.org/rfc/rfc6455 (close codes 4000-4999 are for applications)
// Source: https://www.postgresql.org/docs/18/sql-notify.html (NOTIFY is delivered after commit, may be coalesced)
import { WS_CLOSE, WsClientMessage } from '@legx/contracts/ws';
import type { WebSocket } from 'ws';
import { serial } from './serial.ts';

/** One outbox row as the feed reads it. */
export interface FeedRow {
  readonly seq: number;
  readonly topic: string;
  readonly payload: Uint8Array;
}

/** Where the hub reads from: the outbox table and the NOTIFY channel (Postgres), or a fake in tests. */
export interface LiveSource {
  rowsAfter(dealId: string, after: number, limit: number): Promise<readonly FeedRow[]>;
  /** The newest `ledger.validated` row, if any, with its unique id. */
  latestLedger(): Promise<{ readonly id: string; readonly payload: Uint8Array } | undefined>;
  /** `fn(payload)` for every NOTIFY; `fn('')` after a reconnect (anything may have been missed). Returns the unsubscribe. */
  onNotify(fn: (payload: string) => void): Promise<() => Promise<void>>;
}

export interface LiveOptions {
  readonly source: LiveSource;
  /** Most unflushed messages per socket. Default 256. */
  readonly maxQueue?: number;
  /** A socket that cannot take a message for this long is closed with 4408. Default 10 000 ms. */
  readonly stallMs?: number;
  /** Fallback wake-up in case NOTIFY is not wired (the outbox writers do not call `pg_notify`, I-3.7-a). Default 1000 ms. */
  readonly pollMs?: number;
  /**
   * A row that is not the next `seq` (its predecessor has not committed yet) is held back this long, then sent anyway:
   * the client sees the jump and subscribes again. Writers hold the deal's head lock, so commits are in `seq` order and
   * this only guards a writer that does not. Default 2000 ms.
   */
  readonly gapWaitMs?: number;
  /** Rows per replay page. Default 200. */
  readonly pageSize?: number;
  /** Push `ledger.validated` (OD-9). Default true. */
  readonly ledgerPush?: boolean;
}

interface Session {
  readonly socket: WebSocket;
  readonly dealId: string;
  last: number;
  /** When the current discontinuity was first seen. */
  gapSince: number | undefined;
  outstanding: number;
  readonly waiters: Set<(ok: boolean) => void>;
  pump: () => Promise<void>;
  closed: boolean;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class LiveHub {
  readonly #o: Required<Omit<LiveOptions, 'source'>> & { source: LiveSource };
  readonly #byDeal = new Map<string, Set<Session>>();
  #unlisten: (() => Promise<void>) | undefined;
  #timer: NodeJS.Timeout | undefined;
  #lastLedgerId: string | undefined;
  readonly #ledgerPump = serial(() => this.#pushLedger());
  #stopped = false;

  constructor(o: LiveOptions) {
    this.#o = {
      maxQueue: 256,
      stallMs: 10_000,
      pollMs: 1000,
      pageSize: 200,
      gapWaitMs: 2000,
      ledgerPush: true,
      ...o,
    };
  }

  async start(): Promise<void> {
    if (this.#o.ledgerPush) this.#lastLedgerId = (await this.#o.source.latestLedger())?.id; // only NEW ledgers are pushed
    this.#unlisten = await this.#o.source.onNotify((p) => this.#wake(p));
    this.#timer = setInterval(() => this.#wake(''), this.#o.pollMs);
    this.#timer.unref();
  }

  async stop(): Promise<void> {
    this.#stopped = true;
    if (this.#timer) clearInterval(this.#timer);
    await this.#unlisten?.();
    for (const set of this.#byDeal.values()) for (const s of [...set]) s.socket.close(1001);
  }

  /** Number of subscribed sockets (health and tests). */
  get sockets(): number {
    let n = 0;
    for (const set of this.#byDeal.values()) n += set.size;
    return n;
  }

  /**
   * Serves one WebSocket. `canRead` is decided by the caller from the authenticated upgrade request. The first message
   * must be a valid subscribe; anything else closes the socket with 4400, a deal the caller may not read with 4403.
   */
  attach(socket: WebSocket, canRead: (dealId: string) => Promise<boolean>): void {
    let session: Session | undefined;
    let busy = false;
    socket.on('message', (raw: Buffer) => {
      if (busy || session) return socket.close(WS_CLOSE.BAD_REQUEST); // one subscription per socket, one message at a time
      busy = true;
      void this.#subscribe(socket, raw, canRead)
        .then((s) => {
          session = s;
        })
        .finally(() => {
          busy = false;
        });
    });
    socket.on('close', () => {
      if (session) this.#drop(session);
    });
    socket.on('error', () => socket.terminate());
  }

  async #subscribe(socket: WebSocket, raw: Buffer, canRead: (dealId: string) => Promise<boolean>) {
    const parsed = WsClientMessage.safeParse(parseJson(raw));
    if (!parsed.success) return void this.#reject(socket, 'BAD_REQUEST', WS_CLOSE.BAD_REQUEST);
    const { subscribe: dealId, after } = parsed.data;
    let allowed = false;
    try {
      allowed = await canRead(dealId);
    } catch {
      allowed = false;
    }
    if (!allowed) return void this.#reject(socket, 'FORBIDDEN', WS_CLOSE.FORBIDDEN);
    if (this.#stopped || socket.readyState !== socket.OPEN) return undefined;
    const s: Session = {
      socket,
      dealId,
      last: after,
      gapSince: undefined,
      outstanding: 0,
      waiters: new Set(),
      pump: () => Promise.resolve(),
      closed: false,
    };
    s.pump = serial(() => this.#replay(s));
    const set = this.#byDeal.get(dealId) ?? new Set<Session>();
    this.#byDeal.set(dealId, set);
    set.add(s); // listener first, then the first pump: a NOTIFY during the replay only schedules one more run
    await s.pump().catch(() => this.#overflow(s));
    return s;
  }

  #reject(socket: WebSocket, code: 'BAD_REQUEST' | 'FORBIDDEN', closeCode: number): void {
    socket.send(JSON.stringify({ type: 'error', code }), () => socket.close(closeCode));
  }

  /** The pump body: read the outbox after `last` in pages, send in order, wait for room before each row. */
  async #replay(s: Session): Promise<void> {
    for (;;) {
      if (s.closed) return;
      const rows = await this.#o.source.rowsAfter(s.dealId, s.last, this.#o.pageSize);
      for (const row of rows) {
        if (row.seq <= s.last) continue; // never a repeat
        if (row.seq !== s.last + 1) {
          // never a gap: wait for the missing row (the next wake-up or the poll reads again)
          s.gapSince ??= Date.now();
          if (Date.now() - s.gapSince < this.#o.gapWaitMs) return;
        }
        s.gapSince = undefined;
        if (!(await this.#room(s))) return;
        this.#send(s, {
          type: 'row',
          dealId: s.dealId,
          seq: row.seq,
          topic: row.topic,
          payload: Buffer.from(row.payload).toString('base64'),
        });
        s.last = row.seq;
      }
      if (rows.length < this.#o.pageSize) return;
    }
  }

  /** Resolves true when the socket can take one more message; false (and the socket is closed with 4408) if it stalls. */
  #room(s: Session): Promise<boolean> {
    if (s.closed) return Promise.resolve(false);
    if (s.outstanding < this.#o.maxQueue) return Promise.resolve(true);
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        s.waiters.delete(done);
        this.#overflow(s);
        resolve(false);
      }, this.#o.stallMs);
      const done = (ok: boolean) => {
        clearTimeout(timer);
        resolve(ok);
      };
      s.waiters.add(done);
    });
  }

  #send(s: Session, message: unknown): void {
    if (s.closed || s.socket.readyState !== s.socket.OPEN) return;
    s.outstanding++;
    s.socket.send(JSON.stringify(message), (err) => {
      s.outstanding--;
      if (err) return s.socket.terminate();
      if (s.outstanding < this.#o.maxQueue)
        for (const w of [...s.waiters]) {
          s.waiters.delete(w);
          w(true);
        }
    });
  }

  /** Closes a socket whose queue is full: the client subscribes again from its last `seq`. */
  #overflow(s: Session): void {
    if (s.closed) return;
    s.socket.close(WS_CLOSE.OVERFLOW);
    const t = setTimeout(() => s.socket.terminate(), 1000); // a stuck client never answers the close frame
    t.unref();
    this.#drop(s);
  }

  #drop(s: Session): void {
    s.closed = true;
    this.#byDeal.get(s.dealId)?.delete(s);
    if (this.#byDeal.get(s.dealId)?.size === 0) this.#byDeal.delete(s.dealId);
    for (const w of [...s.waiters]) w(false);
    s.waiters.clear();
  }

  #wake(payload: string): void {
    if (this.#stopped) return;
    if (UUID.test(payload)) {
      for (const s of this.#byDeal.get(payload.toLowerCase()) ?? []) void s.pump().catch(() => this.#overflow(s));
    } else {
      for (const set of this.#byDeal.values()) for (const s of set) void s.pump().catch(() => this.#overflow(s));
    }
    if (this.#o.ledgerPush && (payload === '' || payload === 'ledger.validated'))
      void this.#ledgerPump().catch(() => undefined);
  }

  async #pushLedger(): Promise<void> {
    const latest = await this.#o.source.latestLedger();
    if (!latest || latest.id === this.#lastLedgerId) return;
    this.#lastLedgerId = latest.id;
    const body = parseJson(Buffer.from(latest.payload));
    if (body === undefined) return;
    for (const set of this.#byDeal.values())
      for (const s of set) {
        if (s.outstanding >= this.#o.maxQueue) this.#overflow(s);
        else this.#send(s, { type: 'ledger', topic: 'ledger.validated', payload: body });
      }
  }
}

function parseJson(raw: Buffer): unknown {
  try {
    return JSON.parse(raw.toString('utf8'));
  } catch {
    return undefined;
  }
}
