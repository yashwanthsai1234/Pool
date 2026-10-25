// Test doubles for the live feed: an in-memory outbox with NOTIFY, a bare Fastify server around a hub, and a client
// that records what it receives.
import { randomUUID } from 'node:crypto';
import websocket from '@fastify/websocket';
import Fastify from 'fastify';
import WebSocket from 'ws';
import { type FeedRow, LiveHub, type LiveOptions, type LiveSource } from '../../src/live.ts';

export class MemorySource implements LiveSource {
  readonly deals = new Map<string, FeedRow[]>();
  ledger: { id: string; payload: Uint8Array } | undefined;
  readonly listeners = new Set<(p: string) => void>();
  /** Set to false to model a NOTIFY that never arrives (the poll must still deliver). */
  notifyOn = true;
  reads = 0;

  append(dealId: string, payload = `{"n":1}`, topic = 'deal.event'): number {
    const rows = this.deals.get(dealId) ?? [];
    const seq = rows.length;
    rows.push({ seq, topic, payload: new TextEncoder().encode(payload) });
    this.deals.set(dealId, rows);
    if (this.notifyOn) for (const l of this.listeners) l(dealId);
    return seq;
  }
  pushLedger(index: number): void {
    this.ledger = {
      id: randomUUID(),
      payload: new TextEncoder().encode(JSON.stringify({ index, hash: 'AB'.repeat(32), close_time: index })),
    };
    if (this.notifyOn) for (const l of this.listeners) l('ledger.validated');
  }
  async rowsAfter(dealId: string, after: number, limit: number): Promise<readonly FeedRow[]> {
    this.reads++;
    return (this.deals.get(dealId) ?? []).filter((r) => r.seq > after).slice(0, limit);
  }
  async latestLedger() {
    return this.ledger;
  }
  async onNotify(fn: (p: string) => void) {
    this.listeners.add(fn);
    return async () => void this.listeners.delete(fn);
  }
}

export async function hubServer(
  source: LiveSource,
  opts: Partial<LiveOptions> = {},
  canRead: (deal: string) => Promise<boolean> = async () => true,
) {
  const hub = new LiveHub({ source, pollMs: 50, ...opts });
  const app = Fastify();
  await app.register(websocket);
  app.get('/ws', { websocket: true }, (socket) => hub.attach(socket, canRead));
  await hub.start();
  await app.listen({ port: 0, host: '127.0.0.1' });
  const port = (app.server.address() as { port: number }).port;
  return {
    hub,
    app,
    url: `ws://127.0.0.1:${port}/ws`,
    close: async () => {
      await hub.stop();
      await app.close();
    },
  };
}

export interface Msg {
  type: string;
  dealId?: string;
  seq?: number;
  topic?: string;
  payload?: unknown;
  code?: string;
}

/** A WebSocket client that subscribes on open and records every message and the close code. */
export class Client {
  readonly messages: Msg[] = [];
  closeCode: number | undefined;
  readonly ws: WebSocket;
  readonly closed: Promise<number>;
  constructor(url: string, dealId: string, after: number, opts: { pause?: boolean } = {}) {
    this.ws = new WebSocket(url);
    this.closed = new Promise((resolve) =>
      this.ws.on('close', (code) => {
        this.closeCode = code;
        resolve(code);
      }),
    );
    this.ws.on('open', () => {
      this.ws.send(JSON.stringify({ subscribe: dealId, after }));
      if (opts.pause) this.ws.pause();
    });
    this.ws.on('message', (raw: Buffer) => this.messages.push(JSON.parse(raw.toString('utf8'))));
    this.ws.on('error', () => undefined);
  }
  get rows(): number[] {
    return this.messages.filter((m) => m.type === 'row').map((m) => m.seq as number);
  }
  async waitFor(pred: () => boolean, ms = 5000): Promise<void> {
    const end = Date.now() + ms;
    while (!pred()) {
      if (Date.now() > end)
        throw new Error(`timeout; got ${JSON.stringify(this.rows.slice(-5))} (${this.rows.length} rows)`);
      await new Promise((r) => setTimeout(r, 5));
    }
  }
  async waitSeq(seq: number, ms = 5000): Promise<void> {
    await this.waitFor(() => this.rows.at(-1) === seq, ms);
  }
  close(code?: number): void {
    this.ws.close(code);
  }
}

export const range = (from: number, to: number) => Array.from({ length: to - from + 1 }, (_, i) => from + i);
