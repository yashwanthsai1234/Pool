// A watcher's view of one ledger server: JSON-RPC over WebSocket plus the pushed events of one subscription.
import type { XrplJson } from '@legx/contracts/ports';
import xrpl from 'xrpl';
import { type Rpc, rpcOf } from '../read.ts';

export type LinkEvent =
  /** A `transaction` stream message, exactly as pushed (validated or not: the watcher decides). */
  | { readonly type: 'transaction'; readonly message: XrplJson }
  /** A `ledger` stream message: a ledger was validated. */
  | { readonly type: 'ledger'; readonly index: number; readonly hash: string }
  /** The socket (re)connected. Every subscription made on the earlier socket is gone. */
  | { readonly type: 'up' }
  | { readonly type: 'down' };

export interface Link extends Rpc {
  readonly name: string;
  /** Subscribes to the `accounts` stream for `accounts` and to the `ledger` stream. Never the proposed-transactions stream. */
  subscribe(accounts: readonly string[]): Promise<void>;
  /** Registers the one event listener. */
  listen(fn: (e: LinkEvent) => void): void;
  close(): Promise<void>;
}

const CLOSE_GRACE_MS = 3000;

/**
 * An xrpl.js client as a Link. xrpl.js reconnects by itself after an unexpected close and emits `connected` again;
 * the subscription does not survive, so `up` tells the watcher to subscribe and backfill.
 */
// Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/subscription-methods/subscribe
export function xrplLink(name: string, url: string, opts: { timeoutMs?: number } = {}): Link {
  const client = new xrpl.Client(url, { timeout: opts.timeoutMs ?? 20_000 });
  const rpc = rpcOf(client);
  return {
    name,
    ...rpc,
    subscribe: async (accounts) => {
      await rpc.request({ command: 'subscribe', accounts: [...accounts], streams: ['ledger'] });
    },
    listen: (fn) => {
      client.on('connected', () => fn({ type: 'up' }));
      client.on('disconnected', () => fn({ type: 'down' }));
      client.on('transaction', (message) => fn({ type: 'transaction', message: message as unknown as XrplJson }));
      client.on('ledgerClosed', (m) => fn({ type: 'ledger', index: m.ledger_index, hash: m.ledger_hash }));
    },
    // xrpl.js 5.3.0 `disconnect()` can hang when called while the socket is closing (build/status/2.2.md).
    close: async () => {
      let timer: NodeJS.Timeout | undefined;
      await Promise.race([
        client.disconnect().catch(() => undefined),
        new Promise((r) => {
          timer = setTimeout(r, CLOSE_GRACE_MS);
        }),
      ]);
      clearTimeout(timer);
    },
  };
}
