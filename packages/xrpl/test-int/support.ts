// Shared helpers for the 2.2 integration tests: a background ledger closer (standalone ledgers close only when
// asked), a TCP proxy whose connections can be killed (a dropped WebSocket), and a signed-transaction helper.
import net from 'node:net';
import type xrpl from 'xrpl';
import type { Client, SubmittableTransaction } from 'xrpl';
import { advanceLedgers } from '../src/ledger.ts';

/** Closes a ledger every `ms` on its own client until stopped. */
export function closer(client: Client, ms = 100): () => Promise<void> {
  let on = true;
  const loop = (async () => {
    while (on) {
      await advanceLedgers(client, 1).catch(() => undefined);
      await new Promise((r) => setTimeout(r, ms));
    }
  })();
  return async () => {
    on = false;
    await loop;
  };
}

export interface TcpProxy {
  url: string;
  /** Destroy every open connection at once, as a network drop would. */
  killAll(): void;
  close(): Promise<void>;
}

export async function startProxy(target: string): Promise<TcpProxy> {
  const { hostname, port } = new URL(target);
  const sockets = new Set<net.Socket>();
  const server = net.createServer((down) => {
    const up = net.connect(Number(port), hostname);
    for (const s of [down, up]) {
      sockets.add(s);
      s.on('error', () => undefined);
      s.on('close', () => sockets.delete(s));
    }
    down.pipe(up);
    up.pipe(down);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const addr = server.address() as net.AddressInfo;
  return {
    url: `ws://127.0.0.1:${addr.port}`,
    killAll: () => {
      for (const s of sockets) s.destroy();
    },
    close: () =>
      new Promise((r) => {
        for (const s of sockets) s.destroy();
        server.close(() => r());
      }),
  };
}

type Wallet = InstanceType<typeof xrpl.Wallet>;

/** Autofill (LastLedgerSequence = validated + 20 by default) and sign. */
export async function signed(
  client: Client,
  wallet: Wallet,
  tx: Record<string, unknown>,
): Promise<{ blob: string; hash: string; tx: SubmittableTransaction }> {
  const filled = await client.autofill({ Account: wallet.classicAddress, ...tx } as SubmittableTransaction);
  const s = wallet.sign(filled);
  return { blob: s.tx_blob, hash: s.hash, tx: filled };
}

export async function accountSequence(client: Client, account: string): Promise<number> {
  const r = await client.request({ command: 'account_info', account, ledger_index: 'validated' });
  return r.result.account_data.Sequence;
}

/**
 * Disconnect, but never hang. xrpl.js 5.3.0 can lose the `disconnect()` promise when it is called while the socket
 * is closing: its own close handler runs `removeAllListeners()` first (dist/npm/client/connection.js, onceOpen).
 */
export async function disconnectQuietly(client: Client): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  await Promise.race([
    client.disconnect().catch(() => undefined),
    new Promise((r) => {
      timer = setTimeout(r, 3000);
    }),
  ]);
  clearTimeout(timer);
}
