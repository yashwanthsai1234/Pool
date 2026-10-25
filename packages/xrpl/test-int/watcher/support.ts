// Helpers for the watcher integration tests: a TCP proxy that can refuse connections (a long outage), a ledger driver
// that records every transaction it validates, and a server that lies about ledger hashes.
import net from 'node:net';
import type { Client } from 'xrpl';
import { GENESIS } from '../../src/fund.ts';
import { advanceLedgers } from '../../src/ledger.ts';
import type { Link } from '../../src/watcher/index.ts';

export interface BlockableProxy {
  url: string;
  /** Drops every connection and refuses new ones until `unblock`. */
  block(): void;
  unblock(): void;
  close(): Promise<void>;
}

export async function blockableProxy(target: string): Promise<BlockableProxy> {
  const { hostname, port } = new URL(target);
  const sockets = new Set<net.Socket>();
  let blocked = false;
  const killAll = () => {
    for (const s of sockets) s.destroy();
  };
  const server = net.createServer((down) => {
    if (blocked) return void down.destroy();
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
    block: () => {
      blocked = true;
      killAll();
    },
    unblock: () => {
      blocked = false;
    },
    close: () =>
      new Promise((r) => {
        killAll();
        server.close(() => r());
      }),
  };
}

export interface Closed {
  hash: string;
  ledgerIndex: number;
}

/** Submits `txs` genesis payments, then closes one ledger. Returns the validated transactions. */
export async function closeLedgerWith(client: Client, destinations: string[]): Promise<Closed[]> {
  const hashes: string[] = [];
  for (const dest of destinations) {
    const tx = await client.autofill({
      TransactionType: 'Payment',
      Account: GENESIS.classicAddress,
      Destination: dest,
      Amount: '1000000',
    });
    const signed = GENESIS.sign(tx);
    const r = await client.request({ command: 'submit', tx_blob: signed.tx_blob });
    if (r.result.engine_result !== 'tesSUCCESS') throw new Error(`payment rejected: ${r.result.engine_result}`);
    hashes.push(signed.hash);
  }
  await advanceLedgers(client, 1);
  const head = (await client.request({ command: 'ledger', ledger_index: 'validated' })).result.ledger_index;
  return hashes.map((hash) => ({ hash, ledgerIndex: head }));
}

/** The same server, but every ledger hash it reports is wrong. */
export function lying(inner: Link, name = 'liar'): Link {
  return {
    ...inner,
    name,
    request: async (req) => {
      const r = await inner.request(req);
      if (req.command !== 'ledger') return r;
      const result = r.result as { ledger_hash: string };
      return {
        result: {
          ...result,
          ledger_hash: `${result.ledger_hash.slice(0, -1)}${result.ledger_hash.endsWith('0') ? '1' : '0'}`,
        },
      };
    },
  };
}

export const until = async (what: string, ok: () => boolean, ms = 60_000): Promise<void> => {
  const end = Date.now() + ms;
  while (!ok()) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 50));
  }
};
