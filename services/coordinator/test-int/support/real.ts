// The real pieces of the integration tests: a standalone ledger on port 6103 with a background closer, the `ledgerPort`
// of @legx/xrpl over it, and a fresh Postgres 18 database on port 5502.
import { randomBytes } from 'node:crypto';
import type { KyselyDatabase } from '@legx/db/client';
import { openPg } from '@legx/db/pg';
import { connect } from '@legx/xrpl/connect';
import { standaloneEnv } from '@legx/xrpl/env';
import { fundAccount } from '@legx/xrpl/fund';
import { advanceLedgers } from '@legx/xrpl/ledger';
import { ledgerPort } from '@legx/xrpl/submit';
import pg from 'pg';
import type { Client, Wallet } from 'xrpl';
import type { TestLedger } from '../../test/support/world.ts';

export const LEDGER_WS = process.env.LEGX_32_LEDGER ?? process.env.XRPLD_WS ?? 'ws://127.0.0.1:6103';
export const ADMIN_URL =
  process.env.LEGX_32_PG ?? process.env.LEGX_PG_URL ?? 'postgres://postgres:pw@127.0.0.1:5502/postgres';

export async function freshPg() {
  const name = `t_${randomBytes(6).toString('hex')}`;
  const admin = new pg.Client({ connectionString: ADMIN_URL });
  await admin.connect();
  await admin.query(`CREATE DATABASE ${name}`);
  await admin.end();
  const u = new URL(ADMIN_URL);
  u.pathname = `/${name}`;
  return openPg(u.toString()) as KyselyDatabase;
}

export interface RealLedger {
  port: TestLedger;
  client: Client;
  env: ReturnType<typeof standaloneEnv>;
  fund(xrp?: number): Promise<Wallet>;
  /** Sign with one wallet, autofill, submit reliably; the result must be validated. */
  submit(wallet: Wallet, tx: Record<string, unknown>): Promise<{ result: string; hash: string; ledgerIndex: number }>;
  close(n: number): Promise<void>;
  stop(): Promise<void>;
}

export async function realLedger(): Promise<RealLedger> {
  const env = standaloneEnv(LEDGER_WS);
  const client = await connect(env);
  const ticker = await connect(env);
  let index = 0;
  let on = true;
  const validated = await client.request({ command: 'ledger', ledger_index: 'validated' });
  index = validated.result.ledger_index;
  // Standalone ledgers close only when asked: close one every 100 ms, as the 2.2 integration tests do.
  const loop = (async () => {
    while (on) {
      await advanceLedgers(ticker, 1).catch(() => undefined);
      const v = await ticker.request({ command: 'ledger', ledger_index: 'validated' }).catch(() => undefined);
      if (v) index = v.result.ledger_index;
      await new Promise((r) => setTimeout(r, 300));
    }
  })();
  const port = ledgerPort(client, env, { pollMs: 50, timeoutMs: 60_000 }) as TestLedger;
  Object.defineProperty(port, 'index', { get: () => index }); // Object.assign would copy the value once
  const submit: RealLedger['submit'] = async (wallet, tx) => {
    const filled = await client.autofill({ Account: wallet.classicAddress, ...tx } as never);
    const r = await port.submitReliable(wallet.sign(filled as never).tx_blob);
    if (r.status !== 'validated') throw new Error(`submit: ${r.status} ${JSON.stringify(r)}`);
    return { result: r.result, hash: r.hash, ledgerIndex: r.ledgerIndex };
  };
  return {
    port,
    client,
    env,
    fund: (xrp = 50) => fundAccount(env, client, xrp),
    submit,
    // I-W-16: refresh the index requests are signed with right away; the background loop would leave it up to `n`
    // ledgers behind, and the server refuses a request more than 20 ledgers old (OD-5).
    close: async (n) => {
      await advanceLedgers(client, n);
      index = (await port.validatedLedger()).ledgerIndex;
    },
    stop: async () => {
      on = false;
      await loop;
      await ticker.disconnect();
      await client.disconnect();
    },
  };
}
