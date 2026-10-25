// A process that writes one observation and kills itself (SIGKILL) right after the write named in LEGX_KILL_AFTER.
// Run by watcher.int.test.ts: a real crash, so Postgres sees a connection that vanishes inside the transaction.
import { openPg } from '@legx/db';
import { recordObservation, type Step } from '../src/index.ts';

const db = openPg(String(process.env.LEGX_PG_URL), 1);
const after = process.env.LEGX_KILL_AFTER;
const WALLET = 'rKillTestWallet';
await recordObservation(
  db,
  [WALLET],
  {
    hash: 'AB'.repeat(32),
    ledgerIndex: 42,
    transactionIndex: 1,
    tx: { Account: WALLET, TransactionType: 'Payment' },
    meta: { TransactionResult: 'tesSUCCESS', TransactionIndex: 1 },
    source: 'backfill',
    account: WALLET,
  },
  (s: Step) => {
    if (s === after) process.kill(process.pid, 'SIGKILL');
  },
);
await db.close();
