// The one database transaction per validated transaction (DESIGN 8.5): observation, outbox row, cursor.
import type { Database } from '@legx/db';
import type { Observation } from '@legx/xrpl/watcher/index';
import { type Kysely, sql } from 'kysely';

export const OBSERVATION_TOPIC = 'ledger.observation';
export const NOTIFY_CHANNEL = 'legx_outbox';

/** The write points of the transaction. A test seam: `onStep` may throw or kill the process after any of them. */
export type Step = 'observation' | 'outbox' | 'cursor';

export const json = (x: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(x));

/** `pg_notify` after the commit, so a listener that wakes always finds the row. */
// Source: https://www.postgresql.org/docs/18/sql-notify.html
export type Notify = (topic: string) => Promise<void>;
export const pgNotify =
  (db: Database): Notify =>
  async (topic) => {
    const { kysely } = db as unknown as { kysely: Kysely<unknown> };
    await sql`select pg_notify(${NOTIFY_CHANNEL}, ${topic})`.execute(kysely);
  };

/**
 * Handles one observation idempotently on `tx_hash`. A replay (a crash after the commit but before the client moved
 * its own cursor) inserts nothing and queues nothing. The cursor moves to `ledger - 1` only for a backfilled
 * transaction: the ledger is not complete yet, and a stream message says nothing about the ledgers before it.
 */
export async function recordObservation(
  db: Database,
  accounts: readonly string[],
  o: Observation,
  onStep: (s: Step) => void | Promise<void> = () => undefined,
): Promise<boolean> {
  // A stream message names no account: file it under a watched party of the transaction, else under the sender.
  const parties = [o.tx.Account, o.tx.Destination].filter((a): a is string => typeof a === 'string');
  const account = o.account ?? parties.find((a) => accounts.includes(a)) ?? String(o.tx.Account);
  return db.transaction(async (r) => {
    // The row is stored under the first account that reported it (stream: the sender; backfill: the watched account).
    let known = false;
    for (const a of new Set([...accounts, String(o.tx.Account)]))
      known ||= (await r.ledgerObservations.listForAccount(a, o.ledgerIndex)).some(
        (x) => x.tx_hash.toUpperCase() === o.hash,
      );
    await r.ledgerObservations.insert({
      tx_hash: o.hash,
      ledger_index: o.ledgerIndex,
      tx_index: o.transactionIndex,
      account,
      tx_type: String(o.tx.TransactionType),
      result: String(o.meta.TransactionResult),
      meta: o.meta,
    });
    await onStep('observation');
    if (!known)
      await r.outbox.enqueue({
        topic: OBSERVATION_TOPIC,
        payload: json({ hash: o.hash, ledger_index: o.ledgerIndex, account, tx_type: o.tx.TransactionType }),
      });
    await onStep('outbox');
    if (o.source === 'backfill') await r.watcherCursors.advance(account, o.ledgerIndex - 1);
    await onStep('cursor');
    return !known;
  });
}
