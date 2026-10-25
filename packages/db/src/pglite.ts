// A Kysely dialect over PGlite (in-process Postgres 18), for unit tests.
// Source: https://kysely.dev/docs/recipes/dialects (a dialect = driver + query compiler + adapter + introspector)
// Source: https://pglite.dev/docs/api (`query`, `exec`, `parsers`)
import { PGlite, types } from '@electric-sql/pglite';
import {
  CompiledQuery,
  type DatabaseConnection,
  type Dialect,
  type Driver,
  Kysely,
  PostgresAdapter,
  PostgresIntrospector,
  PostgresQueryCompiler,
  type QueryResult,
} from 'kysely';
import { createDatabase, type KyselyDatabase } from './client.ts';
import { toSafeNumber } from './int8.ts';

class PgliteConnection implements DatabaseConnection {
  readonly #pg: PGlite;
  constructor(pg: PGlite) {
    this.#pg = pg;
  }
  async executeQuery<R>(q: CompiledQuery): Promise<QueryResult<R>> {
    // `query` is the extended protocol (one statement, parameters); `exec` runs several statements (migrations).
    if (q.parameters.length === 0) {
      const results = await this.#pg.exec(q.sql);
      const last = results.at(-1);
      return { rows: (last?.rows ?? []) as R[], numAffectedRows: BigInt(last?.affectedRows ?? 0) };
    }
    const r = await this.#pg.query<R>(q.sql, [...q.parameters]);
    return { rows: r.rows, numAffectedRows: BigInt(r.affectedRows ?? 0) };
  }
  // biome-ignore lint/correctness/useYield: Kysely requires the method, PGlite has no cursor
  async *streamQuery(): AsyncIterableIterator<never> {
    throw new Error('streaming is not supported by the PGlite dialect');
  }
}

/** PGlite allows one connection, so a driver-level lock serialises callers (and holds it across a transaction). */
class PgliteDriver implements Driver {
  readonly #pg: PGlite;
  #tail: Promise<void> = Promise.resolve();
  readonly #release = new WeakMap<DatabaseConnection, () => void>();
  constructor(pg: PGlite) {
    this.#pg = pg;
  }
  async init(): Promise<void> {
    await this.#pg.waitReady;
  }
  async acquireConnection(): Promise<DatabaseConnection> {
    const prev = this.#tail;
    let release!: () => void;
    this.#tail = new Promise<void>((r) => {
      release = r;
    });
    await prev;
    const conn = new PgliteConnection(this.#pg);
    this.#release.set(conn, release);
    return conn;
  }
  async beginTransaction(conn: DatabaseConnection): Promise<void> {
    await conn.executeQuery(CompiledQuery.raw('begin'));
  }
  async commitTransaction(conn: DatabaseConnection): Promise<void> {
    await conn.executeQuery(CompiledQuery.raw('commit'));
  }
  async rollbackTransaction(conn: DatabaseConnection): Promise<void> {
    await conn.executeQuery(CompiledQuery.raw('rollback'));
  }
  async releaseConnection(conn: DatabaseConnection): Promise<void> {
    this.#release.get(conn)?.();
  }
  async destroy(): Promise<void> {
    await this.#pg.close();
  }
}

/** A fresh in-memory PGlite database with int8 parsed to a JS number, as in the `pg` setup. */
export function openPglite(): KyselyDatabase {
  const pg = new PGlite({ parsers: { [types.INT8]: (v: string) => toSafeNumber(v) } });
  const dialect: Dialect = {
    createAdapter: () => new PostgresAdapter(),
    createDriver: () => new PgliteDriver(pg),
    createIntrospector: (db) => new PostgresIntrospector(db),
    createQueryCompiler: () => new PostgresQueryCompiler(),
  };
  return createDatabase(new Kysely({ dialect }));
}
