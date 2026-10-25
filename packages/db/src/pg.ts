// The `pg` (node-postgres) connection for integration tests and production.
// Source: https://node-postgres.com/apis/pool and https://kysely.dev/docs/getting-started#dialects
import { Kysely, PostgresDialect } from 'kysely';
import pg from 'pg';
import { createDatabase, type KyselyDatabase } from './client.ts';
import { toSafeNumber } from './int8.ts';

export function openPg(connectionString: string, max = 10): KyselyDatabase {
  const pool = new pg.Pool({
    connectionString,
    max,
    types: {
      getTypeParser: (oid: number, format?: 'text' | 'binary') =>
        oid === 20 ? toSafeNumber : pg.types.getTypeParser(oid, format),
    },
  });
  return createDatabase(new Kysely({ dialect: new PostgresDialect({ pool }) }));
}
