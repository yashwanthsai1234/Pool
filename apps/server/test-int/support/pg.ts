// A fresh database on the 3.7 Postgres (port 5510), migrated, with the NOTIFY trigger of migration 0003 (dropped when `trigger: false`).
import { randomBytes } from 'node:crypto';
import type { Database } from '@legx/db';
import { openPg } from '@legx/db';
import pg from 'pg';

export const ADMIN_URL =
  process.env.LEGX_37_PG ?? process.env.LEGX_PG_URL ?? 'postgres://postgres:pw@127.0.0.1:5510/postgres';

export async function freshDb(
  opts: { trigger?: boolean } = {},
): Promise<{ db: Database; url: string; drop(): Promise<void> }> {
  const name = `t_${randomBytes(6).toString('hex')}`;
  const admin = new pg.Client({ connectionString: ADMIN_URL });
  await admin.connect();
  await admin.query(`CREATE DATABASE ${name}`);
  await admin.end();
  const u = new URL(ADMIN_URL);
  u.pathname = `/${name}`;
  const url = u.toString();
  const db = openPg(url, 12);
  await db.migrate();
  if (opts.trigger === false) {
    // Migration 0003 installs the NOTIFY trigger (I-3.7-a); a test of the poll path drops it.
    const c = new pg.Client({ connectionString: url });
    await c.connect();
    await c.query('DROP TRIGGER outbox_notify ON outbox');
    await c.end();
  }
  return {
    db,
    url,
    drop: async () => {
      await db.close();
      const a = new pg.Client({ connectionString: ADMIN_URL });
      await a.connect();
      await a.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
      await a.end();
    },
  };
}
