import { randomBytes } from 'node:crypto';
import pg from 'pg';

export const ADMIN_URL = process.env.LEGX_PG_URL ?? 'postgres://postgres:pw@localhost:5501/postgres';

/** Creates an empty database on the server and returns its URL. */
export async function freshPgDatabase(): Promise<string> {
  const name = `t_${randomBytes(6).toString('hex')}`;
  const admin = new pg.Client({ connectionString: ADMIN_URL });
  await admin.connect();
  await admin.query(`CREATE DATABASE ${name}`);
  await admin.end();
  const u = new URL(ADMIN_URL);
  u.pathname = `/${name}`;
  return u.toString();
}
