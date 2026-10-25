// The production profile: a real Postgres 18.6 (container legx-3.9-pg on port 5507), a fresh database for each test.
// Run: docker run -d --name legx-3.9-pg -e POSTGRES_PASSWORD=pw -p 127.0.0.1:5507:5432 postgres:18.6-trixie
import { randomBytes } from 'node:crypto';
import type { KyselyDatabase } from '@legx/db/client';
import { openPg } from '@legx/db/pg';
import pg from 'pg';
import { profileSuite } from '../test/support/profile.ts';

const ADMIN_URL = process.env.LEGX_39_PG ?? process.env.LEGX_PG_URL ?? 'postgres://postgres:pw@127.0.0.1:5507/postgres';

async function freshPg(): Promise<KyselyDatabase> {
  const name = `t_${randomBytes(6).toString('hex')}`;
  const admin = new pg.Client({ connectionString: ADMIN_URL });
  await admin.connect();
  await admin.query(`CREATE DATABASE ${name}`);
  await admin.end();
  const u = new URL(ADMIN_URL);
  u.pathname = `/${name}`;
  return openPg(u.toString()) as KyselyDatabase;
}

profileSuite('production (Postgres 18.6)', freshPg);
