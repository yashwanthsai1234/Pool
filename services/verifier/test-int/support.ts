// Shared setup for the verifier integration tests: Postgres 18 on 5503, standalone xrpld on 6104.
import { randomBytes } from 'node:crypto';
import { KeyId } from '@legx/contracts/values';
import { openPg } from '@legx/db';
import { generateNodeSignerKeys, nodeSigner } from '@legx/signer';
import { standaloneEnv } from '@legx/xrpl';
import pg from 'pg';

export const PG_URL = process.env.LEGX_PG_URL ?? 'postgres://postgres:pw@localhost:5503/postgres';
export const env = standaloneEnv(process.env.XRPLD_WS ?? 'ws://127.0.0.1:6104');

export async function freshDb() {
  const name = `t_${randomBytes(6).toString('hex')}`;
  const admin = new pg.Client({ connectionString: PG_URL });
  await admin.connect();
  await admin.query(`CREATE DATABASE ${name}`);
  await admin.end();
  const u = new URL(PG_URL);
  u.pathname = `/${name}`;
  const db = openPg(u.toString());
  await db.migrate();
  return { db, url: u.toString() };
}

const tag = () => randomBytes(3).toString('hex');
export const newSigner = () =>
  nodeSigner(generateNodeSignerKeys(KeyId.parse(`ver-ed-${tag()}`), KeyId.parse(`ver-ml-${tag()}`)));
