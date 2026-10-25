// The production profile: a real Postgres 18.6 (container legx-3.10-pg on port 5509), a fresh database per test.
// Run: docker run -d --name legx-3.10-pg -e POSTGRES_PASSWORD=pw -p 127.0.0.1:5509:5432 postgres:18.6-trixie
import { randomBytes } from 'node:crypto';
import { releaseShare } from '@legx/core/frostRules';
import type { KyselyDatabase } from '@legx/db/client';
import { openPg } from '@legx/db/pg';
import { PgNonceLedger } from '@legx/recovery-agent/nonces';
import pg from 'pg';
import { describe, expect, it } from 'vitest';
import { makeFirmWorld, verifies } from '../test/support/firm.ts';

const ADMIN_URL =
  process.env.LEGX_310_PG ?? process.env.LEGX_PG_URL ?? 'postgres://postgres:pw@127.0.0.1:5509/postgres';

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

describe('production profile (Postgres 18.6)', () => {
  it('signs a good exit, refuses a bad one, and keeps one hash chain under concurrent audit writes', async () => {
    const fw = await makeFirmWorld(await freshPg());
    try {
      const { msg } = fw.exit();
      expect(verifies(fw, (await fw.signNormal(msg)).sig, msg)).toBe(true);
      await expect(fw.signNormal(fw.exit({ Amount: '1' }).msg)).rejects.toMatchObject({ code: 'NOT_ALLOWED' });
      await Promise.all(
        Array.from({ length: 20 }, (_, i) =>
          fw.audit.append({
            dealId: fw.w.dealId,
            slot: 'LA',
            decision: 'refused',
            reason: `R${i}`,
            messageHash: '',
            seal: fw.seal,
          }),
        ),
      );
      expect(await fw.audit.verifyChain()).toBe(true);
      expect((await fw.audit.entries()).length).toBe(22);
    } finally {
      await fw.w.close();
    }
  });

  it('releases exactly one share when 20 concurrent requests use one commitment', async () => {
    const fw = await makeFirmWorld(await freshPg());
    try {
      const ledger = new PgNonceLedger(fw.w.deps.db, {
        keyId: 'hsm',
        dealId: fw.w.dealId,
        messageHash: '00'.repeat(32),
      });
      const out = await Promise.allSettled(
        Array.from({ length: 20 }, () => releaseShare(ledger, 'ab'.repeat(32), () => new Uint8Array([1]))),
      );
      expect(out.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    } finally {
      await fw.w.close();
    }
  });
});
