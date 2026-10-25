// The agent runs under its own Postgres role: it can do its work and nothing else.
import { randomBytes } from 'node:crypto';
import type { KyselyDatabase } from '@legx/db/client';
import { openPg } from '@legx/db/pg';
import { sql } from 'kysely';
import pg from 'pg';
import { describe, expect, it } from 'vitest';
import { PgNonceLedger } from '../src/nonces.ts';
import { agentRoleSql } from '../src/role.ts';
import { ShareVault } from '../src/vault.ts';
import { makeAgentWorld } from '../test/support/agent.ts';
import { makeWorld, rnd } from '../test/support/world.ts';

const ADMIN_URL = process.env.LEGX_39_PG ?? process.env.LEGX_PG_URL ?? 'postgres://postgres:pw@127.0.0.1:5507/postgres';
const urlFor = (name: string, user = 'postgres', pw = 'pw') => {
  const u = new URL(ADMIN_URL);
  u.pathname = `/${name}`;
  u.username = user;
  u.password = pw;
  return u.toString();
};

describe("the agent's database role", () => {
  it('reads and writes its own tables, marks nonces, and is refused everything else', async () => {
    const name = `t_${randomBytes(6).toString('hex')}`;
    const admin = new pg.Client({ connectionString: ADMIN_URL });
    await admin.connect();
    await admin.query(`CREATE DATABASE ${name}`);
    await admin.end();
    const owner = openPg(urlFor(name)) as KyselyDatabase;
    const w = await makeWorld({ db: owner });
    try {
      const _a = await makeAgentWorld(w); // creates the agent's tables as the owner
      const role = `agent_${randomBytes(3).toString('hex')}`;
      for (const q of agentRoleSql(role, 'agentpw')) await sql.raw(q).execute(owner.kysely);
      const agentDb = openPg(urlFor(name, role, 'agentpw')) as KyselyDatabase;
      try {
        const vault = new ShareVault(agentDb, rnd(32));
        // its own tables: a read of the share the owner stored fails to open under another master key, but the SELECT works
        expect(await new ShareVault(agentDb, rnd(32)).count(w.dealId, 'A')).toBe(1);
        await expect(vault.get(w.dealId, 'A')).rejects.toMatchObject({ code: 'TAMPERED' });
        // nonce marking
        const ledger = new PgNonceLedger(agentDb, { keyId: 'agent', dealId: w.dealId, messageHash: '00'.repeat(32) });
        expect(await ledger.markUsed('cd'.repeat(32))).toBe(true);
        expect(await ledger.markUsed('cd'.repeat(32))).toBe(false);
        // the keys it checks requests against
        expect((await agentDb.repos.enrollmentKeys.listForDeal(w.dealId)).length).toBe(3);
        // nothing else
        for (const table of [
          'deal',
          'evidence_event',
          'signature',
          'frost_relay_message',
          'frost_relay_session',
          'used_nonce',
        ])
          await expect(sql.raw(`select 1 from ${table} limit 1`).execute(agentDb.kysely), table).rejects.toThrow(
            /permission denied/,
          );
        await expect(sql.raw('delete from recovery_agent_share').execute(agentDb.kysely)).rejects.toThrow(
          /permission denied/,
        );
        await expect(sql.raw('delete from frost_nonce_use').execute(agentDb.kysely)).rejects.toThrow(
          /permission denied/,
        );
        await expect(sql.raw('update frost_nonce_use set deal_id = deal_id').execute(agentDb.kysely)).rejects.toThrow(
          /permission denied/,
        );
      } finally {
        await agentDb.close();
      }
    } finally {
      await w.close();
    }
  });
});
