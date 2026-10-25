// [pg] P3.1-01 with the real tool: `pg_dump --schema-only` of a freshly migrated database equals the committed dump.
// Source: https://www.postgresql.org/docs/18/app-pgdump.html
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { openPg } from '../src/pg.ts';
import { freshPgDatabase } from './support.ts';

const CONTAINER = process.env.LEGX_PG_CONTAINER ?? 'legx-3.1-pg';
const DUMP_FILE = new URL('../test/schema.pg_dump.sql', import.meta.url);

/** pg_dump 18.x adds a random `\restrict` token and version comments; drop them so the dump is stable. */
const normalise = (d: string) =>
  d
    .split('\n')
    .filter((l) => !/^\\(un)?restrict /.test(l) && !/^-- Dumped (from|by) /.test(l))
    .join('\n');

it('P3.1-01 [pg] the pg_dump schema of a migrated database equals the committed dump', async () => {
  const url = await freshPgDatabase();
  const db = openPg(url);
  await db.migrate();
  await db.close();
  const name = new URL(url).pathname.slice(1);
  const dump = normalise(
    execFileSync(
      'docker',
      ['exec', CONTAINER, 'pg_dump', '-U', 'postgres', '-d', name, '--schema-only', '--no-owner', '--no-privileges'],
      { encoding: 'utf8' },
    ),
  );
  if (process.env.UPDATE_SNAPSHOT === '1') writeFileSync(DUMP_FILE, dump);
  expect(dump).toBe(readFileSync(DUMP_FILE, 'utf8'));
});
