// A normalised catalog dump, the same query on PGlite and Postgres, so one committed file checks both engines.
// Source: https://www.postgresql.org/docs/18/catalogs.html
import { sql } from 'kysely';
import type { KyselyDatabase } from '../../src/client.ts';

const APP_TABLES = `
  SELECT c.oid, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname NOT LIKE 'kysely\\_%'`;

async function lines(db: KyselyDatabase, q: string): Promise<string[]> {
  const r = await sql<{ l: string }>`${sql.raw(q)}`.execute(db.kysely);
  return r.rows.map((x) => x.l);
}

export async function catalogSnapshot(db: KyselyDatabase): Promise<string> {
  const out: string[] = [];
  const section = async (title: string, q: string) => {
    out.push(`-- ${title}`, ...(await lines(db, q)), '');
  };
  await section(
    'columns',
    `
    SELECT format('%s.%s %s%s%s', c.relname, a.attname, format_type(a.atttypid, a.atttypmod),
      CASE WHEN a.attnotnull THEN ' NOT NULL' ELSE '' END,
      COALESCE(' DEFAULT ' || pg_get_expr(d.adbin, d.adrelid), '')) AS l
    FROM (${APP_TABLES}) c JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
    LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
    ORDER BY c.relname, a.attnum`,
  );
  await section(
    'constraints',
    `
    SELECT format('%s %s %s', c.relname, k.conname, pg_get_constraintdef(k.oid)) AS l
    FROM (${APP_TABLES}) c JOIN pg_constraint k ON k.conrelid = c.oid ORDER BY c.relname, k.conname`,
  );
  await section(
    'indexes',
    `
    SELECT pg_get_indexdef(i.indexrelid) AS l FROM (${APP_TABLES}) c JOIN pg_index i ON i.indrelid = c.oid
    ORDER BY c.relname, 1`,
  );
  await section(
    'triggers',
    `
    SELECT format('%s %s', c.relname, pg_get_triggerdef(t.oid)) AS l
    FROM (${APP_TABLES}) c JOIN pg_trigger t ON t.tgrelid = c.oid WHERE NOT t.tgisinternal ORDER BY c.relname, t.tgname`,
  );
  await section(
    'functions',
    `
    SELECT p.proname || '(' || pg_get_function_arguments(p.oid) || ')' AS l FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' ORDER BY 1`,
  );
  await section(
    'app_rw privileges',
    `
    SELECT format('%s %s', c.relname, concat_ws(',',
      CASE WHEN has_table_privilege('app_rw', c.oid, 'SELECT') THEN 'select' END,
      CASE WHEN has_table_privilege('app_rw', c.oid, 'INSERT') THEN 'insert' END,
      CASE WHEN has_table_privilege('app_rw', c.oid, 'UPDATE') THEN 'update' END,
      CASE WHEN has_table_privilege('app_rw', c.oid, 'DELETE') THEN 'delete' END,
      CASE WHEN has_table_privilege('app_rw', c.oid, 'TRUNCATE') THEN 'truncate' END)) AS l
    FROM (${APP_TABLES}) c ORDER BY c.relname`,
  );
  return out.join('\n');
}

export async function appendOnlyTables(db: KyselyDatabase): Promise<string[]> {
  return await lines(
    db,
    `
    SELECT DISTINCT c.relname AS l FROM (${APP_TABLES}) c JOIN pg_trigger t ON t.tgrelid = c.oid
    WHERE NOT t.tgisinternal AND t.tgname LIKE '%\\_immutable' ORDER BY 1`,
  );
}
