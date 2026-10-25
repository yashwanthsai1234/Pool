// Raw `.sql` migrations run by the Kysely migrator, so PGlite and Docker run the same SQL (IMPLEMENTATION 4.3).
// Kysely 0.29 moved Migrator to the `kysely/migration` entry point (package.json exports).
// Source: https://kysely.dev/docs/migrations (custom MigrationProvider)
import { readdir, readFile } from 'node:fs/promises';
import { type Kysely, sql } from 'kysely';
import { type Migration, type MigrationProvider, Migrator } from 'kysely/migration';

const MIGRATIONS_DIR = new URL('../migrations/', import.meta.url);

const provider: MigrationProvider = {
  async getMigrations() {
    const out: Record<string, Migration> = {};
    for (const file of (await readdir(MIGRATIONS_DIR)).filter((f) => f.endsWith('.sql')).sort()) {
      const text = await readFile(new URL(file, MIGRATIONS_DIR), 'utf8');
      out[file.slice(0, -'.sql'.length)] = {
        up: async (db: Kysely<unknown>) => {
          await sql.raw(text).execute(db);
        },
      };
    }
    return out;
  },
};

/** Applies every pending migration (each in its own transaction) and returns the names applied now. */
export async function migrateToLatest<T>(db: Kysely<T>): Promise<string[]> {
  const { error, results } = await new Migrator({ db: db as Kysely<unknown>, provider }).migrateToLatest();
  if (error) throw error instanceof Error ? error : new Error(String(error));
  return (results ?? []).filter((r) => r.status === 'Success').map((r) => r.migrationName);
}
