import { writeFile } from 'node:fs/promises';
import { generateSchemaTs } from '../src/gen-schema.ts';
import { migrateToLatest } from '../src/migrate.ts';
import { openPglite } from '../src/pglite.ts';

const db = openPglite();
await migrateToLatest(db.kysely);
await writeFile(new URL('../src/schema.ts', import.meta.url), await generateSchemaTs(db.kysely));
await db.close();
