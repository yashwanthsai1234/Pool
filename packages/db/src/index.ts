// @legx/db public surface: the handle, the repositories and their plain row types. No Kysely type is exported.

import type { Database } from './client.ts';
import { openPg as openPgInternal } from './pg.ts';

export type { Database, Repos } from './client.ts';
export { KeyNotRecorded, SeqTaken } from './errors.ts';
export type { DealHead, EvidenceEventRow, NewEvidenceEvent } from './repos/evidence.ts';

/** A Postgres 18 pool over `pg`. For PGlite (unit tests) import `@legx/db/pglite`. */
export const openPg: (connectionString: string, max?: number) => Database = openPgInternal;
