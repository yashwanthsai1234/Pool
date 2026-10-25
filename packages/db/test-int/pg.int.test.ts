// [pg] The same suite on a real Postgres 18 server (container legx-3.1-pg, port 5501).
import { describe } from 'vitest';
import { openPg } from '../src/pg.ts';
import { repositorySuite } from '../test/support/suite.ts';
import { freshPgDatabase } from './support.ts';

describe('repositories on Postgres 18', () => {
  repositorySuite('pg', async () => openPg(await freshPgDatabase()));
});
