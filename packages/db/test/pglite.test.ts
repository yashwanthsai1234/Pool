import { describe } from 'vitest';
import { openPglite } from '../src/pglite.ts';
import { repositorySuite } from './support/suite.ts';

describe('repositories on PGlite (Postgres 18.6 in-process)', () => {
  repositorySuite('pglite', async () => openPglite());
});
