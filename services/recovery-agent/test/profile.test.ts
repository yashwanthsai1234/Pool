// The demo profile: an in-process Postgres 18 (PGlite).
import { openPglite } from '@legx/db/pglite';
import { profileSuite } from './support/profile.ts';

profileSuite('demo (PGlite)', async () => openPglite());
