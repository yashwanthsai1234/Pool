# Sources (@legx/db)

- DESIGN.md sections 6.3, 6.4, 6.10, 8.1, 8.9, 8.10, 9 and IMPLEMENTATION.md 3.1: the tables, the append-only pattern, seq, nonces.
- https://www.postgresql.org/docs/18/sql-select.html : `FOR UPDATE SKIP LOCKED` for the outbox ("queue-like table"); `FOR UPDATE` on `deal_head`.
- https://www.postgresql.org/docs/18/functions-uuid.html : `uuidv7()` as an ID default (no strict monotonicity documented, so never a cursor).
- https://www.postgresql.org/docs/18/sql-createtrigger.html and /sql-revoke.html : append-only triggers (row and TRUNCATE) plus REVOKE.
- https://www.postgresql.org/docs/18/app-pgdump.html : committed `pg_dump --schema-only` snapshot.
- https://www.postgresql.org/docs/18/errcodes-appendix.html : 23505 unique, 23514 check, 23503 foreign key, 42501 privilege.
- https://kysely.dev/docs/migrations : custom `MigrationProvider`; in 0.29 `Migrator` is exported from `kysely/migration`.
- https://kysely.dev/docs/recipes/dialects : the PGlite dialect (driver, adapter, compiler, introspector).
- https://pglite.dev/docs/api : `query` (one statement, parameters) versus `exec` (many statements, no parameters); `parsers`.
- https://node-postgres.com/apis/pool : pool options, custom `types.getTypeParser`.
