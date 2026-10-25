# Sources (@legx/watcher)

- DESIGN.md 8.5 (watcher), 10.2 (invariants as code), IMPLEMENTATION.md 3.5, Appendix B DQ-1; DECISIONS OD-9.
- https://www.postgresql.org/docs/18/sql-notify.html : `pg_notify` delivers on commit; the service calls it after the commit.
- https://www.postgresql.org/docs/18/functions-info.html : not used; transactions roll back when the client connection vanishes (the SIGKILL test shows it).
- https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/subscription-methods/subscribe : ledger stream (`ledgerClosed`).
- https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_objects : lock-check reads (through `@legx/xrpl/read` `snapshot`).
