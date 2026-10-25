# Sources for apps/server

- Fastify content type parsers, `parseAs: 'buffer'` (exact body bytes for the signature): https://fastify.dev/docs/latest/Reference/ContentTypeParser/
- Fastify hooks (`onRequest`, `onSend`), plugins and encapsulation: https://fastify.dev/docs/latest/Reference/Hooks/ , https://fastify.dev/docs/latest/Reference/Plugins/
- `@fastify/websocket` (route option `websocket: true`, hooks run before the upgrade): https://github.com/fastify/fastify-websocket
- `ws` (send callback, close codes, `pause`): https://github.com/websockets/ws/blob/master/doc/ws.md
- WebSocket close codes 4000-4999 for applications: https://www.rfc-editor.org/rfc/rfc6455#section-7.4.2
- Postgres LISTEN / NOTIFY (delivery after commit, may coalesce, per-connection): https://www.postgresql.org/docs/18/sql-notify.html , https://www.postgresql.org/docs/18/sql-listen.html
- node-postgres notifications on a dedicated client: https://node-postgres.com/features/notifications
- Content-Security-Policy `frame-ancestors`: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-ancestors
- Docker run (the dev containers): https://docs.docker.com/reference/cli/docker/container/run/
- https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html : production signer: KMS Ed25519 and ML-DSA-65 (`production.ts`)
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html : production object store with Object Lock COMPLIANCE (`production.ts`)
- https://node-postgres.com/apis/pool : the pump's and the watcher's deal queries (`wiring.ts`)
- https://nodejs.org/api/process.html#processgetbuiltinmoduleid : lazy system TLS roots (evidence `tsa.ts`, used by the bundle's time stamp roots)
- https://esbuild.github.io/api/#build : the offline verifier built once at start-up (`verifyScript.ts`)
- build/DECISIONS.md OD-31, OD-32 : observer key (live feed, read only) and public-proof-only `zk.verify`
