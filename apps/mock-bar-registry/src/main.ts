import { startRegistry } from './server.ts';

// Source: https://nodejs.org/api/process.html#processenv (PORT, default 7070)
const port = Number(process.env.PORT ?? 7070);
await startRegistry(port);
console.log(`mock bar registry (DEMO) listening on http://127.0.0.1:${port}`);
