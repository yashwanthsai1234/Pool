import { PHONE_ROUTE_BUDGET_BYTES, phoneRouteGzipBytes } from './budget.ts';

const bytes = phoneRouteGzipBytes(new URL('../dist', import.meta.url).pathname);
process.stdout.write(
  `phone route: ${(bytes / 1000).toFixed(1)} kB gzipped (budget ${PHONE_ROUTE_BUDGET_BYTES / 1000} kB)\n`,
);
if (bytes > PHONE_ROUTE_BUDGET_BYTES) process.exit(1);
