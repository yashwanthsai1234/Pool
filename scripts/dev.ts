// `pnpm dev`: Postgres, a standalone ledger, the mock bar registry and the server (demo profile), then waits.
// Ports (task 3.7): Postgres 5510, ledger 6113, registry 7070, server 8710 (LEGX_PG_PORT, LEGX_LEDGER_PORT,
// LEGX_REGISTRY_PORT, LEGX_PORT override them, and LEGX_DEV_PREFIX the container names, as for the demo scripts). Ctrl-C stops the processes; the containers
// stay up for the next run (`pnpm dev:down` removes them).
// Source: https://docs.docker.com/reference/cli/docker/container/run/
import { type ChildProcess, spawn, spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { CONTAINERS, PORTS } from './demo/lib.ts';

const root = resolve(import.meta.dirname, '..');
const PG = { name: CONTAINERS.postgres, port: PORTS.postgres };
const LEDGER = { name: CONTAINERS.ledger, port: PORTS.ledger };
const REGISTRY_PORT = PORTS.registry;
const SERVER_PORT = PORTS.server;

const docker = (...args: string[]) => spawnSync('docker', args, { encoding: 'utf8' });
const running = (name: string) =>
  docker('ps', '--filter', `name=^${name}$`, '--format', '{{.Names}}').stdout.trim() === name;
const exists = (name: string) =>
  docker('ps', '-a', '--filter', `name=^${name}$`, '--format', '{{.Names}}').stdout.trim() === name;

function ensure(name: string, create: string[]): void {
  if (running(name)) return;
  const r = exists(name) ? docker('start', name) : docker('run', '-d', '--name', name, ...create);
  if (r.status !== 0) throw new Error(`docker could not start ${name}: ${r.stderr}`);
}

async function until(what: string, ok: () => Promise<boolean>, ms = 60_000): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await ok().catch(() => false)) return;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`${what} did not come up in ${ms / 1000} s`);
}

if (process.argv.includes('--down')) {
  for (const n of [PG.name, LEDGER.name]) docker('rm', '-f', n);
  process.exit(0);
}

ensure(PG.name, ['-e', 'POSTGRES_PASSWORD=pw', '-p', `127.0.0.1:${PG.port}:5432`, 'postgres:18.6-trixie']);
ensure(LEDGER.name, [
  '--platform',
  'linux/amd64',
  '-p',
  `127.0.0.1:${LEDGER.port}:6006`,
  '-v',
  `${root}/ci:/etc/xrpld/:ro`,
  'rippleci/xrpld:3.4.1',
  '--standalone',
]);
await until('postgres', async () => docker('exec', PG.name, 'pg_isready', '-U', 'postgres').status === 0);
await until('the ledger', async () => {
  const res = await fetch(`http://127.0.0.1:${LEDGER.port}`, { method: 'POST', body: '{}' }).catch(() => undefined);
  return res !== undefined || docker('logs', '--tail', '5', LEDGER.name).stdout.length > 0;
});

const children: ChildProcess[] = [];
const run = (cmd: string, env: Record<string, string>) => {
  const c = spawn('node', [cmd], { cwd: root, env: { ...process.env, ...env }, stdio: 'inherit' });
  children.push(c);
  return c;
};
run('apps/mock-bar-registry/src/main.ts', { PORT: String(REGISTRY_PORT) });
const server = run('apps/server/src/main.ts', {
  LEGX_PROFILE: 'demo',
  LEGX_PG: `postgres://postgres:pw@127.0.0.1:${PG.port}/postgres`,
  LEGX_LEDGER_WS: `ws://127.0.0.1:${LEDGER.port}`,
  LEGX_BAR_REGISTRY: `http://127.0.0.1:${REGISTRY_PORT}`,
  LEGX_PORT: String(SERVER_PORT),
});
server.on('exit', (code) => {
  for (const c of children) c.kill('SIGTERM');
  process.exit(code ?? 1);
});
for (const sig of ['SIGINT', 'SIGTERM'] as const)
  process.once(sig, () => {
    for (const c of children) c.kill('SIGTERM');
  });
await until('the server', async () => (await fetch(`http://127.0.0.1:${SERVER_PORT}/health`)).ok, 120_000);
process.stderr.write(
  `dev stack up: server http://127.0.0.1:${SERVER_PORT}/health, registry :${REGISTRY_PORT}, postgres :${PG.port}, ledger :${LEDGER.port}\n`,
);
