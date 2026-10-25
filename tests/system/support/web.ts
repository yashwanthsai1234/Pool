// The web app's Vite dev server (the way `pnpm --filter @legx/web dev` serves it), proxying /api and /ws to the server.
import { type ChildProcess, spawn } from 'node:child_process';
import { join } from 'node:path';
import { ROOT, SERVER_PORT } from './stack.ts';

export const WEB_PORT = 5199;
export const WEB_URL = `http://127.0.0.1:${WEB_PORT}`;

export async function startWeb(): Promise<{ stop(): Promise<void> }> {
  const dir = join(ROOT, 'apps/web');
  const child: ChildProcess = spawn(
    'node',
    [join(dir, 'node_modules/vite/bin/vite.js'), '--port', String(WEB_PORT), '--strictPort', '--host', '127.0.0.1'],
    {
      cwd: dir,
      stdio: 'ignore',
      env: { ...process.env, LEGX_PORT: String(SERVER_PORT) },
    },
  );
  const end = Date.now() + 90_000;
  for (;;) {
    const ok = await fetch(WEB_URL).then(
      (r) => r.ok,
      () => false,
    );
    if (ok) break;
    if (Date.now() > end || child.exitCode !== null) throw new Error('vite did not start');
    await new Promise((r) => setTimeout(r, 300));
  }
  return {
    stop: async () => {
      const done = new Promise((r) => child.once('exit', r));
      child.kill('SIGTERM');
      await done;
    },
  };
}
