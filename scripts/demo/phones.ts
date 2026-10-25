// `pnpm demo:phones` : the whole stack plus an HTTPS tunnel, for two real phones. Phones need a secure context for
// WebCrypto and WebAuthn, so a LAN http:// address does not work. A Cloudflare quick tunnel (no account) fronts the Vite
// web app, which proxies the API and /ws to the server. The tunnel host becomes LEGX_TUNNEL_URL, the WebAuthn RP ID and origin.
// Needs `cloudflared` and `qrencode` (brew install cloudflared qrencode). WEB_PORT (default 5173) moves the web app.
// Source: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/
import { type ChildProcess, spawn, spawnSync } from 'node:child_process';
import { PORTS, ROOT } from './lib.ts';

const WEB = Number(process.env.WEB_PORT ?? 5173);
const children: ChildProcess[] = [];
const stop = () => {
  for (const c of children) c.kill('SIGTERM');
};
for (const s of ['SIGINT', 'SIGTERM'] as const)
  process.once(s, () => {
    stop();
    process.exit(0);
  });
for (const bin of ['cloudflared', 'qrencode'])
  if (spawnSync('which', [bin]).status !== 0) throw new Error(`${bin} not found: brew install cloudflared qrencode`);

const tunnel = spawn('cloudflared', ['tunnel', '--url', `http://127.0.0.1:${WEB}`, '--no-autoupdate'], {
  stdio: ['ignore', 'ignore', 'pipe'],
});
children.push(tunnel);
const url = await new Promise<string>((resolve, reject) => {
  let buf = '';
  const t = setTimeout(() => reject(new Error('no tunnel URL within 60 s')), 60_000);
  tunnel.stderr?.on('data', (d) => {
    buf += String(d);
    const m = buf.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/);
    if (m) {
      clearTimeout(t);
      resolve(m[0]);
    }
  });
  tunnel.on('exit', () => reject(new Error('cloudflared exited')));
});
const env = { ...process.env, LEGX_TUNNEL_URL: url, LEGX_RP_ID: new URL(url).hostname, LEGX_RP_ORIGIN: url };
const run = (cmd: string, args: string[], cwd = ROOT) => {
  const c = spawn(cmd, args, { cwd, env, stdio: 'inherit' });
  children.push(c);
  return c;
};
run('node', ['scripts/dev.ts']);
const until = async (what: string, f: () => Promise<boolean>) => {
  for (let i = 0; i < 180; i++) {
    if (await f().catch(() => false)) return;
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`${what} did not come up`);
};
await until('the server', async () => (await fetch(`http://127.0.0.1:${PORTS.server}/health`)).ok);
run('./node_modules/.bin/vite', ['--port', String(WEB), '--strictPort'], `${ROOT}/apps/web`);
await until('the web app', async () => (await fetch(`${url}/party/alice`)).ok);

const qr = (label: string, u: string) => {
  process.stdout.write(`\n${label}: ${u}\n`);
  spawnSync('qrencode', ['-t', 'ANSIUTF8', '-m', '1', u], { stdio: 'inherit' });
};
qr('ALICE phone', `${url}/party/alice`);
qr('BOB phone', `${url}/party/bob`);
process.stdout.write(
  `\nLAWYERS (laptop): ${url}/lawyers\nDASHBOARD (projector): ${url}/dashboard\nCtrl-C stops everything.\n`,
);
await new Promise(() => {});
