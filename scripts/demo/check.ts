// `node scripts/demo/check.ts` (P5.6-03, P5.6-10): one green or red line per dependency; exit 1 if any is red.
// Manual items (phones, keys, tunnel) come from the checklist in demo/state.json.
// Source: https://docs.docker.com/reference/cli/docker/container/exec/ (pg_isready); https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/server-info-methods/server_info
import { spawnSync } from 'node:child_process';
import { demoPassport } from '../../packages/fixtures/src/index.ts';
import { connect, standaloneEnv, testnetEnv } from '../../packages/xrpl/src/index.ts';
import { CONTAINERS, PORTS, probe, readState, registryUrl, serverUrl } from './lib.ts';

const rows: { name: string; ok: boolean; note: string }[] = [];
async function item(name: string, f: () => Promise<string | undefined>): Promise<void> {
  try {
    const note = await f();
    rows.push({ name, ok: note === undefined || !note.startsWith('FAIL'), note: note ?? '' });
  } catch (e) {
    rows.push({ name, ok: false, note: (e as Error).message });
  }
}
const state = readState();
const ledgerWs = process.env.LEGX_LEDGER_WS ?? `ws://127.0.0.1:${PORTS.ledger}`;

await item('state file', async () => (state ? `${state.network}` : 'FAIL: run scripts/demo/seed.ts'));
await item('ledger reachable', async () => {
  const env = state?.network === 'testnet' ? testnetEnv() : standaloneEnv(ledgerWs);
  const client = await connect(env);
  try {
    const info = (await client.request({ command: 'server_info' })).result.info;
    return `${env.name}, ${info.complete_ledgers}`;
  } finally {
    await client.disconnect();
  }
});
await item('accounts funded', async () => {
  const funded = Object.values(state?.accounts ?? {}).filter((a) => a.funded).length;
  return funded === 6 ? '6/6' : `FAIL: ${funded}/6`;
});
await item('postgres up', async () => {
  const r = spawnSync('docker', ['exec', CONTAINERS.postgres, 'pg_isready', '-U', 'postgres'], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : `FAIL: ${r.stderr.trim() || r.stdout.trim()}`;
});
await item('mock bar registry', async () =>
  (async () => {
    const r = await probe(`${registryUrl()}/api/lawyers/XA-DM/DEMO-0001`);
    return r.status === 200 ? 'DEMO-0001 active' : `FAIL: HTTP ${r.status}`;
  })(),
);
await item('server /health', async () => {
  const r = await probe(`${serverUrl()}/health`);
  return r.status === 200
    ? `${Object.keys((JSON.parse(r.body) as { ports: object }).ports).length} ports`
    : `FAIL: HTTP ${r.status}`;
});
await item('fixture passports load', async () => `${demoPassport('alice').label}, ${demoPassport('bob').label}`);
await item('tunnel (LEGX_TUNNEL_URL)', async () =>
  process.env.LEGX_TUNNEL_URL
    ? `HTTP ${(await probe(`${process.env.LEGX_TUNNEL_URL}/health`)).status}`
    : 'FAIL: LEGX_TUNNEL_URL not set',
);
await item('sepolia RPC (LEGX_ZK_RPC)', async () => {
  const url = process.env.LEGX_ZK_RPC;
  if (!url) return 'FAIL: LEGX_ZK_RPC not set';
  const r = await probe(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}',
  });
  return r.body.includes('0xaa36a7') ? 'chain 11155111' : `FAIL: ${r.body.slice(0, 80)}`;
});
await item('recovery agent + firm co-signer', async () => {
  const r = await probe(`${serverUrl()}/health`);
  const names = r.body.includes('recovery-agent') && r.body.includes('firm-cosigner');
  return names ? 'both listed in /health' : 'FAIL: not listed in /health';
});
for (const [k, v] of Object.entries(state?.manual ?? {}))
  rows.push({ name: `manual: ${k}`, ok: v, note: v ? '' : 'FAIL: not confirmed' });

for (const r of rows) process.stdout.write(`${r.ok ? 'GREEN' : 'RED  '}  ${r.name}${r.note ? `  (${r.note})` : ''}\n`);
process.exit(rows.every((r) => r.ok) ? 0 : 1);
