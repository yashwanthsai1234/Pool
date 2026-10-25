// `node scripts/demo/dry-run.ts` : walks the judge demo as far as the current wiring allows. Every step is run, a
// failing step is printed with its exact error and the walk goes on. Writes demo/dry-run.json (for build/ISSUES.md I-D-*).
// Needs the stack from `node scripts/dev.ts` and a seeded demo/state.json.
// Source: IMPLEMENTATION.md section 3 (demo profile); xrpl.js https://js.xrpl.org/
import { existsSync, readdirSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { demoPassport } from '../../packages/fixtures/src/index.ts';
import { connect, standaloneEnv, testnetEnv } from '../../packages/xrpl/src/index.ts';
import { PORTS, probe, ROOT, readState, registryUrl, serverUrl } from './lib.ts';
import { type DemoKey, demoSigner } from './sign.ts';

// xrpl is a dependency of packages/xrpl, not of the repo root: resolve it from there.
const xrpl = (
  await import(pathToFileURL(createRequire(resolve(ROOT, 'packages/xrpl/package.json')).resolve('xrpl')).href)
).default;
const state = readState();
if (!state) throw new Error('no demo/state.json: run node scripts/demo/seed.ts first');
const results: { step: string; who: string; ok: boolean; detail: string }[] = [];
async function step(name: string, who: string, f: () => Promise<string>): Promise<void> {
  const t = Date.now();
  try {
    results.push({ step: name, who, ok: true, detail: `${await f()} (${Date.now() - t} ms)` });
  } catch (e) {
    results.push({ step: name, who, ok: false, detail: (e as Error).message });
  }
  const r = results.at(-1);
  process.stdout.write(`${r?.ok ? 'PASS' : 'FAIL'}  [${who}] ${name}: ${r?.detail}\n`);
}
const expect = async (url: string, init: RequestInit, want: number): Promise<string> => {
  const r = await probe(url, init);
  if (r.status !== want) throw new Error(`${init.method ?? 'GET'} ${url} -> HTTP ${r.status} ${r.body.slice(0, 160)}`);
  return `HTTP ${r.status}`;
};
const post = (body: unknown): RequestInit => ({
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(body),
});
const S = serverUrl();

await step('stack health (19 ports ok)', 'laptop', async () => {
  const r = await probe(`${S}/health`);
  const ports = Object.values((JSON.parse(r.body) as { ports: Record<string, { status: string }> }).ports);
  if (ports.some((p) => p.status !== 'ok')) throw new Error(`a port is not ok: ${r.body.slice(0, 200)}`);
  return `${ports.length} ports ok`;
});
await step('both lawyers active in the mock bar registry', 'laptop', async () => {
  for (const l of state.registry.lawyers) {
    const r = await probe(`${registryUrl()}/api/lawyers/${state.registry.jurisdiction}/${l.barNumber}`);
    if (!r.body.includes('"active"')) throw new Error(`${l.barNumber}: ${r.status} ${r.body}`);
  }
  return state.registry.lawyers.map((l) => l.barNumber).join(', ');
});
await step('fixture passports: alice, bob load', 'phones', async () => {
  for (const n of ['alice', 'bob'] as const)
    if (demoPassport(n).expect !== 'accept') throw new Error(`${n} expects ${demoPassport(n).expect}`);
  return 'alice, bob expect accept';
});
await step('ledger: alice pays bob 10 XRP and it validates', 'phones', async () => {
  const env = state.network === 'testnet' ? testnetEnv() : standaloneEnv(`ws://127.0.0.1:${PORTS.ledger}`);
  const client = await connect(env);
  try {
    const alice = xrpl.Wallet.fromSeed(state.accounts.alice?.seed as string, { algorithm: xrpl.ECDSA.ed25519 });
    const tx = await client.autofill({
      TransactionType: 'Payment',
      Account: alice.classicAddress,
      Destination: state.accounts.bob?.address as string,
      Amount: xrpl.xrpToDrops(10),
    });
    const pending = client.submitAndWait(alice.sign(tx).tx_blob);
    if (env.advance)
      for (let i = 0; i < 3; i++) {
        await new Promise((r) => setTimeout(r, 500));
        await client.request({ command: 'ledger_accept' } as never);
      }
    const res = await pending;
    const code = (res.result.meta as { TransactionResult: string }).TransactionResult;
    if (code !== 'tesSUCCESS') throw new Error(code);
    return `${code} ${res.result.hash.slice(0, 12)}`;
  } finally {
    await client.disconnect();
  }
});
// One connection to the ledger for the signed requests: the signed ledger index is the newest validated one (OD-10).
const ledgerClient = await connect(
  state.network === 'testnet' ? testnetEnv() : standaloneEnv(`ws://127.0.0.1:${PORTS.ledger}`),
);
const validated = async () =>
  Number(
    ((await ledgerClient.request({ command: 'ledger', ledger_index: 'validated' })).result as { ledger_index: number })
      .ledger_index,
  );
const key = (name: string): DemoKey => {
  const k = name === 'observer' ? state.observer : state.keys?.[name];
  if (!k) throw new Error(`no demo key "${name}" in demo/state.json: run node scripts/demo/seed.ts`);
  return k;
};
const observer = demoSigner(key('observer'), validated);
const lawyerA = demoSigner(key('lawyer-a'), validated);
const lawyerB = demoSigner(key('lawyer-b'), validated);
let dealId = '';

await step('an unsigned write is refused (POST /deals -> 401)', 'laptop', () => expect(`${S}/deals`, post({}), 401));
await step('observer key authenticates the feed upgrade (signed GET /ws -> 101)', 'projector', async () => {
  const auth = await observer.feedAuth();
  const ws = new WebSocket(`${S.replace('http', 'ws')}/ws?auth=${encodeURIComponent(auth)}`);
  await new Promise<void>((resolveOpen, reject) => {
    ws.onopen = () => resolveOpen();
    ws.onerror = () => reject(new Error('the upgrade was refused'));
  });
  ws.close();
  return 'socket open';
});
await step('observer key can read but never post (signed POST /deals -> 403)', 'projector', async () => {
  const s = await observer.request(S, 'POST', '/deals', {});
  return await expect(s.url, s.init, 403);
});
await step('lawyers A and B create a deal (signed POST /deals)', 'laptop', async () => {
  const payload = {
    network: state.network,
    identityPolicy: 'zk-or-chip',
    amountDrops: '5000000000',
    payoutA: `${state.accounts.alice?.address}:7`,
    payoutB: state.accounts.bob?.address,
    lawyerOpsA: state.accounts['lawyer-a']?.address,
    lawyerOpsB: state.accounts['lawyer-b']?.address,
  };
  const s = await lawyerA.request(S, 'POST', '/deals', payload);
  const r = await probe(s.url, s.init);
  if (r.status !== 200) throw new Error(`POST /deals -> HTTP ${r.status} ${r.body.slice(0, 200)}`);
  dealId = (JSON.parse(r.body) as { dealId: string }).dealId;
  const b = await lawyerB.request(S, 'GET', `/deals/${dealId}`);
  await expect(b.url, b.init, 403); // lawyer B holds no key in this deal yet
  return `deal ${dealId}`;
});
await step('dashboard receives the new deal as observer (live feed row)', 'projector', async () => {
  const auth = await observer.feedAuth();
  const ws = new WebSocket(`${S.replace('http', 'ws')}/ws?auth=${encodeURIComponent(auth)}`);
  const row = await new Promise<string>((resolveRow, reject) => {
    const t = setTimeout(() => reject(new Error('no row within 10 s')), 10_000);
    ws.onopen = () => ws.send(JSON.stringify({ subscribe: dealId, after: -1 }));
    ws.onmessage = (m) => {
      const msg = JSON.parse(String(m.data)) as { type: string; topic?: string };
      if (msg.type === 'row') {
        clearTimeout(t);
        resolveRow(msg.topic ?? '');
      } else if (msg.type === 'error') reject(new Error(`feed error ${JSON.stringify(msg)}`));
    };
  });
  ws.close();
  return `row ${row}`;
});
await step('zk.verify answers a signed request (not 501): bad proof refused', 'phones', async () => {
  const s = await lawyerA.request(S, 'POST', `/deals/${dealId}/zk/verify`, {
    side: 'A',
    request: {},
    zkSalt32: '00'.repeat(32),
  });
  const r = await probe(s.url, s.init);
  if (![400, 403, 422].includes(r.status)) throw new Error(`HTTP ${r.status} ${r.body.slice(0, 200)}`);
  return `HTTP ${r.status}`;
});
await step(
  'headless prover (tools/zk-prove) present and its recorded fallback loads (demo profile)',
  'laptop',
  async () => {
    if (!existsSync(resolve(ROOT, 'tools/zk-prove/cli.ts'))) throw new Error('tools/zk-prove/cli.ts does not exist');
    const { loadRecorded } = await import('../../tools/zk-prove/src/recorded.ts');
    loadRecorded('alice-release', 'demo');
    return 'cli.ts present, recorded proof loads';
  },
);
await step('recorded ZK proofs for the fallback (3 sets, production refuses them)', 'laptop', async () => {
  const dir = resolve(ROOT, 'demo/recorded-proofs/sets');
  if (!existsSync(dir) || readdirSync(dir).length < 3)
    throw new Error('demo/recorded-proofs/sets has fewer than 3 sets');
  const { loadRecorded } = await import('../../tools/zk-prove/src/recorded.ts');
  try {
    loadRecorded('alice-release', 'production');
  } catch (e) {
    return `${readdirSync(dir).length} sets; production: ${(e as { code?: string }).code}`;
  }
  throw new Error('production profile accepted a recorded proof');
});
await step('rehearsal screenshots of every scene (replaces the backup video)', 'laptop', async () => {
  const dir = resolve(ROOT, 'demo/rehearsal');
  const shots = existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith('.png')) : [];
  if (shots.length < 4) throw new Error('fewer than 4 screenshots in demo/rehearsal: run pnpm demo:rehearse');
  return `${shots.length} screenshots`;
});

await ledgerClient.disconnect();
writeFileSync(resolve(ROOT, 'demo', 'dry-run.json'), `${JSON.stringify(results, null, 2)}\n`);
const failed = results.filter((r) => !r.ok).length;
process.stdout.write(`\n${results.length - failed}/${results.length} steps passed\n`);
process.exit(failed === 0 ? 0 : 1);
