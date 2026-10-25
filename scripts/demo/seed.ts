// `node scripts/demo/seed.ts [--network testnet|standalone] [--reset]` (P5.6-01, P5.6-07). Idempotent: a second run
// changes nothing and calls no faucet. State: demo/state.json. Steps that need other tasks are listed as "pending".
// Source: https://xrpl.org/docs/tutorials/public-servers/ (faucet); Node ML-DSA https://nodejs.org/docs/latest-v24.x/api/crypto.html#cryptogeneratekeypairtype-options
import { generateKeyPairSync } from 'node:crypto';
import { LAWYERS } from '../../apps/mock-bar-registry/src/data.ts';
import { DEMO_NAMES, demoPassport } from '../../packages/fixtures/src/index.ts';
import { connect, fundAccount, standaloneEnv, testnetEnv } from '../../packages/xrpl/src/index.ts';
import { arg, type DemoState, MANUAL_CHECKLIST, PORTS, ROLES, readState, resetState, writeState } from './lib.ts';

if (process.argv.includes('--reset')) resetState();
const network = (arg('network') ?? readState()?.network ?? 'standalone') as DemoState['network'];
if (network !== 'testnet' && network !== 'standalone') throw new Error(`--network must be testnet or standalone`);

const raw = (k: Buffer | string) => (typeof k === 'string' ? k : k.toString('hex'));
function makeKey(prefix: string): DemoState['observer'] {
  const ed = generateKeyPairSync('ed25519');
  const pq = generateKeyPairSync('ml-dsa-65');
  const pub = (k: typeof ed.publicKey) => raw(k.export({ format: 'der', type: 'spki' }));
  const priv = (k: typeof ed.privateKey) => raw(k.export({ format: 'der', type: 'pkcs8' }));
  const ed25519Public = pub(ed.publicKey);
  return {
    keyId: `${prefix}-${ed25519Public.slice(-16)}`,
    ed25519Public,
    mlDsa65Public: pub(pq.publicKey),
    ed25519Private: priv(ed.privateKey),
    mlDsa65Private: priv(pq.privateKey),
  };
}

const state: DemoState = readState() ?? {
  version: 1,
  network,
  accounts: {},
  registry: { jurisdiction: 'XA-DM', lawyers: [] },
  passports: {},
  observer: makeKey('observer'),
  keys: {},
  lawyersOnboarded: {},
  frostDkg: {},
  pqBound: false,
  manual: Object.fromEntries(MANUAL_CHECKLIST.map((c) => [c, false])),
  faucetCalls: 0,
};
if (state.network !== network) throw new Error(`state is for ${state.network}; run with --reset to switch`);

// The demo enrollment keys the server pins (LEGX_LAWYER_KEYS, LEGX_OBSERVER_KEYS, LEGX_OPERATOR_KEYS are built from them
// by apps/server/src/demo.ts). Made once; a second run keeps them.
state.keys ??= {};
for (const k of ['lawyer-a', 'lawyer-b', 'operator']) state.keys[k] ??= makeKey(k);

// Mock bar registry: lawyer-a and lawyer-b are the two active demo lawyers (DEMO-0001, DEMO-0002).
const active = LAWYERS.filter((l) => l.status === 'active');
state.registry.lawyers = active.map((l, i) => ({
  role: i === 0 ? 'lawyer-a' : 'lawyer-b',
  barNumber: l.barNumber,
  name: l.name,
}));
for (const n of DEMO_NAMES) {
  const d = demoPassport(n);
  state.passports[n] = { name: n, label: d.label, expect: d.expect };
}

// Fund the 6 accounts: only the missing ones, one faucet call each (Testnet faucet caps at 1000 XRP).
const missing = ROLES.filter((r) => !state.accounts[r]?.funded);
if (missing.length > 0) {
  const env = network === 'testnet' ? testnetEnv() : standaloneEnv(`ws://127.0.0.1:${PORTS.ledger}`);
  const client = await connect(env);
  try {
    for (const role of missing) {
      const w = await fundAccount(env, client, 1000);
      state.accounts[role] = { address: w.classicAddress, seed: w.seed as string, funded: true };
      if (network === 'testnet') state.faucetCalls++;
      writeState(state); // resume point after every account
      process.stdout.write(`funded ${role} ${w.classicAddress}\n`);
    }
  } finally {
    await client.disconnect();
  }
}

// Not buildable yet (see build/ISSUES.md I-D-*): onboarding (0a, 0b), the FROST DKG and the PQ binding need signed
// requests from an enrolled key; the composed server mounts them but the client side is not wired.
for (const r of ['lawyer-a', 'lawyer-b']) state.lawyersOnboarded[r] ??= false;
writeState(state);
const pending = Object.entries(state.lawyersOnboarded)
  .filter(([, v]) => !v)
  .map(([k]) => k);
process.stdout.write(
  `seed ok (${network}): ${Object.keys(state.accounts).length} accounts, faucet calls ${state.faucetCalls}, observer ${state.observer.keyId}\n` +
    `pending (needs wiring): onboarding ${pending.join(', ')}; frost DKG; pq binding\n` +
    `manual: ${Object.entries(state.manual).filter(([, v]) => !v).length} checklist items open\n`,
);
