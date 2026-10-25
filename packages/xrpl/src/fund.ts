import type { Client } from 'xrpl';
import xrpl from 'xrpl';
import type { LedgerEnv } from './env.ts';
import { advanceLedgers } from './ledger.ts';

// The standalone genesis account. The seed is public and test-only.
// Source: https://xrpl.org/docs/infrastructure/testing-and-auditing/start-a-new-genesis-ledger-in-stand-alone-mode
export const GENESIS = xrpl.Wallet.fromSeed('snoPBrXtMeMyMHUVTgbuqAfg1SUTb', { algorithm: xrpl.ECDSA.secp256k1 });

// Genesis payments share one Sequence counter, so they run one at a time per client.
const queues = new WeakMap<Client, Promise<unknown>>();
function serial<T>(client: Client, job: () => Promise<T>): Promise<T> {
  const run = (queues.get(client) ?? Promise.resolve()).then(job, job);
  queues.set(
    client,
    run.catch(() => undefined),
  );
  return run;
}

async function fundFromGenesis(client: Client, dest: string, xrp: number): Promise<void> {
  await serial(client, async () => {
    const tx = await client.autofill({
      TransactionType: 'Payment',
      Account: GENESIS.classicAddress,
      Destination: dest,
      Amount: String(xrp * 1_000_000),
    });
    const res = await client.submit(GENESIS.sign(tx).tx_blob);
    await advanceLedgers(client, 1);
    const code = res.result.engine_result;
    if (code !== 'tesSUCCESS')
      throw new Error(`fundAccount: genesis payment rejected: ${code} ${res.result.engine_result_message}`);
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Faucet call with exponential backoff. Never used in pull-request tests (nightly only). */
// Source: https://xrpl.org/docs/tutorials/public-servers (faucets); behaviour measured in research r5-xrpl.md section 3
export async function fundFromFaucet(
  env: LedgerEnv,
  client: Client,
  dest: string,
  xrp: number,
  attempts = 5,
): Promise<void> {
  if (!env.faucetUrl) throw new Error(`fundAccount: ${env.name} has no faucet`);
  let lastError = '';
  for (let i = 0; i < attempts; i++) {
    try {
      const r = await fetch(env.faucetUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ destination: dest, xrpAmount: String(xrp), userAgent: 'legx' }),
      });
      if (r.ok) break;
      lastError = `HTTP ${r.status}`;
      if (r.status === 400) throw new Error(`faucet rejected the request: ${await r.text()}`);
    } catch (e) {
      lastError = String(e);
      if (lastError.includes('faucet rejected')) throw e;
    }
    if (i === attempts - 1) throw new Error(`fundAccount: faucet failed after ${attempts} attempts (${lastError})`);
    await sleep(2000 * 2 ** i);
  }
  for (let i = 0; i < 40; i++) {
    const r = await client
      .request({ command: 'account_info', account: dest, ledger_index: 'validated' })
      .catch(() => undefined);
    if (r) return;
    await sleep(1000);
  }
  throw new Error('fundAccount: funded account did not appear in a validated ledger within 40 s');
}

/** Creates a new Ed25519 wallet holding `xrp` XRP (default 1000; the faucet caps at 1000). */
export async function fundAccount(
  env: LedgerEnv,
  client: Client,
  xrp = 1000,
): Promise<InstanceType<typeof xrpl.Wallet>> {
  const wallet = xrpl.Wallet.generate(xrpl.ECDSA.ed25519);
  if (env.name === 'standalone') await fundFromGenesis(client, wallet.classicAddress, xrp);
  else await fundFromFaucet(env, client, wallet.classicAddress, xrp);
  return wallet;
}
