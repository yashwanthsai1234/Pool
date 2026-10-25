import type { Client } from 'xrpl';
import xrpl from 'xrpl';
import type { LedgerEnv } from './env.ts';
import { assertHostAllowed, assertNotMainnet } from './guard.ts';

/** Connects to a ledger after the Mainnet guard passes. Throws before opening any socket when the host is not allowed. */
export async function connect(env: LedgerEnv): Promise<Client> {
  assertHostAllowed(env.name, env.wsUrl);
  const client = new xrpl.Client(env.wsUrl, { timeout: 20_000 });
  await client.connect();
  try {
    await assertNotMainnet(env.name, client);
  } catch (e) {
    await client.disconnect();
    throw e;
  }
  return client;
}
