import { execFileSync } from 'node:child_process';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Client } from 'xrpl';
import {
  advanceCloseTime,
  advanceLedgers,
  assertAmendments,
  closeTime,
  connect,
  fundAccount,
  readFees,
  standaloneEnv,
} from '../src/index.ts';
import { submitAccept } from './harness.ts';

const env = standaloneEnv();
const docker = (...a: string[]) => execFileSync('docker', a, { encoding: 'utf8' }).trim();
const ledgerIndex = async (c: Client) =>
  ((await c.request({ command: 'ledger', ledger_index: 'validated' })).result as { ledger_index: number }).ledger_index;

// A throwaway second ledger on a free host port, to prove ledgers share no state and to run the broken-config test.
async function startExtra(name: string, cfgDir?: string) {
  docker('rm', '-f', name);
  docker(
    'run',
    '-d',
    '--name',
    name,
    '--platform',
    'linux/amd64',
    '-p',
    '127.0.0.1::6006',
    '-v',
    `${cfgDir ?? `${process.cwd()}/ci`}:/etc/xrpld/:ro`,
    'rippleci/xrpld:3.4.1',
    '--standalone',
  );
  const port = docker('port', name, '6006/tcp').split('\n')[0]?.split(':').pop();
  const e = standaloneEnv(`ws://127.0.0.1:${port}`);
  for (let i = 0; i < 60; i++) {
    try {
      return { env: e, client: await connect(e) };
    } catch {
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
  throw new Error(`${name} did not start`);
}

describe('standalone ledger', () => {
  let client: Client;
  beforeAll(async () => {
    client = await connect(env);
  });
  afterAll(async () => {
    await client.disconnect();
  });

  it('P2.1-01 server_info answers and the ledger is standalone genesis', async () => {
    const info = (await client.request({ command: 'server_info' })).result.info;
    expect(info.build_version).toBe('3.4.1');
    expect(info.network_id ?? 0).toBe(0);
  });

  it('P2.1-02 assertAmendments passes with the xrpl.js config', async () => {
    await expect(assertAmendments(client)).resolves.toBeUndefined();
  });

  it('P2.1-04 fundAccount (genesis) creates an account with at least the reserve, also concurrently', async () => {
    const amounts = [100, 50, 25];
    const wallets = await Promise.all(amounts.map((xrp) => fundAccount(env, client, xrp)));
    const fees = await readFees(client);
    for (const [i, w] of wallets.entries()) {
      const info = await client.request({
        command: 'account_info',
        account: w.classicAddress,
        ledger_index: 'validated',
      });
      const balance = Number(info.result.account_data.Balance);
      expect(balance).toBe((amounts[i] ?? 0) * 1_000_000);
      expect(balance).toBeGreaterThanOrEqual(fees.baseReserveDrops);
    }
  });

  it('P2.1-04 fundAccount below the reserve fails with the engine code', async () => {
    await expect(fundAccount(env, client, 1)).rejects.toThrow(/tecNO_DST_INSUF_XRP/);
  });

  it('P2.1-05 advanceCloseTime moves the validated close_time past the target', async () => {
    const target = (await closeTime(client)) + 120;
    const t = await advanceCloseTime(client, target);
    expect(t).toBeGreaterThan(target);
    expect(await closeTime(client)).toBeGreaterThan(target);
  });

  it('P2.1-05 advanceCloseTime refuses an unreachable target instead of looping', async () => {
    await expect(advanceCloseTime(client, (await closeTime(client)) + 10 ** 7, 50)).rejects.toThrow(/did not pass/);
  });

  it('P2.1-06 advanceLedgers(260) moves the ledger index by at least 260', async () => {
    const before = await ledgerIndex(client);
    await advanceLedgers(client, 260);
    expect((await ledgerIndex(client)) - before).toBeGreaterThanOrEqual(260);
  });

  it('P2.1-07 readFees matches the standalone test config', async () => {
    expect(await readFees(client)).toEqual({
      baseFeeDrops: 200,
      baseReserveDrops: 20_000_000,
      ownerReserveDrops: 5_000_000,
    });
  });

  it('harness fix: a transaction rejected before it is applied reports its engine_result', async () => {
    const w = await fundAccount(env, client, 100);
    const r = await submitAccept(
      client,
      { TransactionType: 'Payment', Account: w.classicAddress, Destination: w.classicAddress, Amount: '1000000' },
      w,
    );
    expect(r.engine).toBe('temREDUNDANT');
    expect(r.final).toBe('temREDUNDANT');
  });

  it('two standalone ledgers share no state', async () => {
    const other = await startExtra('legx-2.1-xrpld-b');
    try {
      const w = await fundAccount(env, client, 100);
      const missing = await other.client
        .request({ command: 'account_info', account: w.classicAddress, ledger_index: 'validated' })
        .catch((e) => e.data);
      expect(missing.error).toBe('actNotFound');
      await advanceLedgers(other.client, 5);
      const a = await ledgerIndex(client);
      await advanceLedgers(other.client, 5);
      expect(await ledgerIndex(client)).toBe(a);
    } finally {
      await other.client.disconnect();
      docker('rm', '-f', 'legx-2.1-xrpld-b');
    }
  });

  it('P2.1-03 a config without the Credentials stanza fails and names Credentials', async () => {
    const { chmodSync, mkdtempSync, readFileSync, writeFileSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const dir = mkdtempSync(`${tmpdir()}/legx-nocred-`);
    writeFileSync(
      `${dir}/xrpld.cfg`,
      readFileSync(`${process.cwd()}/ci/xrpld.cfg`, 'utf8').replace(/^Credentials$/m, ''),
    );
    // mkdtemp makes the folder 0700; the container's own user must read the mounted config (Linux CI).
    chmodSync(dir, 0o755);
    chmodSync(`${dir}/xrpld.cfg`, 0o644);
    const bare = await startExtra('legx-2.1-xrpld-nocred', dir);
    try {
      await expect(assertAmendments(bare.client)).rejects.toThrow(/Credentials/);
    } finally {
      await bare.client.disconnect();
      docker('rm', '-f', 'legx-2.1-xrpld-nocred');
    }
  });

  it('I-2.6-d the config keeps the history: a ledger 600 closes old is still readable by number and by tx hash', async () => {
    const name = 'legx-f5-xrpld-history';
    const node = await startExtra(name);
    try {
      const w = await fundAccount(node.env, node.client, 100);
      const first = await ledgerIndex(node.client);
      await advanceLedgers(node.client, 600);
      expect(await ledgerIndex(node.client)).toBeGreaterThanOrEqual(first + 600);
      const old = await node.client.request({ command: 'ledger', ledger_index: first });
      expect(Number(old.result.ledger.ledger_index)).toBe(first);
      const info = await node.client.request({
        command: 'account_info',
        account: w.classicAddress,
        ledger_index: first,
      });
      expect(info.result.account_data.Account).toBe(w.classicAddress);
    } finally {
      await node.client.disconnect();
      docker('rm', '-f', name);
    }
  }, 120_000);
});
