// Nightly only (tag: nightly). Run by hand with LEGX_NIGHTLY=1. Never runs in pull requests: it calls the public faucets.
import { describe, expect, it } from 'vitest';
import {
  advanceLedgers,
  assertAmendments,
  connect,
  devnetEnv,
  fundAccount,
  readFees,
  testnetEnv,
} from '../src/index.ts';
import { newDeal } from './deal.ts';
import { openChain } from './roles.ts';

describe.skipIf(!process.env.LEGX_NIGHTLY)('nightly: Testnet and Devnet', () => {
  it('Testnet: guard, amendments, fees (P2.1-02, P2.1-07), faucet funding (P2.1-04)', async () => {
    const env = testnetEnv();
    const client = await connect(env);
    try {
      await assertAmendments(client);
      expect(await readFees(client)).toEqual({
        baseFeeDrops: 10,
        baseReserveDrops: 1_000_000,
        ownerReserveDrops: 200_000,
      });
      const w = await fundAccount(env, client, 100);
      const info = await client.request({
        command: 'account_info',
        account: w.classicAddress,
        ledger_index: 'validated',
      });
      expect(Number(info.result.account_data.Balance)).toBeGreaterThanOrEqual(1_000_000);
      await expect(advanceLedgers(client, 1)).rejects.toThrow();
    } finally {
      await client.disconnect();
    }
  }, 120_000);

  it('Devnet: guard and amendments (P2.1-02)', async () => {
    const client = await connect(devnetEnv());
    try {
      await assertAmendments(client);
    } finally {
      await client.disconnect();
    }
  }, 60_000);
});

// T-N-01: the T-I-01 flow (P0 to P8, chip identity, Ed25519 operations accounts, every slot signing by FROST) on a
// public test network. Slow: the 256-ledger wait before AccountDelete takes about 20 minutes at 4 s a ledger.
// Run: LEGX_TESTNET=1 pnpm vitest run --project integration packages/xrpl/test-int/network.int.test.ts
// Only Testnet is run here (Devnet's amendments move; its guard check is above). Never Mainnet (hard rule 1).
describe.skipIf(!process.env.LEGX_TESTNET)('T-N-01 full flow on Testnet', () => {
  it('P0 to P8 end to end: the gate passes, the escrow is released, Bob is paid, the shell closes to Alice', async () => {
    const c = await openChain(testnetEnv());
    try {
      const d = await newDeal(c, 'locked');
      const gate = await d.gate();
      expect(gate.failing).toEqual([]);
      await d.release();
      const exit = await d.exit('bob');
      expect(exit.receiverAfter - exit.receiverBefore).toBe(BigInt('50000000'));
      await d.closeShell();
      await expect(
        c.client.request({ command: 'account_info', account: d.wallet, ledger_index: 'validated' }),
      ).rejects.toMatchObject({ data: { error: 'actNotFound' } });
      expect(c.log.filter((l) => l.result !== 'tesSUCCESS')).toEqual([]);
    } finally {
      await c.close();
    }
  }, 3_600_000);
});
