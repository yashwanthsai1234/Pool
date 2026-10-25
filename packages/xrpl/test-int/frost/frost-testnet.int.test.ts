// T-I-11, Testnet variant. Nightly (tag: nightly): run by hand with LEGX_TESTNET=1. It uses the public faucet twice
// and waits about 256 ledgers (roughly 15 minutes) before the AccountDelete. Never runs in pull requests; never Mainnet.
import { describe, expect, it } from 'vitest';
import xrpl from 'xrpl';
import { connect } from '../../src/connect.ts';
import { testnetEnv } from '../../src/env.ts';
import { fundAccount } from '../../src/fund.ts';
import { readFees } from '../../src/ledger.ts';
import { dkgKit, NAMES, type Net, runDeal } from './support.ts';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe.skipIf(!process.env.LEGX_TESTNET)('nightly: T-I-11 on Testnet', () => {
  it('lock steps, exit and close signed by four 2-of-3 FROST slots; every transaction tesSUCCESS', async () => {
    const env = testnetEnv();
    const client = await connect(env);
    try {
      const slots = await Promise.all(NAMES.map(dkgKit));
      const net: Net = {
        client,
        ctx: { network: 'testnet', baseFeeDrops: (await readFees(client)).baseFeeDrops },
        fund: (xrp) => fundAccount(env, client, xrp),
        waitUntil: async (index) => {
          for (;;) {
            const r = await client.request({ command: 'ledger', ledger_index: 'validated' });
            if (r.result.ledger_index >= index) return;
            await sleep(5000);
          }
        },
        timeoutMs: 180_000,
      };
      const deal = await runDeal(net, slots);
      expect(deal.steps).toHaveLength(4);
      for (const step of deal.steps) {
        const t = (await client.request({ command: 'tx', transaction: step.hash })).result as unknown as {
          validated: boolean;
          tx_json: { Signers: { Signer: { SigningPubKey: string; Account: string } }[] };
        };
        expect(t.validated).toBe(true);
        expect(t.tx_json.Signers.map((x) => x.Signer.SigningPubKey).sort()).toEqual([...deal.groupKeys].sort());
        for (const { Signer } of t.tx_json.Signers)
          expect(xrpl.deriveAddress(Signer.SigningPubKey)).toBe(Signer.Account);
      }
    } finally {
      await client.disconnect();
    }
  }, 2_400_000);
});
