// Prerequisite probes. A full SYS flow needs several capabilities; each probe asks the running system whether one exists.
// A SYS test that lists a failing probe is an `it.fails` with the issue that owns the probe, so it flips when the last
// blocker is fixed (and must then be strengthened to drive the whole flow, see REGRESSION.md).
import { execSync } from 'node:child_process';
import { connect } from '@legx/xrpl/connect';
import { standaloneEnv } from '@legx/xrpl/env';
import { fundAccount } from '@legx/xrpl/fund';
import pg from 'pg';
import type { Deal } from './deal.ts';
import { LEDGER_WS, ROOT, type Stack, waitFor } from './stack.ts';

export type Probe =
  | 'purposes'
  | 'gate'
  | 'zkRoute'
  | 'keysRegister'
  | 'watcher'
  | 'webWiring'
  | 'recoveryProof'
  | 'observer'
  | 'bundle';

/** The issue that owns each probe. */
export const OWNER: Record<Probe, string> = {
  purposes: 'I-14',
  gate: 'I-3.7-g',
  zkRoute: 'I-3.7-d',
  keysRegister: 'I-W-1',
  watcher: 'I-W-4',
  webWiring: 'I-31 / I-W-2 / I-W-10',
  recoveryProof: 'I-21 / I-W-13',
  observer: 'I-W-11',
  bundle: 'I-W-8',
};

const grep = (pattern: string, where: string) =>
  execSync(`grep -rnE "${pattern}" ${where} --include=*.ts --include=*.tsx || true`, {
    cwd: ROOT,
    encoding: 'utf8',
    shell: '/bin/bash',
  }).trim();

export async function runProbe(p: Probe, stack: Stack, deal: Deal): Promise<boolean> {
  switch (p) {
    case 'purposes':
      for (const purpose of ['ticket_create', 'signer_list_update', 'seal_update', 'escrow_finish']) {
        const r = await stack.call(deal.alice, 'POST', `/deals/${deal.dealId}/signature-requests`, { purpose });
        if (r.status === 501) return false;
      }
      return true;
    case 'gate':
      return (
        ((await (await fetch(`${stack.url}/health`)).json()) as { ports: Record<string, { impl: string }> }).ports[
          'release-gate'
        ]?.impl !== 'stub'
      );
    case 'zkRoute':
      return (await stack.call(deal.lawyerA, 'POST', `/deals/${deal.dealId}/zk/verify`, {})).status !== 501;
    case 'keysRegister':
      return (await stack.call(deal.alice, 'POST', '/enrollment-keys', {})).status !== 501;
    case 'watcher':
      return await walletObserved(stack, deal);
    case 'webWiring':
      return grep('<(PartyProvider|ConsoleProvider)\\b', 'apps/web/src') === '';
    case 'recoveryProof':
      return grep("Refusal\\('PROOF_NOT_VERIFIED'\\)", 'apps/server/src') === '';
    case 'observer':
      return grep('observer', 'apps/server/src apps/web/src/lib') !== '';
    case 'bundle':
      return (await stack.call(deal.alice, 'POST', `/deals/${deal.dealId}/bundle`, { side: 'A' })).status !== 501;
  }
}

/** Funds a wallet, registers it with deals.setWallet and waits for the watcher to observe a transaction of it. */
export async function walletObserved(stack: Stack, deal: Deal): Promise<boolean> {
  const env = standaloneEnv(LEDGER_WS);
  const client = await connect(env);
  try {
    const w = await fundAccount(env, client, 100);
    const r = await stack.call(deal.alice, 'POST', `/deals/${deal.dealId}/wallet`, { walletAddress: w.classicAddress });
    if (r.status !== 200) return false;
    const c = new pg.Client({ connectionString: stack.pgUrl });
    await c.connect();
    try {
      await waitFor(
        async () =>
          (await c.query('select 1 from ledger_observation where account = $1', [w.classicAddress])).rows.length > 0,
        6000,
        'observation',
      );
      return true;
    } catch {
      return false;
    } finally {
      await c.end();
    }
  } finally {
    await client.disconnect();
  }
}
