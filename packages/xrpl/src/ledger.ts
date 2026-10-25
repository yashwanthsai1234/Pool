import type { Client } from 'xrpl';

/** Close one or more ledgers. Standalone only: elsewhere rippled answers notStandAlone. */
// Source: https://xrpl.org/docs/references/http-websocket-apis/admin-api-methods/server-control-methods/ledger_accept
export async function advanceLedgers(client: Client, n: number): Promise<void> {
  for (let i = 0; i < n; i++) await client.request({ command: 'ledger_accept' } as never);
}

export async function closeTime(client: Client): Promise<number> {
  const r = await client.request({ command: 'ledger', ledger_index: 'validated' });
  return r.result.ledger.close_time; // seconds since the Ripple epoch
}

/** Keep closing ledgers until the validated close_time passes `target`. Each close moves time by at least one second
 * (wall clock, never faster), so far targets are refused instead of looping for hours. */
// Source: https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/test/integration/utils.ts (waitForAndForceProgressLedgerTime)
export async function advanceCloseTime(client: Client, target: number, maxLedgers = 20_000): Promise<number> {
  for (let i = 0; i < maxLedgers; i++) {
    const t = await closeTime(client);
    if (t > target) return t;
    await advanceLedgers(client, 1);
  }
  throw new Error(`advanceCloseTime: close_time did not pass ${target} within ${maxLedgers} ledgers`);
}

export interface Fees {
  baseFeeDrops: number;
  baseReserveDrops: number;
  ownerReserveDrops: number;
}

/** Fees and reserves from `server_info` (never hard-coded: the standalone config differs from Mainnet). */
// Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/server-info-methods/server_info
export async function readFees(client: Client): Promise<Fees> {
  const info = (await client.request({ command: 'server_info' })).result.info;
  const v = info.validated_ledger;
  if (!v) throw new Error('readFees: server has no validated ledger yet');
  const drops = (xrp: number) => Math.round(xrp * 1_000_000);
  return {
    baseFeeDrops: drops(v.base_fee_xrp),
    baseReserveDrops: drops(v.reserve_base_xrp),
    ownerReserveDrops: drops(v.reserve_inc_xrp),
  };
}
