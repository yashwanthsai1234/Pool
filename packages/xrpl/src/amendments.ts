import type { Client } from 'xrpl';

// Amendments the design needs (DESIGN 7.1).
export const REQUIRED_AMENDMENTS = [
  'Escrow',
  'MultiSign',
  'MultiSignReserve',
  'ExpandedSignerList',
  'DepositAuth',
  'DepositPreauth',
  'TicketBatch',
  'DisallowIncoming',
  'Credentials',
] as const;

// Retired amendments: their code is always on, but `feature` reports enabled:false or vetoed:"Obsolete".
// Accepted without a check (DESIGN 11.2). TicketBatch retired in rippled 3.2.0 (research r5-xrpl.md, section 2).
// Source: https://xrpl.org/resources/known-amendments
export const RETIRED_AMENDMENTS: ReadonlySet<string> = new Set([
  'Escrow',
  'MultiSign',
  'CryptoConditions',
  'DepositAuth',
  'DepositPreauth',
  'MultiSignReserve',
  'ExpandedSignerList',
  'DeletableAccounts',
  'DisallowIncoming',
  'TicketBatch',
]);

interface Feature {
  name: string;
  enabled: boolean;
  vetoed?: boolean | 'Obsolete';
}

// Public account rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh is the standalone genesis account; any address works for this probe.
const PROBE_ACCOUNT = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';
const PROBE_SUBJECT = 'rrrrrrrrrrrrrrrrrrrrBZbvji';

/** Credentials can be live while `feature` says enabled:false (standalone with a [features] stanza), so ask the engine.
 * `simulate` never applies anything; temDISABLED comes from preflight, before any account lookup. */
// Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/transaction-methods/simulate
async function credentialsLive(client: Client): Promise<boolean> {
  const r = await client.request({
    command: 'simulate',
    tx_json: {
      TransactionType: 'CredentialCreate',
      Account: PROBE_ACCOUNT,
      Subject: PROBE_SUBJECT,
      CredentialType: '4B5943',
    },
  });
  return (r.result as { engine_result: string }).engine_result !== 'temDISABLED';
}

/** Throws with a message naming every required amendment that is not usable on this server. */
// Source: https://xrpl.org/docs/references/http-websocket-apis/admin-api-methods/status-and-debugging-methods/feature
export async function assertAmendments(
  client: Client,
  required: readonly string[] = REQUIRED_AMENDMENTS,
): Promise<void> {
  const res = await client.request({ command: 'feature' });
  const features = Object.values((res.result as { features: Record<string, Feature> }).features);
  const byName = new Map(features.map((f) => [f.name, f]));
  const missing: string[] = [];
  for (const name of required) {
    const f = byName.get(name);
    if (f?.enabled === true) continue;
    if (f?.vetoed === 'Obsolete' || RETIRED_AMENDMENTS.has(name)) continue;
    if (name === 'Credentials' && f !== undefined && (await credentialsLive(client))) continue;
    missing.push(name);
  }
  if (missing.length > 0) {
    throw new Error(`Required amendments not enabled on this ledger: ${missing.join(', ')}`);
  }
}
