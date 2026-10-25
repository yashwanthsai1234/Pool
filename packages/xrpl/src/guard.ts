// Hard rule 1: never touch XRPL Mainnet. Every check runs before the socket is opened, except the
// server_info checks, which run before any other request. A config value alone is never trusted.
// Source: https://xrpl.org/docs/concepts/networks-and-servers/parallel-networks (network ids: Mainnet 0, Testnet 1, Devnet 2)

export type EnvName = 'standalone' | 'testnet' | 'devnet';

/** Known public Mainnet endpoints. The allow-list below is the stronger check; this list names the obvious ones. */
export const MAINNET_HOST_DENYLIST = [
  'xrplcluster.com',
  'ripple.com',
  'xrpl.ws',
  'xrpl.link',
  'xrpl.org',
  'xrpscan.com',
  'bithomp.com',
  'xrpl.to',
] as const;

const NETWORK_ID: Record<EnvName, number> = { standalone: 0, testnet: 1, devnet: 2 };

const onDomain = (host: string, domain: string) => host === domain || host.endsWith(`.${domain}`);

function isPrivateHost(host: string): boolean {
  if (host === 'localhost' || host === '[::1]' || host === 'host.docker.internal') return true;
  const m = /^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/.exec(host);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 127 || a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31);
}

/** Throws unless the URL is allowed for this environment. Pure: sends nothing. */
export function assertHostAllowed(name: EnvName, wsUrl: string): void {
  const netVar = (process.env.NETWORK ?? '').trim().toLowerCase();
  if (netVar === 'mainnet' || netVar === 'main' || netVar === 'livenet') {
    throw new Error('Refusing to connect: NETWORK=mainnet. This project never talks to Mainnet (hard rule 1).');
  }
  if (!(name in NETWORK_ID)) throw new Error(`Refusing to connect: unknown environment "${String(name)}".`);
  let host: string;
  try {
    const u = new URL(wsUrl);
    if (u.protocol !== 'ws:' && u.protocol !== 'wss:') throw new Error('not a ws(s) URL');
    host = u.hostname.toLowerCase();
  } catch {
    throw new Error(`Refusing to connect: invalid WebSocket URL "${wsUrl}".`);
  }
  if (MAINNET_HOST_DENYLIST.some((d) => onDomain(host, d))) {
    throw new Error(`Refusing to connect: ${host} is a known Mainnet host (hard rule 1).`);
  }
  // Positive allow-list: standalone only on this machine or a private network; test networks only on rippletest.net.
  const ok = name === 'standalone' ? isPrivateHost(host) : onDomain(host, 'rippletest.net');
  if (!ok) throw new Error(`Refusing to connect: ${host} is not an allowed host for the ${name} environment.`);
}

interface ServerInfoResult {
  info: { network_id?: number; peers?: number; validation_quorum?: number };
}
interface LedgerResult {
  ledger: { parent_hash: string; close_time: number; total_coins: string };
}
type Requester = { request: (r: never) => Promise<{ result: unknown }> };
const ask = (c: Requester, r: { command: string; [k: string]: unknown }) => c.request(r as never);

/** Checks `server_info.network_id` and, for standalone, that this is a private ledger with no peers and no validator list.
 * Ledger 1 is the strongest proof (Mainnet history has no ledger 1, and its parent hash, close time and coins are fixed),
 * but online_delete drops it after 256 ledgers, so a standalone node without it must still show zero peers and quorum 0. */
export async function assertNotMainnet(name: EnvName, client: Requester): Promise<void> {
  const info = ((await ask(client, { command: 'server_info' })).result as ServerInfoResult).info;
  const id = info.network_id ?? 0;
  if (id !== NETWORK_ID[name]) {
    throw new Error(
      `Refusing to use this server: network_id ${id} does not match ${name} (${NETWORK_ID[name]}). Mainnet is 0.`,
    );
  }
  if (name !== 'standalone') return;
  const genesis = await ask(client, { command: 'ledger', ledger_index: 1 })
    .then((r) => (r.result as LedgerResult).ledger)
    .catch(() => undefined);
  if (genesis !== undefined) {
    const ok =
      /^0+$/.test(genesis.parent_hash) && genesis.close_time === 0 && genesis.total_coins === '100000000000000000';
    if (!ok)
      throw new Error(
        'Refusing to use this server: ledger 1 is not a genesis ledger, so it is not a standalone ledger.',
      );
    return;
  }
  if (info.peers !== 0 || info.validation_quorum !== 0) {
    throw new Error(
      'Refusing to use this server: no genesis ledger 1 and it has peers or a validator quorum, so it may be Mainnet.',
    );
  }
}
