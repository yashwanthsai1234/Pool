// Explorer links for the ledger log (IMPLEMENTATION 4.5 "Explorers"). The standalone ledger has no explorer, so it has no link.
// Source: https://testnet.xrpl.org (patterns /transactions/<hash>, /accounts/<address>, /nft/<id>); the backup is
// https://test.bithomp.com (/en/explorer/<hash>, /en/account/<address>, /en/nft/<id>).
export type Network = 'standalone' | 'testnet' | 'devnet' | 'mainnet';
export const NETWORKS: readonly Network[] = ['standalone', 'testnet', 'devnet', 'mainnet'];

const HOST: Record<Network, string | undefined> = {
  standalone: undefined,
  testnet: 'https://testnet.xrpl.org',
  devnet: 'https://devnet.xrpl.org',
  mainnet: 'https://livenet.xrpl.org',
};
const BITHOMP = 'https://test.bithomp.com';

export type Kind = 'tx' | 'account' | 'nft';
const PRIMARY: Record<Kind, string> = { tx: 'transactions', account: 'accounts', nft: 'nft' };
const BACKUP: Record<Kind, string> = { tx: 'explorer', account: 'account', nft: 'nft' };

/** The link for an id on the active network, or undefined where there is no explorer. `backup` picks bithomp (Testnet only). */
export function explorerUrl(network: Network, kind: Kind, id: string, backup = false): string | undefined {
  const safe = encodeURIComponent(id);
  if (backup) return network === 'testnet' ? `${BITHOMP}/en/${BACKUP[kind]}/${safe}` : undefined;
  const host = HOST[network];
  return host ? `${host}/${PRIMARY[kind]}/${safe}` : undefined;
}
