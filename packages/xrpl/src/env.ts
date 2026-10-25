import type { EnvName } from './guard.ts';

export type { EnvName };

/** One place that describes a ledger we may talk to. `advance` exists only where we control ledger closing (standalone). */
export interface LedgerEnv {
  name: EnvName;
  wsUrl: string;
  clioUrl?: string;
  /** Faucet base URL (testnet and devnet only). */
  faucetUrl?: string;
  /** True only on standalone: ledgers close when asked, so time travel is possible. */
  advance?: true;
}

export function standaloneEnv(wsUrl = process.env.XRPLD_WS ?? 'ws://127.0.0.1:6101'): LedgerEnv {
  return { name: 'standalone', wsUrl, advance: true };
}

// Source: https://xrpl.org/docs/concepts/networks-and-servers/parallel-networks
export function testnetEnv(): LedgerEnv {
  return {
    name: 'testnet',
    wsUrl: 'wss://s.altnet.rippletest.net:51233',
    clioUrl: 'wss://clio.altnet.rippletest.net:51233',
    faucetUrl: 'https://faucet.altnet.rippletest.net/accounts',
  };
}

export function devnetEnv(): LedgerEnv {
  return {
    name: 'devnet',
    wsUrl: 'wss://s.devnet.rippletest.net:51233',
    clioUrl: 'wss://clio.devnet.rippletest.net:51233',
    faucetUrl: 'https://faucet.devnet.rippletest.net/accounts',
  };
}
