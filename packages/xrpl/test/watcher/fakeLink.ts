// A model ledger behind the watcher's Link: API v2 shapes as measured on xrpld 3.4.1 (build/tmp/2.7/probe.ts).
import type { XrplJson } from '@legx/contracts/ports';
import xrpl from 'xrpl';
import type { RpcRequest } from '../../src/read.ts';
import type { Link, LinkEvent } from '../../src/watcher/link.ts';

export interface FakeTx {
  hash: string;
  ledger: number;
  index: number;
  accounts: string[];
}

const hex = (n: number, salt: string) => (salt + n.toString(16)).padStart(64, '0').toUpperCase().slice(-64);
const ledgerHash = (n: number, salt = 'A') => hex(n, salt);

/** One shared chain; a FakeLink is one server's view of it (it may lag, or fork with another salt). */
export class FakeChain {
  txs: FakeTx[] = [];
  head = 1;
  private seq = 0;
  /** Closes one ledger holding `accounts` transactions, one per entry. Returns the new transactions. */
  close(per: string[][]): FakeTx[] {
    this.head += 1;
    const made = per.map((accounts, index) => ({
      hash: hex(++this.seq, 'B'),
      ledger: this.head,
      index,
      accounts,
    }));
    this.txs.push(...made);
    return made;
  }
}

const rippled = (error: string) => new xrpl.RippledError(error, { error });
const body = (t: FakeTx, validated: boolean): XrplJson => ({
  hash: t.hash,
  ledger_index: t.ledger,
  tx_json: { Account: t.accounts[0], TransactionType: 'Payment' },
  meta: { TransactionIndex: t.index, TransactionResult: 'tesSUCCESS' },
  validated,
});

export class FakeLink implements Link {
  connected = true;
  subscribedTo: string[] | undefined;
  readonly calls: RpcRequest[] = [];
  /** Shuffles entries inside each `account_tx` page, as rippled's pages may be unordered. */
  scramble = false;
  /** This server's hash for a ledger index (default: ledgerHash(n, salt)). */
  salt = 'A';
  lag = 0;
  /** Replaces an `account_tx` result (hostile servers). */
  accountTx?: (req: RpcRequest) => XrplJson;
  /** Runs before every request (fault injection). */
  beforeRequest?: (req: RpcRequest) => void;
  private fn: (e: LinkEvent) => void = () => undefined;

  readonly name: string;
  readonly chain: FakeChain;

  constructor(name: string, chain: FakeChain) {
    this.name = name;
    this.chain = chain;
  }

  get validatedIndex(): number {
    return this.chain.head - this.lag;
  }

  isConnected = () => this.connected;
  /** The server is down: connecting fails. */
  refuse = false;
  async connect(): Promise<void> {
    if (this.refuse) throw new xrpl.ConnectionError('refused');
    if (!this.connected) {
      this.connected = true;
      this.fn({ type: 'up' });
    }
  }
  listen(fn: (e: LinkEvent) => void): void {
    this.fn = fn;
  }
  async close(): Promise<void> {
    this.connected = false;
  }
  async subscribe(accounts: readonly string[]): Promise<void> {
    this.calls.push({ command: 'subscribe', accounts: [...accounts], streams: ['ledger'] });
    if (!this.connected) throw new xrpl.ConnectionError('not connected');
    this.subscribedTo = [...accounts];
  }

  /** The socket drops: subscriptions vanish and requests fail. */
  drop(): void {
    this.connected = false;
    this.subscribedTo = undefined;
    this.fn({ type: 'down' });
  }
  /** What xrpl.js does by itself after a drop. */
  reconnect(): void {
    this.connected = true;
    this.fn({ type: 'up' });
  }
  /** Pushes the events of a newly validated ledger the way a subscribed server does. */
  push(txs: FakeTx[], validated = true): void {
    if (!this.connected || !this.subscribedTo) return;
    for (const t of txs)
      if (t.accounts.some((a) => this.subscribedTo?.includes(a)))
        this.fn({ type: 'transaction', message: body(t, validated) });
    if (validated) this.fn({ type: 'ledger', index: this.validatedIndex, hash: this.hashAt(this.validatedIndex) });
  }
  hashAt(n: number): string {
    return ledgerHash(n, this.salt);
  }

  async request(req: RpcRequest): Promise<{ result: unknown }> {
    this.calls.push(req);
    this.beforeRequest?.(req);
    if (!this.connected) throw new xrpl.ConnectionError('not connected');
    switch (req.command) {
      case 'server_info':
        return { result: { info: { complete_ledgers: `1-${this.validatedIndex}` } } };
      case 'ledger': {
        const n = req.ledger_index === 'validated' ? this.validatedIndex : (req.ledger_index as number);
        if (n > this.validatedIndex || n < 1) throw rippled('lgrNotFound');
        return { result: { ledger_index: n, ledger_hash: this.hashAt(n), validated: true } };
      }
      case 'account_tx':
        return { result: this.accountTx ? this.accountTx(req) : this.page(req) };
      default:
        throw new Error(`FakeLink: unexpected ${req.command}`);
    }
  }

  private page(req: RpcRequest): XrplJson {
    const account = req.account as string;
    const lo = (req.ledger_index_min as number) === -1 ? 1 : (req.ledger_index_min as number);
    const hi = req.ledger_index_max as number;
    const all = this.chain.txs.filter((t) => t.accounts.includes(account) && t.ledger >= lo && t.ledger <= hi);
    const from = typeof req.marker === 'number' ? req.marker : 0;
    const limit = req.limit as number;
    const slice = all.slice(from, from + limit);
    const out = this.scramble ? [...slice].reverse() : slice;
    return {
      account,
      ledger_index_min: lo,
      ledger_index_max: hi,
      transactions: out.map((t) => body(t, true)),
      validated: true,
      ...(from + limit < all.length ? { marker: from + limit } : {}),
    };
  }
}
