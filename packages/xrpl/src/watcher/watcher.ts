// Ledger watcher client (DESIGN 8.5, IMPLEMENTATION 2.7). One primary server (servers[0]) feeds the handler; the other
// servers are only compared against it. The handler sees each transaction hash once per process, and in
// (ledger_index, TransactionIndex) order within a backfill. The handler must itself be idempotent on `hash`: a crash
// between handling and moving the cursor replays the ledger.
import type { XrplJson } from '@legx/contracts/ports';
import { call, rippledCode, uint } from '../read.ts';
import { coversRange } from '../submit.ts';
import type { Link, LinkEvent } from './link.ts';

export interface Observation {
  readonly hash: string;
  readonly ledgerIndex: number;
  readonly transactionIndex: number;
  readonly tx: XrplJson;
  readonly meta: XrplJson;
  readonly source: 'stream' | 'backfill';
  /** The watched account whose `account_tx` returned it (backfill only). */
  readonly account?: string;
}

/** The last fully processed validated ledger per account. 0 (or undefined) means nothing processed yet. */
export interface CursorStore {
  get(account: string): Promise<number | undefined>;
  set(account: string, ledgerIndex: number): Promise<void>;
}

export type Alert =
  | { readonly kind: 'disagreement'; readonly ledgerIndex: number; readonly hashes: Readonly<Record<string, string>> }
  | { readonly kind: 'history-gap'; readonly account: string; readonly fromLedger: number }
  | { readonly kind: 'error'; readonly where: string; readonly message: string };

export interface WatcherOptions {
  /** servers[0] is the primary; every other server is compared against it. */
  readonly servers: readonly Link[];
  readonly accounts: readonly string[];
  readonly cursorStore: CursorStore;
  readonly handler: (o: Observation) => Promise<void>;
  readonly onAlert?: (a: Alert) => void;
  /** Interval of the safety-net tick (reconnect, resubscribe, catch-up). Default 5000. */
  readonly pollMs?: number;
  /** `account_tx` page size. Default 200. */
  readonly pageLimit?: number;
}

interface Entry {
  hash: string;
  ledgerIndex: number;
  transactionIndex: number;
  tx: XrplJson;
  meta: XrplJson;
}

const HASH = /^[0-9A-F]{64}$/i;
const obj = (x: unknown, what: string): XrplJson => {
  if (typeof x !== 'object' || x === null || Array.isArray(x)) throw new Error(`${what}: expected an object`);
  return x as XrplJson;
};

/** A transaction as `account_tx` (API v2) and the `transaction` stream (API v2) both carry it. */
function parseEntry(m: XrplJson): Entry {
  const hash = m.hash;
  if (typeof hash !== 'string' || !HASH.test(hash)) throw new Error('transaction: bad hash');
  const meta = obj(m.meta, 'transaction.meta');
  return {
    hash: hash.toUpperCase(),
    ledgerIndex: uint(m.ledger_index, 'transaction.ledger_index'),
    transactionIndex: uint(meta.TransactionIndex, 'transaction.meta.TransactionIndex'),
    tx: obj(m.tx_json, 'transaction.tx_json'),
    meta,
  };
}

const byPosition = (a: Entry, b: Entry) => a.ledgerIndex - b.ledgerIndex || a.transactionIndex - b.transactionIndex;
const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

export class WatcherClient {
  readonly #o: WatcherOptions;
  readonly #primary: Link;
  readonly #cursors = new Map<string, number>();
  /** hash -> ledger index of every transaction handled and not yet below all cursors. */
  readonly #seen = new Map<string, number>();
  readonly #raised = new Set<string>();
  #queue: Promise<void> = Promise.resolve();
  #timer: NodeJS.Timeout | undefined;
  #subscribed = false;
  #stopped = false;

  constructor(o: WatcherOptions) {
    if (o.servers.length === 0) throw new Error('WatcherClient: at least one server');
    if (o.accounts.length === 0) throw new Error('WatcherClient: at least one account');
    this.#o = o;
    this.#primary = o.servers[0] as Link;
  }

  /** Connects, subscribes, backfills; rejects if that first pass fails. Afterwards it keeps itself in sync. */
  async start(): Promise<void> {
    this.#primary.listen((e) => this.#onEvent(e));
    for (const a of this.#o.accounts) this.#cursors.set(a, (await this.#o.cursorStore.get(a)) ?? 0);
    await this.#run(() => this.#tick(), true);
    this.#timer = setInterval(() => void this.#run(() => this.#tick()), this.#o.pollMs ?? 5000);
  }

  /** Resolves when every queued job has finished. Tests use it as a barrier. */
  idle(): Promise<void> {
    return this.#queue;
  }

  /** Catch up to the validated ledger now (queued behind running jobs). */
  sync(): Promise<void> {
    return this.#run(() => this.#sync());
  }

  async stop(): Promise<void> {
    this.#stopped = true;
    clearInterval(this.#timer);
    await this.#queue;
    await Promise.all(this.#o.servers.map((s) => s.close()));
  }

  #alert(a: Alert): void {
    if (a.kind !== 'error') {
      // A standing disagreement or gap is reported once, not at every tick.
      const key = JSON.stringify(a);
      if (this.#raised.has(key)) return;
      this.#raised.add(key);
    }
    this.#o.onAlert?.(a);
  }

  /** One job at a time, in arrival order. A failing job becomes an alert (or the caller's rejection when `throws`). */
  #run(job: () => Promise<void>, throws = false): Promise<void> {
    const next = this.#queue.then(async () => {
      if (this.#stopped) return;
      try {
        await job();
      } catch (e) {
        if (throws) throw e;
        this.#alert({ kind: 'error', where: 'watcher', message: message(e) });
      }
    });
    this.#queue = next.catch(() => undefined);
    return next;
  }

  #onEvent(e: LinkEvent): void {
    switch (e.type) {
      case 'down':
        this.#subscribed = false;
        return;
      case 'up':
        this.#subscribed = false;
        void this.#run(() => this.#tick());
        return;
      case 'ledger':
        if (this.#subscribed) void this.#run(() => this.#sync());
        return;
      case 'transaction':
        // Only validated transactions count; `validated: false` is a proposed or open-ledger copy.
        if (e.message.validated === true) void this.#run(() => this.#live(e.message));
        return;
    }
  }

  async #tick(): Promise<void> {
    if (!this.#primary.isConnected()) await this.#primary.connect();
    if (!this.#subscribed) {
      // Subscribe first, then backfill: a transaction validated in between is in the backfill, the stream, or both.
      await this.#primary.subscribe(this.#o.accounts);
      this.#subscribed = true;
    }
    await this.#sync();
  }

  #minCursor(): number {
    return Math.min(...this.#cursors.values());
  }

  async #live(m: XrplJson): Promise<void> {
    const e = parseEntry(m);
    if (e.ledgerIndex <= this.#minCursor() || this.#seen.has(e.hash)) return;
    await this.#o.handler({ ...e, source: 'stream' });
    this.#seen.set(e.hash, e.ledgerIndex);
  }

  async #emit(e: Entry, account: string): Promise<void> {
    if (this.#seen.has(e.hash)) return;
    await this.#o.handler({ ...e, source: 'backfill', account });
    this.#seen.set(e.hash, e.ledgerIndex);
  }

  async #sync(): Promise<void> {
    const head = await this.#validated(this.#primary);
    const complete = await this.#complete();
    for (const account of this.#o.accounts) await this.#backfill(account, head.index, complete);
    const low = this.#minCursor();
    for (const [h, l] of this.#seen) if (l <= low) this.#seen.delete(h);
    await this.#compare(head);
  }

  async #complete(): Promise<string> {
    const info = obj((await call(this.#primary, { command: 'server_info' })).info, 'server_info.info');
    if (typeof info.complete_ledgers !== 'string') throw new Error('server_info: no complete_ledgers');
    return info.complete_ledgers;
  }

  async #validated(link: Link): Promise<{ index: number; hash: string }> {
    const r = await call(link, { command: 'ledger', ledger_index: 'validated' });
    return this.#header(r, 'ledger');
  }

  #header(r: XrplJson, what: string): { index: number; hash: string } {
    const hash = r.ledger_hash;
    if (r.validated !== true || typeof hash !== 'string' || !HASH.test(hash))
      throw new Error(`${what}: not a validated header`);
    return { index: uint(r.ledger_index, `${what}.ledger_index`), hash: hash.toUpperCase() };
  }

  /** Forward `account_tx` from the cursor to `head`, following `marker`; ledgers are handled whole and in order. */
  // Source: https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_tx
  async #backfill(account: string, head: number, complete: string): Promise<void> {
    const cursor = this.#cursors.get(account) ?? 0;
    if (cursor >= head) return;
    if (cursor > 0 && !coversRange(complete, cursor + 1, head)) {
      this.#alert({ kind: 'history-gap', account, fromLedger: cursor + 1 });
      throw new Error(`backfill ${account}: the server's history does not cover ${cursor + 1}..${head}`);
    }
    const lo = cursor === 0 ? -1 : cursor + 1; // -1: the earliest ledger the server has
    let pool: Entry[] = [];
    let marker: unknown;
    const markers = new Set<string>();
    do {
      const r = await call(this.#primary, {
        command: 'account_tx',
        account,
        ledger_index_min: lo,
        ledger_index_max: head,
        forward: true,
        limit: this.#o.pageLimit ?? 200,
        ...(marker === undefined ? {} : { marker }),
      });
      if (r.account !== account || r.validated !== true)
        throw new Error('account_tx: not a validated answer for the account');
      if (!Array.isArray(r.transactions)) throw new Error('account_tx: no transactions array');
      for (const t of r.transactions) {
        const x = obj(t, 'account_tx entry');
        if (x.validated !== true) throw new Error('account_tx: unvalidated entry');
        const e = parseEntry(x);
        if (e.ledgerIndex > head || (lo > 0 && e.ledgerIndex < lo))
          throw new Error('account_tx: entry outside the range');
        pool.push(e);
      }
      marker = r.marker;
      if (marker !== undefined) {
        const key = JSON.stringify(marker);
        if (markers.has(key)) throw new Error('account_tx: repeated marker');
        markers.add(key);
        // A ledger may continue on the next page: hand over only ledgers strictly below the newest one seen.
        const newest = Math.max(...pool.map((e) => e.ledgerIndex));
        pool.sort(byPosition);
        const done = pool.filter((e) => e.ledgerIndex < newest);
        pool = pool.filter((e) => e.ledgerIndex === newest);
        for (const e of done) await this.#emit(e, account);
        if (done.length > 0) await this.#move(account, newest - 1);
      }
    } while (marker !== undefined);
    pool.sort(byPosition);
    for (const e of pool) await this.#emit(e, account);
    await this.#move(account, head);
  }

  async #move(account: string, ledgerIndex: number): Promise<void> {
    if (ledgerIndex <= (this.#cursors.get(account) ?? 0)) return;
    await this.#o.cursorStore.set(account, ledgerIndex);
    this.#cursors.set(account, ledgerIndex);
  }

  /**
   * A ledger hash covers its parent hash, so two servers that agree on one validated ledger agree on all before it.
   * Compare at the newest index both have; a server that is merely behind or lacks the ledger is not a disagreement.
   */
  async #compare(head: { index: number; hash: string }): Promise<void> {
    for (const other of this.#o.servers.slice(1)) {
      try {
        if (!other.isConnected()) await other.connect();
        const theirs = await this.#validated(other);
        const index = Math.min(head.index, theirs.index);
        const mine = index === head.index ? head : await this.#at(this.#primary, index);
        const them = index === theirs.index ? theirs : await this.#at(other, index);
        if (mine && them && mine.hash !== them.hash)
          this.#alert({
            kind: 'disagreement',
            ledgerIndex: index,
            hashes: { [this.#primary.name]: mine.hash, [other.name]: them.hash },
          });
      } catch (e) {
        this.#alert({ kind: 'error', where: other.name, message: message(e) });
      }
    }
  }

  async #at(link: Link, index: number): Promise<{ index: number; hash: string } | undefined> {
    try {
      return this.#header(await call(link, { command: 'ledger', ledger_index: index }), 'ledger');
    } catch (e) {
      if (rippledCode(e) === 'lgrNotFound') return undefined;
      throw e;
    }
  }
}
