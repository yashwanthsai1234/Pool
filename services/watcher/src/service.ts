// Ledger watcher service (DESIGN 8.5 and 10.2): the 2.7 client wired to Postgres, the lock checker and alerts.
import type { Finding } from '@legx/contracts/records';
import type { Database } from '@legx/db';
import { ledgerHeader } from '@legx/xrpl/read';
import { type Alert, type Link, type LinkEvent, WatcherClient } from '@legx/xrpl/watcher/index';
import { type DealWatch, failing, lockCheckAt } from './locks.ts';
import { json, type Notify, recordObservation, type Step } from './observe.ts';

export const LEDGER_TOPIC = 'ledger.validated'; // OD-9
export const ALERT_TOPIC = 'alert';

/** An evidence event the watcher asks for. The sink signs and appends it (service 3.4). */
export type EvidenceInput =
  | {
      readonly kind: 'lock.verified';
      readonly dealId: string;
      readonly payload: { ledger: { ledger_index: number; ledger_hash: string }; findings: Finding[] };
    }
  | {
      readonly kind: 'ledger.disagreement'; // DQ-3.5-1: no such kind in contracts yet
      readonly dealId: string;
      readonly payload: { ledger_index: number; hashes: Readonly<Record<string, string>> };
    };

export interface WatcherServiceOptions {
  readonly db: Database;
  /** servers[0] is the primary; on repeated failure the service moves to the next one. */
  readonly servers: readonly Link[];
  readonly accounts: readonly string[];
  readonly deals: () => Promise<readonly DealWatch[]>;
  readonly evidence: (e: EvidenceInput) => Promise<void>;
  readonly notify: Notify;
  readonly pollMs?: number;
  readonly pageLimit?: number;
  /** Consecutive failed passes of the primary before failover. Default 3. */
  readonly failoverAfter?: number;
  /** Test seam: runs after each write of the observation transaction (see `recordObservation`). */
  readonly onStep?: (s: Step) => void | Promise<void>;
}

/** A link whose single listener can be replaced and that reports each event to the service. */
function tap(link: Link, seen: (l: Link, e: LinkEvent) => void): Link {
  let target: (e: LinkEvent) => void = () => undefined;
  let hooked = false;
  const wrapped: Link = {
    name: link.name,
    request: (r) => link.request(r),
    isConnected: () => link.isConnected(),
    connect: () => link.connect(),
    subscribe: (a) => link.subscribe(a),
    close: () => link.close(),
    listen(fn) {
      target = fn;
      if (hooked) return;
      hooked = true;
      link.listen((e) => {
        seen(wrapped, e);
        target(e);
      });
    },
  };
  return wrapped;
}

const msg = (e: unknown) => (e instanceof Error ? e.message : String(e));

export class WatcherService {
  readonly #o: WatcherServiceOptions;
  readonly #links: Link[];
  #client!: WatcherClient;
  #chain: Promise<void> = Promise.resolve();
  #failures = 0;
  #failingOver = false;
  #paused = false;
  readonly #lockAlerts = new Map<string, string>();
  #stopped = false;

  constructor(o: WatcherServiceOptions) {
    this.#o = o;
    this.#links = o.servers.map((s) => tap(s, (l, e) => this.#onLink(l, e)));
  }

  /** True while two servers disagree about a validated ledger: no decision may rely on the ledger. */
  decisionsPaused(): boolean {
    return this.#paused;
  }
  activeServer(): string {
    return (this.#links[0] as Link).name;
  }

  async start(): Promise<void> {
    for (let i = 1; ; i++) {
      this.#client = this.#newClient();
      try {
        return await this.#client.start();
      } catch (e) {
        if (i >= this.#links.length) throw e;
        this.#links.push(this.#links.shift() as Link); // the primary is down at start: try the next server
      }
    }
  }

  async stop(): Promise<void> {
    this.#stopped = true;
    await this.idle();
    await this.#client.stop();
  }

  /** Resolves when the client and every job of the service are quiet. */
  async idle(): Promise<void> {
    let chain: Promise<void>;
    do {
      chain = this.#chain;
      await this.#client.idle();
      await chain;
    } while (chain !== this.#chain);
  }

  #newClient(): WatcherClient {
    const db = this.#o.db;
    return new WatcherClient({
      servers: this.#links,
      accounts: this.#o.accounts,
      cursorStore: {
        get: (a) => db.repos.watcherCursors.get(a),
        set: (a, n) => db.repos.watcherCursors.advance(a, n),
      },
      handler: async (obs) => {
        if (await recordObservation(db, this.#o.accounts, obs, this.#o.onStep))
          await this.#o.notify('ledger.observation');
      },
      onAlert: (a) => this.#job(() => this.#onAlert(a)),
      pollMs: this.#o.pollMs,
      pageLimit: this.#o.pageLimit,
    });
  }

  #job(fn: () => Promise<void>): void {
    this.#chain = this.#chain.then(fn).catch(() => undefined);
  }

  async #push(topic: string, body: unknown): Promise<void> {
    await this.#o.db.transaction((r) => r.outbox.enqueue({ topic, payload: json(body) }).then(() => undefined));
    await this.#o.notify(topic);
  }

  #onLink(link: Link, e: LinkEvent): void {
    if (link !== this.#links[0] || this.#stopped) return;
    if (e.type !== 'ledger') return;
    this.#failures = 0;
    this.#job(() => this.#onLedger(e.index));
  }

  /** Every validated ledger the primary announces: push it (OD-9), re-check agreement, lock-check funded wallets. */
  async #onLedger(index: number): Promise<void> {
    const link = this.#links[0] as Link;
    try {
      const h = await ledgerHeader(link, index);
      await this.#push(LEDGER_TOPIC, { index: h.ledgerIndex, hash: h.ledgerHash, close_time: h.closeTime });
      if (this.#paused) await this.#recheckAgreement(index);
      for (const d of await this.#o.deals()) if (d.phase === 'funded') await this.#lock(link, d, index);
    } catch (e) {
      await this.#push(ALERT_TOPIC, { kind: 'error', where: 'service', message: msg(e) });
    }
  }

  async #lock(link: Link, d: DealWatch, index: number): Promise<void> {
    const { ledger, findings } = await lockCheckAt(link, d, index);
    const bad = failing(findings);
    const key = bad
      .map((f) => f.code)
      .sort()
      .join(',');
    if (this.#lockAlerts.get(d.dealId) === key) return; // a standing failure is raised once
    if (key === '') return void this.#lockAlerts.delete(d.dealId);
    this.#lockAlerts.set(d.dealId, key);
    const anchor = { ledger_index: ledger.ledgerIndex, ledger_hash: ledger.ledgerHash };
    await this.#push(ALERT_TOPIC, {
      kind: 'lock-check-failed',
      dealId: d.dealId,
      ledger: anchor,
      codes: bad.map((f) => f.code),
    });
    await this.#o.evidence({ kind: 'lock.verified', dealId: d.dealId, payload: { ledger: anchor, findings } });
  }

  async #onAlert(a: Alert): Promise<void> {
    await this.#push(ALERT_TOPIC, a);
    if (a.kind === 'disagreement') {
      this.#paused = true;
      for (const d of await this.#o.deals())
        await this.#o.evidence({
          kind: 'ledger.disagreement',
          dealId: d.dealId,
          payload: { ledger_index: a.ledgerIndex, hashes: a.hashes },
        });
    } else if (a.kind === 'error' && a.where === 'watcher' && !this.#stopped) {
      this.#failures += 1;
      if (this.#failures >= (this.#o.failoverAfter ?? 3) && this.#links.length > 1) this.#failover();
    }
  }

  /** The servers agree again when the newest ledger both have has the same hash. */
  async #recheckAgreement(index: number): Promise<void> {
    const hashes = new Set<string>();
    for (const l of this.#links) {
      try {
        hashes.add((await ledgerHeader(l, index)).ledgerHash);
      } catch {
        // a server that lacks the ledger is behind, not in disagreement
      }
    }
    if (hashes.size === 1) {
      this.#paused = false;
      await this.#push(ALERT_TOPIC, { kind: 'agreement-restored', ledgerIndex: index });
    }
  }

  /** Rotates servers[0] to the back and restarts the client on the next one; cursors live in the database. */
  #failover(): void {
    if (this.#failingOver) return;
    this.#failingOver = true;
    setImmediate(async () => {
      try {
        const old = this.#client;
        await old.stop();
        this.#links.push(this.#links.shift() as Link);
        this.#failures = 0;
        this.#client = this.#newClient();
        await this.#push(ALERT_TOPIC, { kind: 'failover', to: this.activeServer() });
        await this.#client
          .start()
          .catch((e: unknown) => this.#push(ALERT_TOPIC, { kind: 'error', where: 'failover', message: msg(e) }));
      } finally {
        this.#failingOver = false;
      }
    });
  }
}
