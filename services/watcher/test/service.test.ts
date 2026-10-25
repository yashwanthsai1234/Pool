// Task 3.5 at the service level on PGlite (Postgres 18.6): P3.5-01 (all or none), T-I-08, P3.5-02, P3.5-03, failover.
import { openPglite } from '@legx/db/pglite';
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.setConfig({ testTimeout: 60_000 });

import {
  type DealWatch,
  NOTIFY_CHANNEL,
  pgNotify,
  recordObservation,
  type Step,
  WatcherService,
} from '../src/index.ts';
import { ALICE, FakeChain, funded, fundedWallet, LedgerLink, type Obj, WALLET } from './support.ts';

const ACCOUNTS = [WALLET, ALICE];
const until = async (what: string, ok: () => boolean | Promise<boolean>, ms = 4000) => {
  const end = Date.now() + ms;
  while (!(await ok())) {
    if (Date.now() > end) throw new Error(`timed out: ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
};

async function rig(opts: { deals?: DealWatch[]; servers?: LedgerLink[]; failoverAfter?: number } = {}) {
  const db = openPglite();
  await db.migrate();
  const chain = new FakeChain();
  const servers = opts.servers ?? [new LedgerLink('rippled', chain)];
  const evidence: unknown[] = [];
  const svc = new WatcherService({
    db,
    servers,
    accounts: ACCOUNTS,
    deals: async () => opts.deals ?? [funded()],
    evidence: async (e) => void evidence.push(e),
    notify: async () => undefined,
    pollMs: 20,
    failoverAfter: opts.failoverAfter,
  });
  const topics = async (t: string) => (await db.repos.outbox.claim(10_000)).filter((r) => r.topic === t);
  const json = (b: Uint8Array) => JSON.parse(new TextDecoder().decode(b));
  return { db, chain, servers, evidence, svc, topics, json };
}
let open: WatcherService | undefined;
afterEach(async () => {
  await open?.stop();
  open = undefined;
});

const obs = (n: number, source: 'stream' | 'backfill' = 'backfill') => ({
  hash: n.toString(16).padStart(64, '0').toUpperCase(),
  ledgerIndex: 10 + n,
  transactionIndex: 0,
  tx: { Account: ALICE, TransactionType: 'Payment' },
  meta: { TransactionResult: 'tesSUCCESS', TransactionIndex: 0 },
  source,
  account: WALLET,
});

describe('P3.5-01 observation, outbox row and cursor in one transaction', () => {
  it('writes all three, and a replay writes nothing more', async () => {
    const { db, topics } = await rig();
    expect(await recordObservation(db, ACCOUNTS, obs(1))).toBe(true);
    expect(await recordObservation(db, ACCOUNTS, obs(1))).toBe(false);
    expect(await db.repos.ledgerObservations.listForAccount(WALLET, 0)).toHaveLength(1);
    expect(await topics('ledger.observation')).toHaveLength(1);
    expect(await db.repos.watcherCursors.get(WALLET)).toBe(10); // ledger 11 is not complete: cursor = 11 - 1
  });

  it('a stream observation does not move the cursor', async () => {
    const { db } = await rig();
    const o = {
      ...obs(2, 'stream'),
      account: undefined,
      tx: { Account: 'rGenesis', Destination: WALLET, TransactionType: 'Payment' },
    };
    await recordObservation(db, ACCOUNTS, o);
    expect(await db.repos.watcherCursors.get(WALLET)).toBeUndefined();
    expect(await db.repos.ledgerObservations.listForAccount(WALLET, 0)).toHaveLength(1); // filed under the watched party
  });

  it.each(['observation', 'outbox', 'cursor'] as Step[])(
    'a crash after the %s write leaves none of the three',
    async (at) => {
      const { db, topics } = await rig();
      const crash = (s: Step) => {
        if (s === at) throw new Error('killed');
      };
      await expect(recordObservation(db, ACCOUNTS, obs(3), crash)).rejects.toThrow('killed');
      expect(await db.repos.ledgerObservations.listForAccount(WALLET, 0)).toHaveLength(0);
      expect(await topics('ledger.observation')).toHaveLength(0);
      expect(await db.repos.watcherCursors.get(WALLET)).toBeUndefined();
      // the retry after the "restart" writes all three
      expect(await recordObservation(db, ACCOUNTS, obs(3))).toBe(true);
      expect(await topics('ledger.observation')).toHaveLength(1);
    },
  );

  it('the same transaction seen from the sender (stream) and the receiver (backfill) queues one outbox row', async () => {
    const { db, topics } = await rig();
    await recordObservation(db, ACCOUNTS, { ...obs(4, 'stream'), account: undefined });
    await recordObservation(db, ACCOUNTS, obs(4));
    expect(await topics('ledger.observation')).toHaveLength(1);
  });

  it('pg_notify runs on the outbox channel', async () => {
    const db = openPglite();
    await db.migrate();
    await expect(pgNotify(db)('ledger.observation')).resolves.toBeUndefined();
    expect(NOTIFY_CHANNEL).toBe('legx_outbox');
  });
});

describe('T-I-08 at the service level', () => {
  it('50 ledgers missed while the connection was down: every transaction once', async () => {
    const { svc, chain, servers, db, topics } = await rig();
    open = svc;
    const link = servers[0] as LedgerLink;
    await svc.start();
    link.push(chain.close([[WALLET]]));
    await svc.idle();
    link.drop();
    const expected = new Set<string>();
    for (let i = 0; i < 50; i++)
      for (const t of chain.close(i % 3 === 0 ? [[WALLET, ALICE], [ALICE]] : [[WALLET]])) expected.add(t.hash);
    link.reconnect();
    await until('backfill', async () => (await db.repos.ledgerObservations.listForAccount(WALLET, 0)).length >= 50);
    await svc.idle();
    const rows = [
      ...(await db.repos.ledgerObservations.listForAccount(WALLET, 0)),
      ...(await db.repos.ledgerObservations.listForAccount(ALICE, 0)),
    ];
    const hashes = rows.map((r) => r.tx_hash.toUpperCase());
    expect(new Set(hashes).size).toBe(hashes.length);
    for (const h of expected) expect(hashes).toContain(h);
    expect((await topics('ledger.observation')).length).toBe(hashes.length);
  });
});

describe('OD-9 ledger.validated', () => {
  it('every validated ledger is pushed with index, hash and close_time', async () => {
    const { svc, chain, servers, topics, json } = await rig({ deals: [] });
    open = svc;
    await svc.start();
    for (let i = 0; i < 3; i++) (servers[0] as LedgerLink).push(chain.close([[WALLET]]));
    await svc.idle();
    const rows = (await topics('ledger.validated')).map((r) => json(r.payload));
    expect(rows.map((r) => r.index)).toEqual([2, 3, 4]);
    expect(rows[0]).toEqual({ index: 2, hash: (servers[0] as LedgerLink).hashAt(2), close_time: 1002 });
  });
});

describe('P3.5-02 lock checker after funding', () => {
  const plant = (mut: (w: ReturnType<typeof fundedWallet>) => void, from: number) => (n: number) => {
    const w = fundedWallet();
    if (n >= from) mut(w);
    return w;
  };
  const alerts = async (r: Awaited<ReturnType<typeof rig>>) =>
    (await r.topics('alert')).map((x) => r.json(x.payload)).filter((a) => a.kind === 'lock-check-failed');

  it('a funded wallet without its escrow, with the exit ticket, raises nothing (DQ-1, exit ticket allowed)', async () => {
    const r = await rig({ deals: [funded({ exitTicket: 77 })] });
    open = r.svc;
    const link = r.servers[0] as LedgerLink;
    link.wallet = () => {
      const w = fundedWallet();
      w.acct.OwnerCount = 3;
      w.objs.push({ LedgerEntryType: 'Ticket', Account: WALLET, TicketSequence: 77, index: 'T1' });
      return w;
    };
    await r.svc.start();
    link.push(r.chain.close([[WALLET]]));
    await r.svc.idle();
    expect(await alerts(r)).toEqual([]);
    expect(r.evidence).toEqual([]);
    expect(link.calls.some((c) => c.command === 'account_objects')).toBe(true);
  });

  it('a planted change raises an alert and an evidence event, once, at the ledger it appeared', async () => {
    const r = await rig();
    open = r.svc;
    const link = r.servers[0] as LedgerLink;
    link.wallet = plant((w) => (w.acct.RegularKey = addr()), 4);
    await r.svc.start();
    for (let i = 0; i < 5; i++) link.push(r.chain.close([[WALLET]]));
    await r.svc.idle();
    const a = await alerts(r);
    expect(a).toHaveLength(1);
    expect(a[0].codes).toEqual(['NO_REGULARKEY']);
    expect(a[0].ledger.ledger_index).toBe(4);
    expect(r.evidence).toHaveLength(1);
    const e = r.evidence[0] as { kind: string; dealId: string; payload: { findings: { code: string; ok: boolean }[] } };
    expect(e.kind).toBe('lock.verified');
    expect(e.payload.findings.find((f) => f.code === 'NO_REGULARKEY')?.ok).toBe(false);
  });

  it('an unrecorded ticket, an extra object and a changed signer list are each caught', async () => {
    const cases: [string, (w: ReturnType<typeof fundedWallet>) => void, string][] = [
      [
        'ticket',
        (w) => {
          w.acct.OwnerCount = 3;
          w.objs.push({ LedgerEntryType: 'Ticket', Account: WALLET, TicketSequence: 5, index: 'T' });
        },
        'TICKET_ALLOWED',
      ],
      [
        'offer',
        (w) => {
          w.acct.OwnerCount = 3;
          w.objs.push({ LedgerEntryType: 'Offer', Account: WALLET, index: 'O' });
        },
        'UNEXPECTED_OWNED_OFFER',
      ],
      [
        'quorum',
        (w) => {
          (w.objs[0] as Obj).SignerQuorum = 3;
        },
        'QUORUM_MATCH',
      ],
    ];
    for (const [, mut, code] of cases) {
      const r = await rig({ deals: [funded({ exitTicket: 77 })] });
      const link = r.servers[0] as LedgerLink;
      link.wallet = plant(mut, 2);
      await r.svc.start();
      link.push(r.chain.close([[WALLET]]));
      await r.svc.idle();
      expect((await alerts(r)).flatMap((a) => a.codes)).toContain(code);
      await r.svc.stop();
    }
  });

  it('a deal before funding is not checked', async () => {
    const r = await rig({ deals: [funded({ phase: 'pre-funding' })] });
    open = r.svc;
    const link = r.servers[0] as LedgerLink;
    link.wallet = plant((w) => (w.acct.RegularKey = addr()), 1);
    await r.svc.start();
    link.push(r.chain.close([[WALLET]]));
    await r.svc.idle();
    expect(await alerts(r)).toEqual([]);
  });
});

const addr = () => 'rPlantedRegularKey';

describe('P3.5-03 two servers disagree', () => {
  it('alerts, raises an evidence event per deal, pauses decisions, and resumes when they agree', async () => {
    const chain = new FakeChain();
    const a = new LedgerLink('rippled', chain);
    const b = new LedgerLink('clio', chain);
    b.salt = 'F';
    const r = await rig({ servers: [a, b] });
    open = r.svc;
    await r.svc.start();
    a.push(chain.close([[WALLET]]));
    await r.svc.idle();
    expect(r.svc.decisionsPaused()).toBe(true);
    const alerts = (await r.topics('alert')).map((x) => r.json(x.payload));
    expect(alerts.find((x) => x.kind === 'disagreement')?.hashes).toMatchObject({
      rippled: a.hashAt(1),
      clio: b.hashAt(1),
    });
    expect(r.evidence.map((e) => (e as { kind: string }).kind)).toContain('ledger.disagreement');
    b.salt = 'A';
    a.push(chain.close([[WALLET]]));
    await r.svc.idle();
    expect(r.svc.decisionsPaused()).toBe(false);
  });

  it('two honest servers never pause', async () => {
    const chain = new FakeChain();
    const r = await rig({ servers: [new LedgerLink('a', chain), new LedgerLink('b', chain)] });
    open = r.svc;
    await r.svc.start();
    for (let i = 0; i < 3; i++) (r.servers[0] as LedgerLink).push(chain.close([[WALLET]]));
    await r.svc.idle();
    expect(r.svc.decisionsPaused()).toBe(false);
  });
});

describe('failover from servers[0] to servers[1]', () => {
  it('a primary that is down at start hands over to the second server', async () => {
    const chain = new FakeChain();
    const a = new LedgerLink('rippled', chain);
    const b = new LedgerLink('clio', chain);
    chain.close([[WALLET]]);
    a.connected = false;
    a.refuse = true;
    const r = await rig({ servers: [a, b] });
    open = r.svc;
    await r.svc.start();
    expect(r.svc.activeServer()).toBe('clio');
    expect((await r.db.repos.ledgerObservations.listForAccount(WALLET, 0)).length).toBe(1);
  });

  it('a primary that dies later: after repeated failures the second server continues from the stored cursor', async () => {
    const chain = new FakeChain();
    const a = new LedgerLink('rippled', chain);
    const b = new LedgerLink('clio', chain);
    const r = await rig({ servers: [a, b], failoverAfter: 2 });
    open = r.svc;
    await r.svc.start();
    a.push(chain.close([[WALLET]]));
    await r.svc.idle();
    a.refuse = true;
    a.drop();
    const missed = chain.close([[WALLET]]);
    await until('failover', () => r.svc.activeServer() === 'clio');
    await until('the missed transaction', async () =>
      (await r.db.repos.ledgerObservations.listForAccount(WALLET, 0)).some(
        (x) => x.tx_hash.toUpperCase() === missed[0]?.hash,
      ),
    );
    const rows = await r.db.repos.ledgerObservations.listForAccount(WALLET, 0);
    expect(rows).toHaveLength(2);
    expect((await r.topics('alert')).map((x) => r.json(x.payload).kind)).toContain('failover');
    const link = r.servers[1] as LedgerLink;
    link.push(chain.close([[WALLET]]));
    await r.svc.idle();
    await until('third', async () => (await r.db.repos.ledgerObservations.listForAccount(WALLET, 0)).length === 3);
  });
});
