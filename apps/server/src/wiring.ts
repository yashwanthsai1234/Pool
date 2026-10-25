// The glue between the services that no single service owns (build/ISSUES.md I-W-4, I-W-5, I-W-6, I-3.7-h):
//   - the deal wallets the watcher watches, read from the database (not a constant `[]`), with the lock-check
//     expectation of each sealed deal, and a sink that appends the watcher's findings as coordinator-signed events;
//   - the pump: integrates stored events into the transparency log and publishes a checkpoint when the log grew. The
//     `deal.state` and `signature.request` feed rows are written by the coordinator itself, in its transaction (I-W-5).
// Source: https://node-postgres.com/apis/pool  Source: DESIGN 8.2 (every event is a leaf of the log), 8.5 (watcher)
import type { ClockPort, LedgerPort, SignerPort } from '@legx/contracts/ports';
import { loadConfig } from '@legx/coordinator/deal';
import { derivePublicData } from '@legx/coordinator/publicData';
import { appendCoordinatorEvent } from '@legx/coordinator/statements';
import type { Database } from '@legx/db';
import type { createLogService } from '@legx/evidence/log';
import type { DealWatch } from '@legx/watcher';
import type pg from 'pg';

const FUNDED_STATES: ReadonlySet<string> = new Set(['FUNDED', 'PAID_OUT', 'REFUNDED', 'DISPUTED', 'EXPIRED', 'CLOSED']);

interface DealIndexRow {
  deal_id: string;
  shell_address: string;
  state: string;
}

/** Every deal that has a wallet, newest state included. */
export const listWalletDeals = async (pool: pg.Pool): Promise<DealIndexRow[]> =>
  (await pool.query<DealIndexRow>('select deal_id, shell_address, state from deal where shell_address is not null'))
    .rows;

/**
 * The watcher's view of the deals. `accounts` is a live array the watcher reads on every pass, so a wallet registered
 * by `deals.setWallet` is watched from the next pass on. A deal whose public data is not sealed yet is watched for its
 * transactions but not lock-checked (there is nothing sealed to check against).
 */
export function dealWatcher(db: Database, pool: pg.Pool, base: readonly string[]) {
  const accounts: string[] = [...base];
  const sealed = new Map<string, DealWatch['expected']>();
  const expectedOf = async (dealId: string): Promise<DealWatch['expected'] | undefined> => {
    const known = sealed.get(dealId);
    if (known) return known;
    const deal = await db.repos.deals.get(dealId);
    if (!deal?.escrow_owner || deal.escrow_sequence === null || !deal.condition_hex || !deal.releaser_account)
      return undefined;
    const pd = await derivePublicData(db.repos, deal, (await loadConfig(db.repos, dealId)).identity_policy);
    if (pd.status !== 'complete') return undefined;
    const expected: DealWatch['expected'] = {
      deal: pd.publicData,
      releaserAccount: deal.releaser_account,
      credentialSubjects: [deal.payout_a, deal.payout_b],
      escrow: {
        owner: deal.escrow_owner,
        sequence: deal.escrow_sequence,
        amountDrops: deal.amount_drops,
        conditionHex: deal.condition_hex,
        minCancelAfter: 0, // set per check by the lock checker from the validated close time
      },
    };
    sealed.set(dealId, expected);
    return expected;
  };
  return {
    accounts,
    /** Adds the wallets of deals created since the last call. Returns true when the list grew. */
    async refresh(): Promise<boolean> {
      let grew = false;
      for (const d of await listWalletDeals(pool))
        if (!accounts.includes(d.shell_address)) {
          accounts.push(d.shell_address);
          grew = true;
        }
      return grew;
    },
    async deals(): Promise<DealWatch[]> {
      const out: DealWatch[] = [];
      for (const d of await listWalletDeals(pool)) {
        const expected = await expectedOf(d.deal_id);
        if (expected)
          out.push({
            dealId: d.deal_id,
            wallet: d.shell_address,
            phase: FUNDED_STATES.has(d.state) ? 'funded' : 'pre-funding',
            expected,
          });
      }
      return out;
    },
  };
}

/** The watcher's evidence sink: a `lock.verified` or `ledger.disagreement` event signed by the coordinator's key. */
export function watcherEvidence(db: Database, signer: SignerPort, ledger: LedgerPort) {
  return async (e: { kind: string; dealId: string; payload: Record<string, unknown> }): Promise<void> => {
    const header = await ledger.validatedLedger();
    await db.transaction(async (repos) => {
      const deal = await repos.deals.get(e.dealId);
      if (!deal) return;
      await appendCoordinatorEvent(repos, signer, {
        dealId: e.dealId,
        kind: e.kind as never,
        data: e.payload,
        contractRoot: deal.contract_root,
        closeTime: header.closeTime,
        beforeAppend: async () => deal.state,
      });
    });
  };
}

export interface PumpDeps {
  readonly pool: pg.Pool;
  readonly db: Database;
  readonly service: Pick<ReturnType<typeof createLogService>, 'integrate' | 'checkpoint'>;
  readonly clock?: ClockPort;
  /** Called after the log grew (the composition asks the anchor job to run). */
  readonly onGrown?: () => Promise<void>;
  readonly everyMs?: number;
}

/** One pass of the pump: log integration and a checkpoint when the log grew. */
export async function pumpOnce(d: PumpDeps): Promise<{ integrated: number }> {
  // Events the coordinator stored since the last pass, oldest first: each is a leaf of the log (DESIGN 8.2).
  const pending = await d.pool.query<{ deal_id: string; seq: string }>(
    `select e.deal_id, e.seq from evidence_event e left join evidence_log_entry l using (event_id)
      where l.event_id is null order by e.received_at, e.deal_id, e.seq limit 500`,
  );
  let integrated = 0;
  for (const r of pending.rows) {
    const row = await d.db.repos.evidenceEvents.getBySeq(r.deal_id, Number(r.seq));
    if (!row) continue;
    await d.service.integrate(row);
    integrated++;
  }
  if (integrated > 0) {
    await d.service.checkpoint();
    await d.onGrown?.();
  }
  return { integrated };
}

/** Runs `pumpOnce` every `everyMs` (default 500) until stopped. A failed pass is retried on the next tick. */
export function startPump(d: PumpDeps, onError: (e: unknown) => void = () => undefined): () => Promise<void> {
  let stopped = false;
  let running: Promise<unknown> = Promise.resolve();
  const timer = setInterval(() => {
    running = running.then(() => (stopped ? undefined : pumpOnce(d).catch(onError)));
  }, d.everyMs ?? 500);
  return async () => {
    stopped = true;
    clearInterval(timer);
    await running;
  };
}
