// Refresh bookkeeping (DESIGN 6.4 "Refresh and repair", P3.9-21). A refresh is hygiene, not revocation, and nobody can
// prove a deletion; what the log can show is that every remaining holder SIGNED a deletion statement. So an epoch's
// refresh stays `pending_deletions` and the old epoch stays unretired until all of those statements are in.
import { kyselyOf } from '@legx/coordinator/frost/store';
import type { Database } from '@legx/db';
import { type Kysely, sql } from 'kysely';

export type RefreshStatus = 'pending_deletions' | 'complete';
export interface RefreshRow {
  readonly dealId: string;
  readonly slot: string;
  readonly epoch: number;
  readonly status: RefreshStatus;
  readonly missing: readonly number[];
  readonly oldEpochRetired: boolean;
}

export class RefreshTable {
  readonly #k: Kysely<unknown>;
  constructor(db: Database) {
    this.#k = kyselyOf(db);
  }

  /** Writes the state for an epoch. A complete refresh is never moved back, and only a complete one retires the old epoch. */
  async set(dealId: string, slot: string, epoch: number, missing: readonly number[]): Promise<RefreshRow> {
    const status: RefreshStatus = missing.length === 0 ? 'complete' : 'pending_deletions';
    await sql`insert into recovery_agent_refresh (deal_id, slot, epoch, status, missing, old_epoch_retired)
      values (${dealId}, ${slot}, ${epoch}, ${status}, ${JSON.stringify(missing)}::jsonb, ${status === 'complete'})
      on conflict (deal_id, slot, epoch) do update set status = excluded.status, missing = excluded.missing,
        old_epoch_retired = excluded.old_epoch_retired where recovery_agent_refresh.status <> 'complete'`.execute(
      this.#k,
    );
    return (await this.get(dealId, slot, epoch)) as RefreshRow;
  }
  async get(dealId: string, slot: string, epoch: number): Promise<RefreshRow | undefined> {
    const r = await sql<{ status: RefreshStatus; missing: number[]; old_epoch_retired: boolean }>`
      select status, missing, old_epoch_retired from recovery_agent_refresh
      where deal_id = ${dealId} and slot = ${slot} and epoch = ${epoch}`.execute(this.#k);
    const x = r.rows[0];
    return x && { dealId, slot, epoch, status: x.status, missing: x.missing, oldEpochRetired: x.old_epoch_retired };
  }
}
