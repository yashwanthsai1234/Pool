// The audit log (P3.10-07): one append-only, hash-chained row for every decision, signed or refused. Each row carries
// the message hash, the deal, the seal and the reason, and its hash covers the previous row's hash, so a deleted or
// edited row breaks the chain. The row is also handed to the evidence port (the coordinator's chained evidence log).
// A database trigger refuses UPDATE and DELETE.
// Source: https://www.postgresql.org/docs/current/plpgsql-trigger.html
import { kyselyOf } from '@legx/coordinator/frost/store';
import { bytesToHex, tupleHash, utf8ToBytes } from '@legx/core/dealcore';
import type { Database } from '@legx/db';
import { type Kysely, sql } from 'kysely';

export type AuditDecision = 'share_released' | 'refused';

export interface AuditEntry {
  readonly dealId: string;
  readonly slot: string;
  readonly decision: AuditDecision;
  /** `signed`, or the refusal code. */
  readonly reason: string;
  /** SHA-256 of the exact message, hex. Empty when the request was refused before a message was known. */
  readonly messageHash: string;
  /** The sealed deal's seal, hex. Empty before the seal exists. */
  readonly seal: string;
  readonly detail?: Record<string, unknown>;
}

/** Where entries are forwarded (the coordinator's evidence log). Kinds follow DESIGN 8.1. */
export interface AuditSink {
  append(dealId: string, kind: 'frost.share.released' | 'frost.refused', data: Record<string, unknown>): Promise<void>;
}

const ZERO = '0'.repeat(64);

const chainHash = (
  prev: string,
  x: Pick<AuditEntry, 'dealId' | 'slot' | 'decision' | 'reason' | 'messageHash' | 'seal'>,
  detail: string,
) =>
  bytesToHex(
    tupleHash(
      'legx/firm-cosigner/audit/v1',
      [prev, x.dealId, x.slot, x.decision, x.reason, x.messageHash, x.seal, detail].map(utf8ToBytes),
    ),
  );

export class AuditLog {
  readonly #k: Kysely<unknown>;
  readonly #sink: AuditSink | undefined;
  constructor(db: Database, sink?: AuditSink) {
    this.#k = kyselyOf(db);
    this.#sink = sink;
  }

  async append(e: AuditEntry): Promise<string> {
    const detail = JSON.stringify(e.detail ?? {});
    const hash = await this.#k.transaction().execute(async (trx) => {
      // one writer at a time extends the chain
      await sql`select pg_advisory_xact_lock(7310)`.execute(trx);
      const last = await sql<{
        entry_hash: string;
      }>`select entry_hash from firm_cosigner_audit order by seq desc limit 1`.execute(trx);
      const prev = last.rows[0]?.entry_hash ?? ZERO;
      const h = chainHash(prev, e, detail);
      await sql`insert into firm_cosigner_audit (deal_id, slot, decision, reason, message_hash, seal, detail, prev_hash, entry_hash)
        values (${e.dealId}, ${e.slot}, ${e.decision}, ${e.reason}, ${e.messageHash}, ${e.seal}, ${detail}, ${prev}, ${h})`.execute(
        trx,
      );
      return h;
    });
    await this.#sink?.append(e.dealId, e.decision === 'refused' ? 'frost.refused' : 'frost.share.released', {
      slot: e.slot,
      reason: e.reason,
      message_hash: e.messageHash,
      seal: e.seal,
      audit_hash: hash,
      ...e.detail,
    });
    return hash;
  }

  /** The whole chain, oldest first. */
  async entries(
    dealId?: string,
  ): Promise<(AuditEntry & { seq: number; rawDetail: string; prevHash: string; entryHash: string })[]> {
    const r = await sql<Record<string, unknown>>`select * from firm_cosigner_audit order by seq`.execute(this.#k);
    return r.rows
      .filter((x) => !dealId || x.deal_id === dealId)
      .map((x) => ({
        seq: Number(x.seq),
        dealId: x.deal_id as string,
        slot: x.slot as string,
        decision: x.decision as AuditDecision,
        reason: x.reason as string,
        messageHash: x.message_hash as string,
        seal: x.seal as string,
        detail: JSON.parse(x.detail as string) as Record<string, unknown>,
        rawDetail: x.detail as string,
        prevHash: x.prev_hash as string,
        entryHash: x.entry_hash as string,
      }));
  }

  /** Recomputes the chain; false if any row was changed, removed or reordered. */
  async verifyChain(): Promise<boolean> {
    let prev = ZERO;
    for (const x of await this.entries()) {
      const h = chainHash(prev, x, x.rawDetail);
      if (x.prevHash !== prev || x.entryHash !== h) return false;
      prev = h;
    }
    return true;
  }
}
