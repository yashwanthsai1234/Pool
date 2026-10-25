// The server holder's nonce ledger (DESIGN 6.4 signing rules, IMPLEMENTATION P3.9-20): a commitment is marked used in
// one atomic insert (`frost_nonce_use`, primary key (key_id, commitment_id)) before the signature share is released.
// If the process dies between the mark and the release, the commitment stays marked: a share is lost, never reused.
import type { NonceLedger } from '@legx/core/frostRules';
import type { Database } from '@legx/db';

export class PgNonceLedger implements NonceLedger {
  readonly #db: Database;
  readonly #ctx: { keyId: string; dealId: string; messageHash: string };
  constructor(db: Database, ctx: { keyId: string; dealId: string; messageHash: string }) {
    this.#db = db;
    this.#ctx = ctx;
  }
  async markUsed(commitmentId: string): Promise<boolean> {
    return await this.#db.repos.frostNonceUses.markUsed({
      key_id: this.#ctx.keyId,
      commitment_id: commitmentId,
      deal_id: this.#ctx.dealId,
      message_hash: this.#ctx.messageHash,
    });
  }
}
