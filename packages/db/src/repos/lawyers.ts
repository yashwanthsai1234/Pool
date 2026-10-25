// lawyer, bar_verification, attorney_credential, bar_deal_link (DESIGN 9, 6.16). Bar records live outside any deal.
import type { Kysely } from 'kysely';
import { bin, bytes, hex } from '../bytes.ts';
import type { DB } from '../schema.ts';

export interface LawyerRow {
  ops_account: string;
  jurisdiction: string;
  bar_number_sha256: string; // never the plain bar number
}

export class LawyersRepo {
  readonly #db: Kysely<DB>;
  constructor(db: Kysely<DB>) {
    this.#db = db;
  }
  async insert(l: LawyerRow): Promise<void> {
    await this.#db
      .insertInto('lawyer')
      .values({ ...l, bar_number_sha256: bin(l.bar_number_sha256) })
      .onConflict((oc) => oc.column('ops_account').doNothing())
      .execute();
  }
  async get(opsAccount: string): Promise<LawyerRow | undefined> {
    const r = await this.#db.selectFrom('lawyer').selectAll().where('ops_account', '=', opsAccount).executeTakeFirst();
    return r && { ...r, bar_number_sha256: hex(r.bar_number_sha256) };
  }
}

export interface BarVerificationRow {
  envelope_sha256: string;
  ops_account: string;
  envelope: Uint8Array;
  status: 'active' | 'not_active';
  checked_at_ledger: number;
  checked_at_ledger_hash: string;
}

export class BarVerificationsRepo {
  readonly #db: Kysely<DB>;
  constructor(db: Kysely<DB>) {
    this.#db = db;
  }
  /** Idempotent by envelope hash: the same envelope twice returns the first row. */
  async insert(v: BarVerificationRow): Promise<BarVerificationRow> {
    await this.#db
      .insertInto('bar_verification')
      .values({ ...v, envelope_sha256: bin(v.envelope_sha256), envelope: v.envelope })
      .onConflict((oc) => oc.column('envelope_sha256').doNothing())
      .execute();
    return (await this.get(v.envelope_sha256)) as BarVerificationRow;
  }
  async get(envelopeSha256: string): Promise<BarVerificationRow | undefined> {
    const r = await this.#db
      .selectFrom('bar_verification')
      .selectAll()
      .where('envelope_sha256', '=', bin(envelopeSha256))
      .executeTakeFirst();
    return r && ({ ...r, envelope_sha256: hex(r.envelope_sha256), envelope: bytes(r.envelope) } as BarVerificationRow);
  }
  /** Newest check first. */
  async listFor(opsAccount: string): Promise<BarVerificationRow[]> {
    const rows = await this.#db
      .selectFrom('bar_verification')
      .selectAll()
      .where('ops_account', '=', opsAccount)
      .orderBy('checked_at_ledger', 'desc')
      .execute();
    return rows.map(
      (r) => ({ ...r, envelope_sha256: hex(r.envelope_sha256), envelope: bytes(r.envelope) }) as BarVerificationRow,
    );
  }
}

export interface AttorneyCredentialRow {
  ops_account: string;
  verification_sha256: string;
  create_tx_hash: string;
  accept_tx_hash: string | null;
  expiration: number;
}

export class AttorneyCredentialsRepo {
  readonly #db: Kysely<DB>;
  constructor(db: Kysely<DB>) {
    this.#db = db;
  }
  async insert(c: AttorneyCredentialRow): Promise<void> {
    await this.#db
      .insertInto('attorney_credential')
      .values({ ...c, verification_sha256: bin(c.verification_sha256) })
      .onConflict((oc) => oc.columns(['ops_account', 'create_tx_hash']).doNothing())
      .execute();
  }
  async listFor(opsAccount: string): Promise<AttorneyCredentialRow[]> {
    const rows = await this.#db
      .selectFrom('attorney_credential')
      .selectAll()
      .where('ops_account', '=', opsAccount)
      .orderBy('expiration', 'desc')
      .execute();
    return rows.map((r) => ({ ...r, verification_sha256: hex(r.verification_sha256) }));
  }
}

export interface BarDealLinkRow {
  deal_id: string;
  role: 'lawyerA' | 'lawyerB';
  envelope: Uint8Array;
  verification_sha256: string;
}

export class BarDealLinksRepo {
  readonly #db: Kysely<DB>;
  constructor(db: Kysely<DB>) {
    this.#db = db;
  }
  async insert(l: BarDealLinkRow): Promise<void> {
    await this.#db
      .insertInto('bar_deal_link')
      .values({ ...l, verification_sha256: bin(l.verification_sha256) })
      .onConflict((oc) => oc.columns(['deal_id', 'role', 'verification_sha256']).doNothing())
      .execute();
  }
  async list(dealId: string): Promise<BarDealLinkRow[]> {
    const rows = await this.#db
      .selectFrom('bar_deal_link')
      .selectAll()
      .where('deal_id', '=', dealId)
      .orderBy('role')
      .execute();
    return rows.map((r) => ({
      ...r,
      role: r.role as BarDealLinkRow['role'],
      envelope: bytes(r.envelope),
      verification_sha256: hex(r.verification_sha256),
    }));
  }
}
