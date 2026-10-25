// deal and deal_key (DESIGN 9). Source: DESIGN.md section 9; contracts DealKey and PqBinding (DESIGN 6.5, 6.13).
import type { DealKey, PqBinding } from '@legx/contracts/records';
import type { DealState, IdMethod, Network } from '@legx/contracts/values';
import type { Kysely, Selectable } from 'kysely';
import type { z } from 'zod';
import { bin, binOrNull, hex, hexOrNull } from '../bytes.ts';
import type { DB } from '../schema.ts';

export interface DealRow {
  deal_id: string;
  state: z.infer<typeof DealState>;
  was_locked: boolean;
  network: z.infer<typeof Network>;
  contract_root: string;
  deal_seal: string | null;
  shell_address: string | null;
  signed_contract_seal: string | null;
  nft_token_id: string | null;
  mint_tx_hash: string | null;
  lawyer_ops_a: string | null;
  lawyer_ops_b: string | null;
  escrow_owner: string | null;
  escrow_sequence: number | null;
  condition_hex: string | null;
  cancel_after: number | null;
  exit_slot: number | null;
  payout_a: string;
  payout_b: string;
  releaser_account: string | null;
  amount_drops: string;
  created_at: Date;
}

export interface NewDeal {
  deal_id?: string;
  state: DealRow['state'];
  network: DealRow['network'];
  contract_root: string;
  payout_a: string;
  payout_b: string;
  amount_drops: string;
}

/** The columns set after creation, as the deal moves through its states (DESIGN 5.1). Bytes are hex. */
export type DealPatch = Partial<Omit<DealRow, 'deal_id' | 'created_at' | 'contract_root' | 'network' | 'amount_drops'>>;

const BYTE_COLUMNS = ['deal_seal', 'signed_contract_seal'] as const;

function toDealRow(r: Selectable<DB['deal']>): DealRow {
  return {
    ...r,
    contract_root: hex(r.contract_root),
    deal_seal: hexOrNull(r.deal_seal),
    signed_contract_seal: hexOrNull(r.signed_contract_seal),
  } as DealRow;
}

export class DealsRepo {
  readonly #db: Kysely<DB>;
  constructor(db: Kysely<DB>) {
    this.#db = db;
  }

  async insert(d: NewDeal): Promise<DealRow> {
    const row = await this.#db
      .insertInto('deal')
      .values({ ...d, contract_root: bin(d.contract_root) })
      .returningAll()
      .executeTakeFirstOrThrow();
    return toDealRow(row);
  }

  async get(dealId: string): Promise<DealRow | undefined> {
    const row = await this.#db.selectFrom('deal').selectAll().where('deal_id', '=', dealId).executeTakeFirst();
    return row && toDealRow(row);
  }

  /** Deals naming `account` as an operations account (either lawyer), newest first (I-W-10). */
  async listForOps(account: string, limit = 200): Promise<DealRow[]> {
    const rows = await this.#db
      .selectFrom('deal')
      .selectAll()
      .where((e) => e.or([e('lawyer_ops_a', '=', account), e('lawyer_ops_b', '=', account)]))
      .orderBy('deal_id', 'desc')
      .limit(limit)
      .execute();
    return rows.map(toDealRow);
  }

  /** Every deal, newest first (the projector's observer view, OD-31). */
  async listAll(limit = 200): Promise<DealRow[]> {
    const rows = await this.#db.selectFrom('deal').selectAll().orderBy('deal_id', 'desc').limit(limit).execute();
    return rows.map(toDealRow);
  }

  async update(dealId: string, patch: DealPatch): Promise<DealRow> {
    const values: Record<string, unknown> = { ...patch };
    for (const c of BYTE_COLUMNS) if (c in patch) values[c] = binOrNull(patch[c]);
    const row = await this.#db
      .updateTable('deal')
      .set(values)
      .where('deal_id', '=', dealId)
      .returningAll()
      .executeTakeFirstOrThrow();
    return toDealRow(row);
  }
}

export type DealKeyInput = z.infer<typeof DealKey> & {
  pq: Pick<z.infer<typeof PqBinding>, 'pq_key_hash' | 'holder_sigs' | 'cross_sig'>;
};

export interface DealKeyRow {
  deal_id: string;
  role: 'alice' | 'lawyerA' | 'bob' | 'lawyerB';
  xrpl_pubkey: string;
  xrpl_account: string;
  commitment: string;
  binding_sig: string;
  slot_policy: string;
  pq_key_hash: string;
  pq_binding_sigs: { key_id: string; sig: string }[];
  pq_cross_sig: string;
  id_method: z.infer<typeof IdMethod> | null;
  contract_sig: string | null;
  ops_account: string | null;
  ops_bind_sig_ops: string | null;
  ops_bind_sig_lawyer: string | null;
}

export class DealKeysRepo {
  readonly #db: Kysely<DB>;
  constructor(db: Kysely<DB>) {
    this.#db = db;
  }

  /** Public data only (DESIGN 9). The post-quantum binding's key hash must equal the one in the role's key data. */
  async insert(dealId: string, k: DealKeyInput): Promise<void> {
    if (k.pq.pq_key_hash !== k.pq_key_hash) throw new Error('pq binding key hash differs from the deal key hash');
    const lawyer = 'contract_sig' in k;
    await this.#db
      .insertInto('deal_key')
      .values({
        deal_id: dealId,
        role: k.role,
        xrpl_pubkey: k.xrpl_pubkey,
        xrpl_account: k.xrpl_account,
        commitment: bin(k.commitment),
        binding_sig: bin(k.binding_sig),
        slot_policy: bin(k.slot_policy),
        pq_key_hash: bin(k.pq_key_hash),
        pq_binding_sigs: JSON.stringify(k.pq.holder_sigs),
        pq_cross_sig: bin(k.pq.cross_sig),
        id_method: 'id_method' in k ? k.id_method : null,
        contract_sig: lawyer ? bin(k.contract_sig) : null,
        ops_account: lawyer ? k.ops_account : null,
        ops_bind_sig_ops: lawyer ? bin(k.ops_bind_sig_ops) : null,
        ops_bind_sig_lawyer: lawyer ? bin(k.ops_bind_sig_lawyer) : null,
      })
      .execute();
  }

  async list(dealId: string): Promise<DealKeyRow[]> {
    const rows = await this.#db
      .selectFrom('deal_key')
      .selectAll()
      .where('deal_id', '=', dealId)
      .orderBy('role')
      .execute();
    return rows.map((r) => ({
      ...r,
      commitment: hex(r.commitment),
      binding_sig: hex(r.binding_sig),
      slot_policy: hex(r.slot_policy),
      pq_key_hash: hex(r.pq_key_hash),
      pq_binding_sigs: r.pq_binding_sigs as DealKeyRow['pq_binding_sigs'],
      pq_cross_sig: hex(r.pq_cross_sig),
      contract_sig: hexOrNull(r.contract_sig),
      ops_bind_sig_ops: hexOrNull(r.ops_bind_sig_ops),
      ops_bind_sig_lawyer: hexOrNull(r.ops_bind_sig_lawyer),
    })) as DealKeyRow[];
  }
}
