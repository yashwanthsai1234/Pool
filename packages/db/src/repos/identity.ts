// passport_attestation, zk_proof, enrollment_key (DESIGN 9, 6.3, 6.10, 6.15). None of them holds passport data.
import { EnrollmentKey, ZkTrustRecord } from '@legx/contracts/records';
import { Hex32, Side, Uuid7 } from '@legx/contracts/values';
import type { Kysely } from 'kysely';
import { z } from 'zod';
import { bin, bytes, hex } from '../bytes.ts';
import { KeyNotRecorded } from '../errors.ts';
import type { DB } from '../schema.ts';

export interface PassportAttestationRow {
  deal_id: string;
  side: 'A' | 'B';
  envelope: Uint8Array;
  anchor_ledger: number;
  leaf_hash: string;
}

export class PassportAttestationsRepo {
  readonly #db: Kysely<DB>;
  constructor(db: Kysely<DB>) {
    this.#db = db;
  }
  /** Idempotent by leaf hash: a second insert of the same envelope returns the first row. */
  async insert(a: PassportAttestationRow): Promise<PassportAttestationRow> {
    await this.#db
      .insertInto('passport_attestation')
      .values({ ...a, leaf_hash: bin(a.leaf_hash) })
      .onConflict((oc) => oc.column('leaf_hash').doNothing())
      .execute();
    const r = await this.#db
      .selectFrom('passport_attestation')
      .selectAll()
      .where('leaf_hash', '=', bin(a.leaf_hash))
      .executeTakeFirstOrThrow();
    return { ...r, side: r.side as 'A' | 'B', envelope: bytes(r.envelope), leaf_hash: hex(r.leaf_hash) };
  }
  async list(dealId: string): Promise<PassportAttestationRow[]> {
    const rows = await this.#db
      .selectFrom('passport_attestation')
      .selectAll()
      .where('deal_id', '=', dealId)
      .orderBy('anchor_ledger')
      .execute();
    return rows.map((r) => ({
      ...r,
      side: r.side as 'A' | 'B',
      envelope: bytes(r.envelope),
      leaf_hash: hex(r.leaf_hash),
    }));
  }
}

/** The trust record (DESIGN 6.10) plus the hashes of the recorded loader files. Strict: no other field gets in. */
const RegistryRoots = ZkTrustRecord.extend({ loader_files: z.record(z.string().max(256), Hex32).optional() });

/** One stored proof. Strict, so a field such as a name, number or birth date is rejected before it reaches the table. */
export const ZkProofRecord = z.strictObject({
  deal_id: Uuid7,
  side: Side,
  stage: z.enum(['onboarding', 'release']),
  proof: z.instanceof(Uint8Array),
  registry_roots: RegistryRoots,
  identifier_hash: Hex32,
});
export type ZkProofRecord = z.infer<typeof ZkProofRecord>;

export class ZkProofsRepo {
  readonly #db: Kysely<DB>;
  constructor(db: Kysely<DB>) {
    this.#db = db;
  }
  async insert(input: unknown): Promise<void> {
    const p = ZkProofRecord.parse(input);
    await this.#db
      .insertInto('zk_proof')
      .values({ ...p, registry_roots: JSON.stringify(p.registry_roots), identifier_hash: bin(p.identifier_hash) })
      .onConflict((oc) => oc.columns(['deal_id', 'side', 'stage', 'identifier_hash']).doNothing())
      .execute();
  }
  async list(dealId: string): Promise<ZkProofRecord[]> {
    const rows = await this.#db
      .selectFrom('zk_proof')
      .selectAll()
      .where('deal_id', '=', dealId)
      .orderBy('side')
      .orderBy('stage')
      .execute();
    return rows.map((r) =>
      ZkProofRecord.parse({ ...r, proof: bytes(r.proof), identifier_hash: hex(r.identifier_hash) }),
    );
  }
}

export interface EnrollmentKeyRow extends EnrollmentKey {
  deal_id: string;
  /** The evidence event that records this key's hash; the key is usable only because it exists. */
  evidence_event_id: string;
}

const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');

export class EnrollmentKeysRepo {
  readonly #db: Kysely<DB>;
  constructor(db: Kysely<DB>) {
    this.#db = db;
  }
  /**
   * Keys are never replaced: a rotated key is a new row with a new `key_id` (DESIGN 6.3). The evidence event that records
   * the key hash must already exist; without it the foreign key refuses the row (T-U-29 at table level).
   */
  async insert(k: EnrollmentKeyRow): Promise<void> {
    const { deal_id, evidence_event_id, ...rest } = k;
    const e = EnrollmentKey.parse(rest);
    const ev = await this.#db
      .selectFrom('evidence_event')
      .select('deal_id')
      .where('event_id', '=', evidence_event_id)
      .executeTakeFirst();
    if (ev?.deal_id !== deal_id) throw new KeyNotRecorded(e.key_id);
    await this.#db
      .insertInto('enrollment_key')
      .values({
        key_id: e.key_id,
        deal_id,
        slot: e.slot,
        holder_role: e.holder_role,
        ed25519_pub: bin(e.ed25519_pub),
        mldsa65_pub: Buffer.from(e.mldsa65_pub, 'base64'),
        valid_from: e.valid_from,
        valid_to: e.valid_to ?? null,
        evidence_event_id,
      })
      .execute();
  }

  /** The key only if its hash was recorded as evidence first; otherwise `KeyNotRecorded`. */
  async getUsable(keyId: string): Promise<EnrollmentKeyRow> {
    const r = await this.#db.selectFrom('enrollment_key').selectAll().where('key_id', '=', keyId).executeTakeFirst();
    if (!r) throw new KeyNotRecorded(keyId);
    return toRow(r);
  }

  /** Every row of one Ed25519 public key (hex), in any deal: the deals a pinned console key was enrolled in. */
  async listByEd25519(ed25519Pub: string): Promise<EnrollmentKeyRow[]> {
    const rows = await this.#db
      .selectFrom('enrollment_key')
      .selectAll()
      .where('ed25519_pub', '=', bin(ed25519Pub))
      .orderBy('deal_id')
      .execute();
    return rows.map(toRow);
  }

  async listForDeal(dealId: string): Promise<EnrollmentKeyRow[]> {
    const rows = await this.#db
      .selectFrom('enrollment_key')
      .selectAll()
      .where('deal_id', '=', dealId)
      .orderBy('slot')
      .orderBy('holder_role')
      .orderBy('valid_from')
      .execute();
    return rows.map(toRow);
  }
}

function toRow(r: {
  key_id: string;
  deal_id: string;
  slot: string;
  holder_role: string;
  ed25519_pub: Uint8Array;
  mldsa65_pub: Uint8Array;
  valid_from: number;
  valid_to: number | null;
  evidence_event_id: string;
}): EnrollmentKeyRow {
  return {
    key_id: r.key_id,
    deal_id: r.deal_id,
    slot: r.slot,
    holder_role: r.holder_role,
    ed25519_pub: hex(r.ed25519_pub),
    mldsa65_pub: b64(r.mldsa65_pub),
    valid_from: r.valid_from,
    ...(r.valid_to === null ? {} : { valid_to: r.valid_to }),
    evidence_event_id: r.evidence_event_id,
  } as EnrollmentKeyRow;
}
