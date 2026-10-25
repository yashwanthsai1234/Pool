// A server holder's share store (DESIGN 6.4, IMPLEMENTATION P3.9-11, P3.10): exactly one share per (deal, slot),
// encrypted at rest. The recovery agent and the firm HSM share this one implementation (I-26); each has its own table
// and holder index. AES-256-GCM with a 32-byte key (the agent: an operator-supplied KMS data key; the HSM: a key
// derived from its own signer), a fresh 96-bit nonce per write, and (deal, slot, epoch, group key) as associated data,
// so a row cannot be moved to another slot or epoch. The table's primary key makes a second share of one slot
// impossible, and the vault refuses any share that is not its holder's own index. The tables are in migration 0003.
// Source: https://csrc.nist.gov/pubs/sp/800/38/d/final (GCM: unique 96-bit IV per key, AAD)
// Source: https://nodejs.org/api/crypto.html#cryptocreatecipherivalgorithm-key-iv-options
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { kyselyOf } from '@legx/coordinator/frost/store';
import { bytesToHex } from '@legx/core/dealcore';
import { holderId, type KeyShare, type SlotPublic } from '@legx/core/frost';
import type { Database } from '@legx/db';
import { type Kysely, sql } from 'kysely';

/** The agent is always holder 3 of a client slot (canonical order: phone, second authenticator, recovery agent). */
export const AGENT_INDEX = 3;

/** Which holder a vault stores for: its table, its holder index and the associated-data label. */
export interface VaultSpec {
  readonly table: 'recovery_agent_share' | 'firm_cosigner_share';
  readonly holderIndex: number;
  readonly label: string;
}
export const AGENT_VAULT: VaultSpec = {
  table: 'recovery_agent_share',
  holderIndex: AGENT_INDEX,
  label: 'legx/recovery-agent/share/v1',
};

export class VaultError extends Error {
  readonly code: 'WRONG_HOLDER' | 'SLOT_TAKEN' | 'NOT_FOUND' | 'TAMPERED';
  constructor(code: VaultError['code']) {
    super(code);
    this.name = 'VaultError';
    this.code = code;
  }
}

export interface StoredShare {
  readonly share: KeyShare;
  readonly pub: SlotPublic;
  readonly epoch: number;
}

const toHex = (m: Record<string, Uint8Array>) =>
  Object.fromEntries(Object.entries(m).map(([k, v]) => [k, bytesToHex(v)]));
const fromHex = (m: Record<string, string>) =>
  Object.fromEntries(Object.entries(m).map(([k, v]) => [k, new Uint8Array(Buffer.from(v, 'hex'))]));

export class ShareVault {
  readonly #k: Kysely<unknown>;
  readonly #key: Uint8Array;
  readonly #spec: VaultSpec;
  readonly #t: ReturnType<typeof sql.table>;

  constructor(db: Database, key: Uint8Array, spec: VaultSpec = AGENT_VAULT) {
    if (key.length !== 32) throw new Error('the vault key must be 32 bytes');
    this.#k = kyselyOf(db);
    this.#key = key;
    this.#spec = spec;
    this.#t = sql.table(spec.table);
  }

  #aad(dealId: string, slot: string, epoch: number, groupPub: string): Buffer {
    return Buffer.from(`${this.#spec.label}|${dealId}|${slot}|${epoch}|${groupPub}`);
  }

  #mine(s: StoredShare): void {
    if (s.share.identifier !== holderId(this.#spec.holderIndex)) throw new VaultError('WRONG_HOLDER');
  }

  #seal(dealId: string, slot: string, s: StoredShare) {
    const groupPub = bytesToHex(s.pub.commitments[0] as Uint8Array);
    const nonce = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', this.#key, nonce);
    c.setAAD(this.#aad(dealId, slot, s.epoch, groupPub));
    const body = JSON.stringify({
      identifier: s.share.identifier,
      signingShare: bytesToHex(s.share.signingShare),
      signers: s.pub.signers,
      commitments: s.pub.commitments.map(bytesToHex),
      verifyingShares: toHex(s.pub.verifyingShares),
    });
    const ciphertext = Buffer.concat([c.update(body, 'utf8'), c.final(), c.getAuthTag()]);
    return { nonce, ciphertext, groupPub };
  }

  /** Stores the holder's share of a slot for the first time. A second share of the same slot is refused. */
  async insert(dealId: string, slot: string, s: StoredShare): Promise<void> {
    this.#mine(s);
    const { nonce, ciphertext, groupPub } = this.#seal(dealId, slot, s);
    const r = await sql`insert into ${this.#t} (deal_id, slot, epoch, group_pub, nonce, ciphertext)
      values (${dealId}, ${slot}, ${s.epoch}, ${groupPub}, ${nonce}, ${ciphertext})
      on conflict (deal_id, slot) do nothing returning slot`.execute(this.#k);
    if (r.rows.length === 0) throw new VaultError('SLOT_TAKEN');
  }

  /** Replaces the share with a newer epoch's (a refresh or a repair); the old ciphertext is overwritten, not kept. */
  async replace(dealId: string, slot: string, s: StoredShare): Promise<void> {
    this.#mine(s);
    const { nonce, ciphertext, groupPub } = this.#seal(dealId, slot, s);
    const r = await sql`update ${this.#t} set epoch = ${s.epoch}, group_pub = ${groupPub}, nonce = ${nonce},
      ciphertext = ${ciphertext} where deal_id = ${dealId} and slot = ${slot} and epoch < ${s.epoch} returning slot`.execute(
      this.#k,
    );
    if (r.rows.length === 0) throw new VaultError('NOT_FOUND');
  }

  async get(dealId: string, slot: string): Promise<StoredShare | undefined> {
    const r = await sql<{ epoch: number; group_pub: string; nonce: Uint8Array; ciphertext: Uint8Array }>`
      select epoch, group_pub, nonce, ciphertext from ${this.#t} where deal_id = ${dealId} and slot = ${slot}`.execute(
      this.#k,
    );
    const row = r.rows[0];
    if (!row) return undefined;
    const buf = Buffer.from(row.ciphertext);
    const d = createDecipheriv('aes-256-gcm', this.#key, Buffer.from(row.nonce));
    d.setAAD(this.#aad(dealId, slot, Number(row.epoch), row.group_pub));
    d.setAuthTag(buf.subarray(buf.length - 16));
    let plain: string;
    try {
      plain = Buffer.concat([d.update(buf.subarray(0, buf.length - 16)), d.final()]).toString('utf8');
    } catch {
      throw new VaultError('TAMPERED');
    }
    const o = JSON.parse(plain) as {
      identifier: string;
      signingShare: string;
      signers: { min: number; max: number };
      commitments: string[];
      verifyingShares: Record<string, string>;
    };
    return {
      epoch: Number(row.epoch),
      share: { identifier: o.identifier, signingShare: new Uint8Array(Buffer.from(o.signingShare, 'hex')) },
      pub: {
        signers: o.signers,
        commitments: o.commitments.map((c) => new Uint8Array(Buffer.from(c, 'hex'))),
        verifyingShares: fromHex(o.verifyingShares),
      },
    };
  }

  /** How many shares this vault holds for a slot (the state test of P3.9-11: always 0 or 1). */
  async count(dealId: string, slot: string): Promise<number> {
    const r = await sql<{
      n: number;
    }>`select count(*)::int as n from ${this.#t} where deal_id = ${dealId} and slot = ${slot}`.execute(this.#k);
    return Number(r.rows[0]?.n);
  }

  /** The raw stored bytes of a slot, for the at-rest test. */
  async raw(dealId: string, slot: string): Promise<Uint8Array | undefined> {
    const r = await sql<{
      ciphertext: Uint8Array;
    }>`select ciphertext from ${this.#t} where deal_id = ${dealId} and slot = ${slot}`.execute(this.#k);
    return r.rows[0] ? new Uint8Array(r.rows[0].ciphertext) : undefined;
  }
}
