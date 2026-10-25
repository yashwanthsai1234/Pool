import { randomBytes } from 'node:crypto';
import { sql } from 'kysely';
import type { KyselyDatabase } from '../../src/client.ts';
import type { DealKeyInput } from '../../src/repos/deals.ts';

export const rnd = (n: number): Uint8Array => new Uint8Array(randomBytes(n));
export const rndHex = (n: number): string => Buffer.from(randomBytes(n)).toString('hex');
export const b64 = (n: number): string => randomBytes(n).toString('base64');

/** UUIDv7 (RFC 9562): 48-bit millisecond time, version 7, variant 10, random rest. */
export function uuid7(): string {
  const b = randomBytes(16);
  b.writeUIntBE(Date.now(), 0, 6);
  b[6] = ((b[6] as number) & 0x0f) | 0x70;
  b[8] = ((b[8] as number) & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// Well-known XRPL accounts with valid checksums.
export const ADDR = [
  'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh',
  'rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn',
  'rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe',
  'rN7n7otQDd6FczFgLdSqtcsAUxDkw6fzRH',
] as const;

const edPub = (): string => `ED${rndHex(32).toUpperCase()}`;

export async function newDeal(db: KyselyDatabase, patch: { lawyer_ops_b?: string } = {}): Promise<string> {
  const d = await db.repos.deals.insert({
    state: 'DRAFT',
    network: 'standalone',
    contract_root: rndHex(32),
    payout_a: ADDR[0],
    payout_b: ADDR[1],
    amount_drops: '1000000',
  });
  if (patch.lawyer_ops_b) await db.repos.deals.update(d.deal_id, { lawyer_ops_b: patch.lawyer_ops_b });
  return d.deal_id;
}

const pq = (keyHash: string) => ({
  pq_key_hash: keyHash,
  holder_sigs: [
    { key_id: 'k1', sig: b64(3309) },
    { key_id: 'k2', sig: b64(3309) },
  ],
  cross_sig: rndHex(64),
});

export function clientKey(role: 'alice' | 'bob'): DealKeyInput {
  const pqh = rndHex(32);
  return {
    role,
    xrpl_pubkey: edPub(),
    xrpl_account: ADDR[2],
    commitment: rndHex(32),
    binding_sig: rndHex(64),
    slot_policy: rndHex(32),
    pq_key_hash: pqh,
    id_method: 'zkpassport',
    pq: pq(pqh),
  } as unknown as DealKeyInput;
}

export function lawyerKey(role: 'lawyerA' | 'lawyerB'): DealKeyInput {
  const pqh = rndHex(32);
  return {
    role,
    xrpl_pubkey: edPub(),
    xrpl_account: ADDR[3],
    commitment: rndHex(32),
    binding_sig: rndHex(64),
    slot_policy: rndHex(32),
    pq_key_hash: pqh,
    contract_sig: rndHex(64),
    ops_account: ADDR[1],
    ops_pub: edPub(),
    ops_bind_sig_ops: rndHex(64),
    ops_bind_sig_lawyer: rndHex(64),
    pq: pq(pqh),
  } as unknown as DealKeyInput;
}

export async function addEvent(db: KyselyDatabase, dealId: string) {
  return await db.transaction((r) =>
    r.evidenceEvents.appendNext(dealId, () => ({ envelope: rnd(40), leaf_hash: rndHex(32) })),
  );
}

/** What a refused statement looked like: SQLSTATE and the first line of the message. Used for the PGlite versus Postgres A/B. */
export async function refusal(p: Promise<unknown>): Promise<{ code: string; message: string }> {
  try {
    await p;
  } catch (e) {
    const err = e as { code?: string; message: string };
    return { code: err.code ?? 'none', message: err.message.split('\n')[0] ?? '' };
  }
  throw new Error('statement was not refused');
}

/** Runs statements on one connection as another role. `SET ROLE` is session state, so it needs one pinned connection. */
export async function asRole<T>(
  db: KyselyDatabase,
  role: string,
  fn: (q: (text: string) => Promise<unknown>) => Promise<T>,
): Promise<T> {
  return await db.kysely.connection().execute(async (c) => {
    await sql.raw(`SET ROLE ${role}`).execute(c);
    try {
      return await fn((text) => sql.raw(text).execute(c));
    } finally {
      await sql.raw('RESET ROLE').execute(c);
    }
  });
}
