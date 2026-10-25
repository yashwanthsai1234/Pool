// The share store: encrypted at rest under a key derived from the HSM's SignerPort, one share per slot, bound to its slot.
import { holderId } from '@legx/core/frost';
import { openPglite } from '@legx/db/pglite';
import { generateNodeSignerKeys, nodeSigner } from '@legx/signer';
import { sql } from 'kysely';
import { describe, expect, it, vi } from 'vitest';

// PGlite starts slowly when the unit files run in parallel.
vi.setConfig({ testTimeout: 600_000, hookTimeout: 600_000 });

import { VaultError } from '@legx/recovery-agent/vault';
import { FirmShareVault, wrapKeyFrom } from '../src/vault.ts';

const share = (id: number) => ({
  share: { identifier: holderId(id), signingShare: new Uint8Array(32).fill(7) },
  pub: {
    signers: { min: 2, max: 3 },
    commitments: [new Uint8Array(32).fill(1)],
    verifyingShares: { [holderId(id)]: new Uint8Array(32).fill(2) },
  },
  epoch: 0,
});

describe('FirmShareVault', () => {
  it('derives the same wrapping key from the same signer and another from another signer', async () => {
    const a = nodeSigner(generateNodeSignerKeys('a-ed' as never, 'a-pq' as never));
    const b = nodeSigner(generateNodeSignerKeys('b-ed' as never, 'b-pq' as never));
    expect(await wrapKeyFrom(a)).toEqual(await wrapKeyFrom(a));
    expect(await wrapKeyFrom(a)).not.toEqual(await wrapKeyFrom(b));
  });

  it('stores one share of holder 2 per slot, never in clear, and fails closed on a moved or tampered row', async () => {
    const db = openPglite();
    await db.migrate();
    const key = await wrapKeyFrom(nodeSigner(generateNodeSignerKeys('c-ed' as never, 'c-pq' as never)));
    const v = new FirmShareVault(db, key);
    await expect(v.insert('d1', 'LA', share(1))).rejects.toMatchObject({ code: 'WRONG_HOLDER' });
    await v.insert('d1', 'LA', share(2));
    await expect(v.insert('d1', 'LA', share(2))).rejects.toMatchObject({ code: 'SLOT_TAKEN' });
    expect((await v.get('d1', 'LA'))?.share.signingShare).toEqual(new Uint8Array(32).fill(7));
    expect(Buffer.from((await v.raw('d1', 'LA')) as Uint8Array).includes(Buffer.alloc(16, 7))).toBe(false);
    await sql`update firm_cosigner_share set slot = 'LB' where deal_id = 'd1'`.execute(db.kysely);
    await expect(v.get('d1', 'LB')).rejects.toBeInstanceOf(VaultError);
    expect(() => new FirmShareVault(db, new Uint8Array(16))).toThrow();
    await db.close();
  });
});
