// P3.9-13: the relay and the agent run in the demo profile (in-process PGlite) and the production profile (Postgres 18)
// and pass the same suite. The profiles differ only in what is passed in: here, the database.

import { verifyEd25519Strict } from '@legx/core/frost';
import { releaseShare } from '@legx/core/frostRules';
import type { KyselyDatabase } from '@legx/db/client';
import { describe, expect, it } from 'vitest';
import { PgNonceLedger } from '../../src/nonces.ts';
import { makeAgentWorld } from './agent.ts';
import { fullLifecycle } from './lifecycle.ts';
import { slotSetup } from './setup.ts';
import { makeWorld, rnd } from './world.ts';

export function profileSuite(label: string, newDb: () => Promise<KyselyDatabase>): void {
  describe(`profile: ${label}`, () => {
    it('a lost phone: recovery, repair, refresh with every deletion, then a signature under the new epoch', async () => {
      const w = await makeWorld({ db: await newDb() });
      try {
        const a = await makeAgentWorld(w);
        await fullLifecycle(w, a);
        expect(await a.vault.count(w.dealId, 'A')).toBe(1);
        expect(a.evidence.ofKind('frost.signed')).toHaveLength(1);
      } finally {
        await w.close();
      }
    });

    it('marks nonces used atomically under concurrent requests', async () => {
      const w = await makeWorld({ db: await newDb() });
      try {
        const ledger = (h: string) =>
          new PgNonceLedger(w.deps.db, { keyId: 'agent', dealId: w.dealId, messageHash: h });
        const id = 'ab'.repeat(32);
        const results = await Promise.allSettled(
          Array.from({ length: 20 }, () => releaseShare(ledger('00'.repeat(32)), id, () => new Uint8Array([1]))),
        );
        expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
      } finally {
        await w.close();
      }
    });

    it('a stalled signer times out and the next pair signs with fresh commitments', async () => {
      const w = await makeWorld({ db: await newDb(), signTimeoutMs: 30_000 });
      try {
        const s = await slotSetup(w);
        const ids = (pair: number[]) => pair.map((i) => w.members[i - 1]?.info.identifier) as [string, string];
        const msg = rnd(48);
        const opts = (i: number, pair: [number, number]) => ({
          msg,
          kind: 'tagged' as const,
          share: s.keys[i - 1]?.secret as never,
          pub: s.pub,
          pair,
          check: () => ({ ok: true as const }),
        });
        const first = await w.relay.openSession({
          dealId: w.dealId,
          slot: w.slot,
          purpose: 'sign',
          participants: w.participants(),
          pair: ids([1, 2]),
        });
        const stalled = w
          .holder(1)
          .sign(first, opts(1, [1, 2]))
          .then(
            () => 'signed',
            (e: Error) => e.message,
          );
        await new Promise((r) => setTimeout(r, 100));
        w.clock.now += 31_000;
        const view = await w.relay.status(first);
        expect(view.status).toBe('timed_out');
        expect(await stalled).toMatch(/session_closed/);
        const sigs = await Promise.all([1, 3].map((i) => w.holder(i).sign(view.next as string, opts(i, [1, 3]))));
        expect(verifyEd25519Strict(sigs[0] as Uint8Array, msg, s.record.slotPub)).toBe(true);
      } finally {
        await w.close();
      }
    });
  });
}
