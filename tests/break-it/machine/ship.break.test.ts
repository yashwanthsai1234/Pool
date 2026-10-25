// OD-37 break-it: a receipt signed by Bob's key, a receipt replayed from another deal, and condition `damaged`.
// Each is refused by the coordinator, leaves the deal SHIPPED, and stores nothing.
// Source: build/SHIP_RECEIPT.md 3, 4, 6; build/DECISIONS.md OD-37, OD-38
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { gatePassed, ok, shipData, toShipped } from '../../../services/coordinator/test/support/lifecycle.ts';
import {
  call,
  holderOf,
  makeWorld,
  newDeal,
  post,
  type World,
} from '../../../services/coordinator/test/support/world.ts';

vi.setConfig({ testTimeout: 180_000 });
let w: World;
beforeAll(async () => {
  w = await makeWorld();
});
afterAll(async () => w.close());

const stateOf = async (id: string) => ok(await call(w, holderOf(w, 'alice'), 'GET', `/deals/${id}`)).state;
const count = async (id: string) => (await w.db.repos.evidenceEvents.listAfter(id, -1)).length;

describe('OD-37 receipts that must not release', () => {
  it('a receipt signed by Bob key: refused, the deal stays SHIPPED, the gate stays shut', async () => {
    const id = await newDeal(w);
    await toShipped(w, id);
    const n = await count(id);
    const s = await shipData(w, id);
    const r = await post(w, id, 'alice', 'receipt.signed', s.receipt({}, 'bob'));
    expect([r.status, r.body.error]).toEqual([422, 'receipt_bad_signature']);
    expect(await count(id)).toBe(n);
    expect(await stateOf(id)).toBe('SHIPPED');
    expect((await gatePassed(w, id)).status).toBe(422);
  });

  it('a receipt replayed from another deal is refused (it is bound to the deal id and the seal)', async () => {
    const other = await makeWorld();
    try {
      const a = await newDeal(other);
      const b = await newDeal(w);
      await toShipped(other, a);
      await toShipped(w, b);
      const foreign = (await shipData(other, a)).receipt();
      const r = await post(w, b, 'alice', 'receipt.signed', foreign);
      expect(r.status).toBe(422);
      expect(['receipt_bad_signature', 'receipt_msg_hash_mismatch', 'receipt_shipment_mismatch']).toContain(
        r.body.error,
      );
      expect(await stateOf(b)).toBe('SHIPPED');
    } finally {
      await other.close();
    }
  });

  it.each(['damaged', 'missing'] as const)('condition %s never releases', async (condition) => {
    const id = await newDeal(w);
    await toShipped(w, id);
    const r = await post(w, id, 'alice', 'receipt.signed', (await shipData(w, id)).receipt({ condition }));
    expect([r.status, r.body.error]).toEqual([422, 'refused_receipt']);
    expect(await stateOf(id)).toBe('SHIPPED');
    expect((await gatePassed(w, id)).status).toBe(422);
  });
});
