// OD-37: shipment.signed (Bob's primary holder, slot B signature) then receipt.signed (Alice's, slot A signature),
// then the release; each refusal leaves nothing behind.
// Source: build/SHIP_RECEIPT.md 2 to 5; build/DECISIONS.md OD-37, OD-38
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { gatePassed, ok, shipData, toReceived, toShipped, toVerified } from './support/lifecycle.ts';
import { call, holderOf, makeWorld, newDeal, post, type World } from './support/world.ts';

vi.setConfig({ testTimeout: 180_000 });
let w: World;
beforeAll(async () => {
  w = await makeWorld();
});
afterAll(async () => w.close());

const stateOf = async (id: string) => ok(await call(w, holderOf(w, 'alice'), 'GET', `/deals/${id}`)).state;
const count = async (id: string) => (await w.db.repos.evidenceEvents.listAfter(id, -1)).length;

describe('shipment and receipt', () => {
  it('verified -> shipped -> received, then the gate and the release are allowed', async () => {
    const id = await newDeal(w);
    await toVerified(w, id);
    const s = await shipData(w, id);
    expect((await post(w, id, 'bob', 'shipment.signed', s.shipment())).status).toBe(200);
    expect(await stateOf(id)).toBe('SHIPPED');
    expect((await post(w, id, 'alice', 'receipt.signed', s.receipt())).status).toBe(200);
    expect(await stateOf(id)).toBe('RECEIVED');
    ok(await gatePassed(w, id));
  });

  it('the gate is refused before the receipt (OD-38: release only from RECEIVED)', async () => {
    const id = await newDeal(w);
    await toShipped(w, id);
    const r = await gatePassed(w, id);
    expect(r.status).toBe(422);
    expect(r.body.error).toBe('wrong_state');
  });

  it('a receipt before a shipment is refused', async () => {
    const id = await newDeal(w);
    await toVerified(w, id);
    const s = await shipData(w, id);
    const before = await count(id);
    const r = await post(w, id, 'alice', 'receipt.signed', s.receipt());
    expect(r.status).toBe(422);
    expect(r.body.error).toBe('wrong_state');
    expect(await count(id)).toBe(before);
  });

  it('only Bob posts the shipment and only Alice the receipt', async () => {
    const id = await newDeal(w);
    await toVerified(w, id);
    const s = await shipData(w, id);
    expect((await post(w, id, 'alice', 'shipment.signed', s.shipment())).status).toBe(403);
    expect((await post(w, id, 'lawyerB', 'shipment.signed', s.shipment())).status).toBe(403);
    ok(await post(w, id, 'bob', 'shipment.signed', s.shipment()));
    expect((await post(w, id, 'bob', 'receipt.signed', s.receipt())).status).toBe(403);
  });

  it('a shipment signed by a key that is not slot B is refused', async () => {
    const id = await newDeal(w);
    await toVerified(w, id);
    const forged = (await shipData(w, id, 'alice')).shipment();
    const r = await post(w, id, 'bob', 'shipment.signed', forged);
    expect(r.status).toBe(422);
    expect(r.body.error).toBe('shipment_bad_signature');
    expect(await stateOf(id)).toBe('VERIFIED');
  });

  it('a stale shipment (more than 20 ledgers old) is refused', async () => {
    const id = await newDeal(w);
    await toVerified(w, id);
    const s = await shipData(w, id, 'bob', w.ledger.index - 30);
    const r = await post(w, id, 'bob', 'shipment.signed', s.shipment());
    expect(r.status).toBe(422);
    expect(r.body.error).toBe('shipment_ledger_too_old');
  });

  it('a second shipment is refused', async () => {
    const id = await newDeal(w);
    await toShipped(w, id);
    const s = await shipData(w, id);
    expect((await post(w, id, 'bob', 'shipment.signed', s.shipment({ trackingId: 'OTHER-1' }))).status).toBe(422);
  });

  it('a receipt signed by Bob key is refused and the deal stays SHIPPED', async () => {
    const id = await newDeal(w);
    await toShipped(w, id);
    const s = await shipData(w, id);
    const r = await post(w, id, 'alice', 'receipt.signed', s.receipt({}, 'bob'));
    expect(r.status).toBe(422);
    expect(r.body.error).toBe('receipt_bad_signature');
    expect(await stateOf(id)).toBe('SHIPPED');
  });

  it('a receipt for another manifest root is refused', async () => {
    const id = await newDeal(w);
    await toShipped(w, id);
    const s = await shipData(w, id);
    const r = await post(w, id, 'alice', 'receipt.signed', s.receipt({ root: new Uint8Array(32).fill(7) }));
    expect(r.status).toBe(422);
    expect(r.body.error).toBe('receipt_manifest_mismatch');
  });

  it.each(['damaged', 'missing'] as const)(
    'a %s receipt does not release: the deal stays SHIPPED',
    async (condition) => {
      const id = await newDeal(w);
      await toShipped(w, id);
      const s = await shipData(w, id);
      const r = await post(w, id, 'alice', 'receipt.signed', s.receipt({ condition }));
      expect(r.status).toBe(422);
      expect(r.body.error).toBe('refused_receipt');
      expect(await stateOf(id)).toBe('SHIPPED');
    },
  );

  it('toReceived leaves the deal RECEIVED', async () => {
    const id = await newDeal(w);
    await toReceived(w, id);
    expect(await stateOf(id)).toBe('RECEIVED');
  });
});
