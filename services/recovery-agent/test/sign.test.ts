// P3.9-06, 07, 08: signing rounds through the relay, with a stalled holder and a retry.
import { decodeSigned } from '@legx/coordinator/frost/schema';
import { aggregateChecked, FrostError, verifyEd25519Strict } from '@legx/core/frost';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PAIRS, slotSetup } from './support/setup.ts';
import { makeWorld, rnd, type World } from './support/world.ts';

let w: World;
let setup: Awaited<ReturnType<typeof slotSetup>>;
beforeAll(async () => {
  w = await makeWorld({ signTimeoutMs: 30_000 });
  setup = await slotSetup(w);
});
afterAll(async () => {
  await w.close();
});

const allow = () => ({ ok: true as const });
const ids = (pair: readonly number[]) =>
  pair.map((i) => (w.members[i - 1] as { info: { identifier: string } }).info.identifier);
const opts = (i: number, msg: Uint8Array, pair: [number, number]) => ({
  msg,
  kind: 'tagged' as const,
  share: setup.keys[i - 1]?.secret as never,
  pub: setup.pub,
  pair,
  check: allow,
});

describe('signing through the relay', () => {
  it('P3.9-07 every 2-of-3 pair gives a valid signature; one share alone cannot finish', async () => {
    for (const pair of PAIRS) {
      const msg = rnd(40);
      const session = await w.relay.openSession({
        dealId: w.dealId,
        slot: w.slot,
        purpose: 'sign',
        participants: w.participants(),
        pair: ids(pair) as [string, string],
      });
      const sigs = await Promise.all(pair.map((i) => w.holder(i).sign(session, opts(i, msg, pair))));
      expect(Buffer.from(sigs[0] as Uint8Array).toString('hex')).toBe(
        Buffer.from(sigs[1] as Uint8Array).toString('hex'),
      );
      expect(verifyEd25519Strict(sigs[0] as Uint8Array, msg, setup.record.slotPub)).toBe(true);
    }
    const msg = rnd(33);
    const lone = sessionOf(1, msg);
    const share = lone.s.signShare(msg, lone.list, allow);
    expect(() =>
      aggregateChecked(setup.pub, [lone.s.commitment], msg, { [lone.s.commitment.identifier]: share }),
    ).toThrow(FrostError);
  });

  it('P3.9-06 a stalled holder times out; the relay offers another pair, with fresh commitments', async () => {
    const msg = rnd(48);
    const first = await w.relay.openSession({
      dealId: w.dealId,
      slot: w.slot,
      purpose: 'sign',
      participants: w.participants(),
      pair: ids([1, 2]) as [string, string],
    });
    // holder 2 never answers; holder 1 starts and waits
    const stalled = w.holder(1).sign(first, opts(1, msg, [1, 2]));
    const stalledResult = stalled.then(
      () => 'signed',
      (e: Error) => e.message,
    );
    await new Promise((r) => setTimeout(r, 100));
    expect((await w.relay.status(first)).status).toBe('open');
    w.clock.now += 31_000;
    const view = await w.relay.status(first);
    expect(view.status).toBe('timed_out');
    expect(view.next).not.toBeNull();
    expect(await stalledResult).toMatch(/session_closed/);
    const next = view.next as string;
    expect((await w.relay.status(next)).pair).toEqual(ids([1, 3]));
    const sigs = await Promise.all([1, 3].map((i) => w.holder(i).sign(next, opts(i, msg, [1, 3]))));
    expect(verifyEd25519Strict(sigs[0] as Uint8Array, msg, setup.record.slotPub)).toBe(true);
    // the new attempt has its own commitments
    const commitOf = async (session: string) =>
      (await w.relay.transcript(session))
        .map((m) => decodeSigned(m.message).message)
        .find((m) => m.kind === 'sign.begin');
    const a = (await commitOf(first)) as { commitment: { hiding: string } };
    const b = (await commitOf(next)) as { commitment: { hiding: string } };
    expect(a.commitment.hiding).not.toBe(b.commitment.hiding);
    // late traffic from the dead attempt is refused
    expect(await w.relay.send((await w.relay.transcript(first))[0]?.message as never).catch((e) => e.code)).toBe(
      'relay_session_closed',
    );
  });

  it('P3.9-08 a retry uses fresh nonces; a reused commitment is refused; the relay stores no nonce', async () => {
    const msg = rnd(48);
    const session = await w.relay.openSession({
      dealId: w.dealId,
      slot: w.slot,
      purpose: 'sign',
      participants: w.participants(),
      pair: ids([2, 3]) as [string, string],
    });
    await Promise.all([2, 3].map((i) => w.holder(i).sign(session, opts(i, msg, [2, 3]))));
    const stored = await w.relay.transcript(session);
    const kinds = stored.map((m) => decodeSigned(m.message).message.kind);
    expect(kinds.sort()).toEqual(['sign.begin', 'sign.commit', 'sign.request', 'sign.share', 'sign.share']);
    expect(JSON.stringify(stored)).not.toMatch(/nonce/i);
    // the same begin message again (a reused commitment) is a duplicate
    const begin = stored.find((m) => decodeSigned(m.message).message.kind === 'sign.begin');
    expect(await w.relay.send(begin?.message as never).catch((e) => e.code)).toBe('relay_duplicate');
    // and a second share from the same session object is refused by the core (T-U-22 at service level)
    const again = sessionOf(2, msg);
    again.s.signShare(msg, again.list, allow);
    expect(() => again.s.signShare(msg, again.list, allow)).toThrow(/NONCE_USED/);
  });
});

import { SigningSession } from '@legx/core/frost';

function sessionOf(i: number, msg: Uint8Array) {
  const s = SigningSession.open(setup.keys[i - 1]?.secret as never, setup.pub, msg);
  const other = SigningSession.open(setup.keys[(i === 1 ? 2 : 1) - 1]?.secret as never, setup.pub, msg);
  return { s, list: [s.commitment, other.commitment] };
}
