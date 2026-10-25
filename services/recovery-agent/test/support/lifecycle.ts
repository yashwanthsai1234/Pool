// The lost-phone lifecycle (P3.9-12): a new phone enrolls, the 72 hours pass, the agent and the second authenticator
// repair, then all three refresh, then the deal continues. Shared by the repair tests and the profile suite.
import { EventPredicate } from '@legx/contracts/events';
import {
  aggregateChecked,
  type Commitment,
  FrostError,
  type KeyShare,
  SigningSession,
  verifyEd25519Strict,
} from '@legx/core/frost';
import { expect } from 'vitest';
import { xwingShareCipher } from '../../src/cipher.ts';
import { FrostHolder } from '../../src/holder.ts';
import { type AgentWorld, HOUR } from './agent.ts';
import { type Member, rnd, type World } from './world.ts';

const allow = () => ({ ok: true as const });
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

/** The phone is lost: a new phone enrolls, the recovery runs its 72 hours, and the agent has authorized it. */
export async function lostPhone(w: World, a: AgentWorld) {
  const phone = await a.newPhone();
  const key = phone.keys.keyId;
  await a.recoveries.startClient({ dealId: w.dealId, slot: 'A', newKeyId: key, proof: a.proof({ newKeyId: key }) });
  a.clock.now += 72 * HOUR;
  a.directory = [phone.info, (w.members[1] as Member).info, (w.members[2] as Member).info];
  const holders = a.directory;
  const mk = (i: number, keys: Member['keys']) =>
    new FrostHolder({
      index: i,
      keys,
      dealId: w.dealId,
      slot: 'A',
      holders,
      relay: w.relay,
      cipher: xwingShareCipher,
      pinned: w.registry.check,
      pollMs: 2,
      timeoutMs: 8000,
      complaintWindowMs: 1500,
    });
  const participants = holders.map((h) => ({ identifier: h.identifier, keyId: h.keyId, role: h.role }));
  return { phone, holders, participants, newPhone: mk(1, phone.keys), second: mk(2, (w.members[1] as Member).keys) };
}

export const session = (
  w: World,
  purpose: 'repair' | 'refresh',
  participants: { identifier: string; keyId: string; role: string }[],
) => w.relay.openSession({ dealId: w.dealId, slot: 'A', purpose, participants });

/** Lost phone, then the agent and the second authenticator rebuild the first share for the new phone. */
export async function repaired(w: World, a: AgentWorld) {
  const l = await lostPhone(w, a);
  const pub = a.setup.pub;
  const s = await session(w, 'repair', l.participants);
  const secondShare = a.setup.keys[1]?.secret as KeyShare;
  const [, , fresh] = await Promise.all([
    l.second.repairHelp(s, { share: secondShare, pub, helpers: [2, 3], newIndex: 1 }),
    a.agent.repairHelp(w.dealId, 'A', s, { newIndex: 1, helpers: [2, 3] }),
    l.newPhone.repairReceive(s, { pub, helpers: [2, 3] }),
  ]);
  return { ...l, fresh, secondShare, pub };
}

/** P3.9-12 from the lost phone to a signature under the new epoch. */
export async function fullLifecycle(w: World, a: AgentWorld) {
  const r = await repaired(w, a);
  const s = await session(w, 'refresh', r.participants);
  const [p1, p2, row] = await Promise.all([
    r.newPhone.refresh(s, { share: r.fresh, pub: r.pub, participants: [1, 2, 3], epoch: 1 }),
    r.second.refresh(s, { share: r.secondShare, pub: r.pub, participants: [1, 2, 3], epoch: 1 }),
    a.agent.refresh(w.dealId, 'A', s, 1),
  ]);
  expect(hex(p1.pub.commitments[0] as Uint8Array)).toBe(hex(r.pub.commitments[0] as Uint8Array)); // the group key
  expect(row.status).toBe('pending_deletions'); // the others have not signed their deletions yet
  await r.newPhone.signDeletion(s, p1.ctx, p1.pub, 1);
  await r.second.signDeletion(s, p2.ctx, p2.pub, 1);
  const done = await a.agent.refreshProgress(w.dealId, 'A', 1);
  expect(done).toMatchObject({ status: 'complete', oldEpochRetired: true, missing: [] });
  const events = a.evidence.ofKind('frost.refreshed');
  expect(events.length).toBeGreaterThanOrEqual(2);
  const last = events.at(-1)?.data as Record<string, unknown>;
  expect((last.deletion_sigs as unknown[]).length).toBe(3);
  const predicate = {
    event_id: '0190a000-0000-7000-8000-000000000001',
    deal_id: w.dealId,
    seq: 1,
    actor: { role: 'alice', key_id: 'x' },
    occurred_at: '2026-10-24T12:00:00Z',
    prev_hash: '00'.repeat(32),
    payload_commitment: '00'.repeat(32),
    sig_algs: ['ed25519', 'ml-dsa-65'],
    kind: 'frost.refreshed',
    data: last,
  };
  const parsed = EventPredicate.safeParse(predicate);
  expect(parsed.success, JSON.stringify(parsed.error?.issues)).toBe(true);
  // the vault now holds the new epoch's share
  expect((await a.vault.get(w.dealId, 'A'))?.epoch).toBe(1);
  // an old share plus a new share does not combine
  const oldSecond = r.secondShare;
  const msg = rnd(33);
  expect(() => SigningSession.open(oldSecond, p1.pub, msg)).toThrow(FrostError); // the new key data rejects an old share
  const ses = [SigningSession.open(oldSecond, r.pub, msg), SigningSession.open(p1.share, p1.pub, msg)];
  const list = ses.map((x) => x.commitment) as Commitment[];
  const shares = Object.fromEntries(
    ses.map((x, i) => [(i === 0 ? oldSecond : p1.share).identifier, x.signShare(msg, list, allow)]),
  );
  expect(() => aggregateChecked(p1.pub, list, msg, shares)).toThrow(FrostError);
  // the deal continues: the agent and the second authenticator sign an exit under the new epoch
  const exit = a.exit();
  const sign = await w.relay.openSession({
    dealId: w.dealId,
    slot: 'A',
    purpose: 'sign',
    participants: r.participants,
    pair: [r.holders[1]?.identifier, r.holders[2]?.identifier] as [string, string],
  });
  const [c, g] = await Promise.all([
    r.second.sign(sign, {
      msg: exit.msg,
      kind: 'xrpl-multisign',
      share: p2.share,
      pub: p2.pub,
      pair: [2, 3],
      check: allow,
    }),
    a.agent.sign(w.dealId, 'A', sign, [2, 3]),
  ]);
  expect(verifyEd25519Strict(c, exit.msg, a.setup.groupKey)).toBe(true);
  expect(hex(g)).toBe(hex(c));
}
