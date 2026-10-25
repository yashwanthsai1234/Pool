import { decodeSigned } from '@legx/coordinator/frost/schema';
import { tupleHash } from '@legx/core/dealcore';
import {
  aggregateChecked,
  type Commitment,
  enrollmentSigned,
  type FrostMsg,
  holderId,
  type KeyShare,
  SigningSession,
  u32,
  verifyEd25519Strict,
} from '@legx/core/frost';
import { ed25519 } from '@noble/curves/ed25519.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { xwingShareCipher } from '../src/cipher.ts';
import { type AgentWorld, HOUR, makeAgentWorld } from './support/agent.ts';
import { fullLifecycle, lostPhone, repaired, session } from './support/lifecycle.ts';
import { type Member, makeWorld, must, rnd, type World } from './support/world.ts';

let w: World;
let a: AgentWorld;
beforeEach(async () => {
  w = await makeWorld();
  a = await makeAgentWorld(w);
});
afterEach(async () => {
  await w.close();
});

const allow = () => ({ ok: true as const });
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

describe('repair (P3.9-23)', () => {
  it('a new device gets a fresh share from two holders without the old share; it signs with one other holder', async () => {
    const l = await lostPhone(w, a);
    const pub = a.setup.pub;
    const s = await session(w, 'repair', l.participants);
    const secondShare = a.setup.keys[1]?.secret as KeyShare;
    const [, , fresh] = await Promise.all([
      l.second.repairHelp(s, { share: secondShare, pub, helpers: [2, 3], newIndex: 1 }),
      a.agent.repairHelp(w.dealId, 'A', s, { newIndex: 1, helpers: [2, 3] }),
      l.newPhone.repairReceive(s, { pub, helpers: [2, 3] }),
    ]);
    // the group key and the verifying share are unchanged; the old phone's share is never sent
    const oldShare = a.setup.keys[0]?.secret as KeyShare;
    expect(hex(fresh.signingShare)).toBe(hex(oldShare.signingShare)); // the same value, rebuilt without it
    expect(JSON.stringify(await w.relay.transcript(s))).not.toContain(hex(oldShare.signingShare));
    // it signs with one other holder
    const msg = rnd(40);
    const sign = await w.relay.openSession({
      dealId: w.dealId,
      slot: 'A',
      purpose: 'sign',
      participants: l.participants,
      pair: [l.holders[0]?.identifier, l.holders[1]?.identifier] as [string, string],
    });
    const sigs = await Promise.all([
      l.newPhone.sign(sign, { msg, kind: 'tagged', share: fresh, pub, pair: [1, 2], check: allow }),
      l.second.sign(sign, { msg, kind: 'tagged', share: secondShare, pub, pair: [1, 2], check: allow }),
    ]);
    expect(verifyEd25519Strict(sigs[0] as Uint8Array, msg, a.setup.groupKey)).toBe(true);
  });

  it('the agent helps only the device an authorized recovery names', async () => {
    const _l = await lostPhone(w, a);
    const stranger = await a.newPhone();
    a.directory = [stranger.info, (w.members[1] as Member).info, (w.members[2] as Member).info];
    const participants = a.directory.map((h) => ({ identifier: h.identifier, keyId: h.keyId, role: h.role }));
    const s = await session(w, 'repair', participants);
    await expect(a.agent.repairHelp(w.dealId, 'A', s, { newIndex: 1, helpers: [2, 3] })).rejects.toMatchObject({
      code: 'NOT_THE_NEW_DEVICE',
    });
  });

  it('the agent refuses to help before the delay has passed', async () => {
    const phone = await a.newPhone();
    await a.recoveries.startClient({
      dealId: w.dealId,
      slot: 'A',
      newKeyId: phone.keys.keyId,
      proof: a.proof({ newKeyId: phone.keys.keyId }),
    });
    a.clock.now += 71 * HOUR;
    a.directory = [phone.info, (w.members[1] as Member).info, (w.members[2] as Member).info];
    const s = await session(
      w,
      'repair',
      a.directory.map((h) => ({ identifier: h.identifier, keyId: h.keyId, role: h.role })),
    );
    await expect(a.agent.repairHelp(w.dealId, 'A', s, { newIndex: 1, helpers: [2, 3] })).rejects.toMatchObject({
      code: 'RECOVERY_DELAY',
    });
  });
});

describe('lost phone: repair, then refresh (P3.9-12, 21, 22)', () => {
  it('P3.9-12 frost.refreshed is logged, the group key is unchanged, an old share does not combine with a new one, the deal continues', async () => {
    await fullLifecycle(w, a);
  });

  it('P3.9-21 the refresh is not complete, and the old epoch not retired, until every deletion statement is in', async () => {
    const r = await repaired(w, a);
    const s = await session(w, 'refresh', r.participants);
    const [p1, p2] = await Promise.all([
      r.newPhone.refresh(s, { share: r.fresh, pub: r.pub, participants: [1, 2, 3], epoch: 1 }),
      r.second.refresh(s, { share: r.secondShare, pub: r.pub, participants: [1, 2, 3], epoch: 1 }),
      a.agent.refresh(w.dealId, 'A', s, 1),
    ]);
    await r.newPhone.signDeletion(s, p1.ctx, p1.pub, 1); // holder 2 has not signed yet
    const pending = await a.agent.refreshProgress(w.dealId, 'A', 1);
    expect(pending).toMatchObject({ status: 'pending_deletions', missing: [2], oldEpochRetired: false });
    const written = a.evidence.ofKind('frost.refreshed').at(-1)?.data as { deletion_sigs: unknown[] };
    expect(written.deletion_sigs).toHaveLength(2); // the agent's and the new phone's
    await r.second.signDeletion(s, p2.ctx, p2.pub, 1);
    expect(await a.agent.refreshProgress(w.dealId, 'A', 1)).toMatchObject({
      status: 'complete',
      oldEpochRetired: true,
    });
    expect(
      (must(a.evidence.ofKind('frost.refreshed').at(-1)).data as { deletion_sigs: unknown[] }).deletion_sigs,
    ).toHaveLength(3);
  });

  it('P3.9-22 a sub-share that does not match its Feldman commitments is rejected, names the dealer; the old shares stay valid', async () => {
    const r = await repaired(w, a);
    const s = await session(w, 'refresh', r.participants);
    const sid = Buffer.from(s, 'hex');
    const bad = async (m: FrostMsg): Promise<FrostMsg> => {
      if (m.to !== 3) return m; // holder 2 cheats toward the agent only
      const commit = (await w.relay.transcript(s))
        .map((x) => decodeSigned(x.message).message)
        .find((x) => x.kind === 'refresh.commit' && x.from === holderId(3)) as { kem_pub: string };
      const aad = tupleHash('legx/frost-refresh/v1', [sid, u32(2), u32(3)]);
      const ct = await xwingShareCipher.seal(
        new Uint8Array(Buffer.from(commit.kem_pub, 'base64')),
        aad,
        new Uint8Array(32).fill(9),
      );
      return enrollmentSigned(
        { sign: (b) => ed25519.sign(b, (w.members[1] as Member).keys.edSecret) },
        { session: m.session, kind: m.kind, from: m.from, to: m.to, fields: [ct] },
      );
    };
    const results = await Promise.allSettled([
      r.newPhone.refresh(s, { share: r.fresh, pub: r.pub, participants: [1, 2, 3], epoch: 1 }),
      r.second.refresh(s, { share: r.secondShare, pub: r.pub, participants: [1, 2, 3], epoch: 1, tamper: bad }),
      a.agent.refresh(w.dealId, 'A', s, 1),
    ]);
    const agentResult = results[2] as PromiseRejectedResult;
    expect(agentResult.status).toBe('rejected');
    expect(agentResult.reason).toMatchObject({ code: 'SUBSHARE_INVALID', culprit: 2 });
    expect(results.filter((x) => x.status === 'fulfilled')).toHaveLength(0);
    // the agent's share is still the old epoch's, and still works with an old share
    const kept = await a.vault.get(w.dealId, 'A');
    expect(kept?.epoch).toBe(0);
    const msg = rnd(33);
    const ses = [
      SigningSession.open(r.secondShare, r.pub, msg),
      SigningSession.open(kept?.share as KeyShare, r.pub, msg),
    ];
    const list = ses.map((x) => x.commitment) as Commitment[];
    const shares = Object.fromEntries(
      ses.map((x, i) => [(i === 0 ? r.secondShare : must(kept).share).identifier, x.signShare(msg, list, allow)]),
    );
    expect(verifyEd25519Strict(aggregateChecked(r.pub, list, msg, shares), msg, a.setup.groupKey)).toBe(true);
    expect(a.evidence.ofKind('frost.refreshed')).toHaveLength(0);
  });
});
