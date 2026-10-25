// P4.7-04, 12, 18, 22: refresh and repair with the shares inside real vaults, over the in-memory relay.
import {
  aggregateChecked,
  type KeyShare,
  SigningSession,
  type SlotPublic,
  slotPubkey,
  verifyEd25519Strict,
} from '@legx/core/frost';
import type { FrostRefreshed } from '@legx/core/frostRefresh';
import { equalBytes } from '@noble/curves/utils.js';
import { describe, expect, it } from 'vitest';
import { xwingShareCipher } from '../../src/frost/cipher.ts';
import { openerSessions, runSlotDkg } from '../../src/frost/dkg.ts';
import { FrostHolder } from '../../src/frost/holder.ts';
import { keyDirectory } from '../../src/frost/pinning.ts';
import { type RefreshEvent, refreshSlot } from '../../src/frost/refresh.ts';
import { repairReceive, repairWithVault } from '../../src/frost/repair.ts';
import { HYGIENE_NOTE } from '../../src/frost/text.ts';
import type { HolderInfo } from '../../src/frost/wire.ts';
import { createVault, messageFor } from '../../src/vault.ts';
import { binding, dealId, fakePrf, freshDb, sealedDeal } from '../helpers.ts';
import { type ClientSlot, clientDevices, device } from './devices.ts';
import { MemoryRelay, type Party, party } from './world.ts';

const ok = () => ({ ok: true }) as const;
/** Tries to sign with two shares under `pub`; true only for a signature that verifies. */
function combines(pub: SlotPublic, a: KeyShare, b: KeyShare, msg: Uint8Array): boolean {
  try {
    const x = SigningSession.open(a, pub, msg);
    const y = SigningSession.open(b, pub, msg);
    const list = [x.commitment, y.commitment];
    const sig = aggregateChecked(pub, list, msg, {
      [a.identifier]: x.signShare(msg, list, ok),
      [b.identifier]: y.signShare(msg, list, ok),
    });
    return verifyEd25519Strict(sig, msg, slotPubkey(pub));
  } catch {
    return false;
  }
}

/** The recovery agent's side of a refresh, scripted (task 3.9's agent does the same through its own holder). */
function agentHolder(
  d: { relay: MemoryRelay; id: string; holders: readonly HolderInfo[] },
  agent: Party,
  slot: 'A' = 'A',
) {
  return new FrostHolder({
    index: 3,
    keys: agent.keys,
    dealId: d.id,
    slot,
    holders: d.holders,
    relay: d.relay,
    cipher: xwingShareCipher,
    pinned: keyDirectory(d.holders),
    timeoutMs: 8_000,
  });
}

async function agentRefresh(d: ClientSlot, opts: { sign?: boolean; tamper?: boolean } = {}) {
  const h = agentHolder(d, d.agent);
  const sid = await d.relay.joiner()('refresh');
  const out = await h.refresh(sid, {
    share: { identifier: d.agentShare.identifier, signingShare: d.agentShare.signingShare.slice() },
    pub: d.pub,
    participants: [1, 2, 3],
    epoch: 1,
    ...(opts.tamper
      ? {
          tamper: (m) =>
            m.kind === 'refresh-share' && m.to === 1
              ? { ...m, fields: [(m.fields[0] as Uint8Array).map((b, i) => (i === 1130 ? b ^ 1 : b))] }
              : m,
        }
      : {}),
  });
  if (opts.sign !== false) await h.signDeletion(sid, out.ctx, out.pub, 1);
  return out;
}

const refreshOn = (d: ClientSlot, who: 'phone' | 'second', events: RefreshEvent[] = [], timeoutMs = 8_000) =>
  refreshSlot({
    dealId: d.id,
    slot: 'A',
    holders: d.holders,
    relay: d.relay,
    sessions: who === 'phone' ? openerSessions(d.relay, d.holders) : d.relay.joiner(),
    pinned: keyDirectory(d.holders),
    local: [who === 'phone' ? { index: 1, keys: d.phone.keys } : { index: 2, keys: d.second.keys }],
    epoch: 1,
    timeoutMs,
    vault: who === 'phone' ? d.phoneVault : d.secondVault,
    onEvent: (e) => events.push(e),
  });

describe('P4.7-12 and P4.7-22 share refresh with all three holders online', () => {
  it('keeps the group key, needs every deletion statement, and old and new shares do not combine', async () => {
    const d = await clientDevices();
    const events: RefreshEvent[] = [];
    const [phone, second, agent] = await Promise.all([
      refreshOn(d, 'phone', events),
      refreshOn(d, 'second'),
      agentRefresh(d),
    ]);
    for (const r of [phone, second] as FrostRefreshed[]) expect(r.status).toBe('COMPLETE');
    expect(events.at(-1)).toEqual({
      kind: 'deletions',
      have: ['Your phone', 'Your second device', 'Recovery agent (Example Recovery Ltd)'],
      missing: [],
    });
    expect(equalBytes(agent.pub.commitments[0] as Uint8Array, d.pub.commitments[0] as Uint8Array)).toBe(true);
    const req = binding(d.deal, 'A');
    const msg = messageFor(d.pub, req);
    const [old1, , old3] = d.clearShares as [KeyShare, KeyShare, KeyShare];
    expect(combines(agent.pub, old1, agent.share, msg)).toBe(false); // old phone share + new agent share
    expect(combines(d.pub, old1, old3, msg)).toBe(true); // hygiene, not revocation: old shares still work together
    expect(HYGIENE_NOTE).toMatch(/hygiene, not revocation/);
    // the slot signs after the refresh, with the new shares in both vaults
    const sig = await d.phoneVault.signFrost(d.id, req);
    expect(verifyEd25519Strict(sig, msg, slotPubkey(d.pub))).toBe(true);
    await Promise.all(d.finished);
  });

  it('a holder that never signs its deletion statement leaves the refresh INCOMPLETE, naming it', async () => {
    const d = await clientDevices();
    const events: RefreshEvent[] = [];
    const [phone] = await Promise.all([
      refreshOn(d, 'phone', events, 1_500),
      refreshOn(d, 'second', [], 1_500),
      agentRefresh(d, { sign: false }),
    ]);
    expect(phone).toMatchObject({ status: 'INCOMPLETE', missing: [3] });
    expect(events.at(-1)).toMatchObject({ kind: 'deletions', missing: ['Recovery agent (Example Recovery Ltd)'] });
  });

  it('a bad sub-share aborts the refresh, names the sender, and the vault keeps its old share', async () => {
    const d = await clientDevices();
    const events: RefreshEvent[] = [];
    const results = await Promise.allSettled([
      refreshOn(d, 'phone', events),
      refreshOn(d, 'second'),
      agentRefresh(d, { tamper: true }),
    ]);
    expect((results[0] as PromiseRejectedResult).reason).toMatchObject({ code: 'SUBSHARE_INVALID', culprit: 3 });
    // the second device got good sub-shares and stored its new share, then saw the phone's abort and went back
    expect((results[1] as PromiseRejectedResult).reason).toMatchObject({ code: 'SESSION_ABORTED' });
    expect(events.find((e) => e.kind === 'aborted')).toMatchObject({
      culprit: 'Recovery agent (Example Recovery Ltd)',
    });
    expect(events.some((e) => e.kind === 'refreshed')).toBe(false);
    // the phone still signs with its old share against the second device's (also unchanged) share
    const req = binding(d.deal, 'A');
    const sig = await d.phoneVault.signFrost(d.id, req);
    expect(verifyEd25519Strict(sig, messageFor(d.pub, req), slotPubkey(d.pub))).toBe(true);
    await Promise.all(d.finished);
  });
});

describe('P4.7-18 repair: a new device gets a share through two helpers without the old share', () => {
  it('the new share signs with one other holder and the group key is unchanged', async () => {
    const d = await clientDevices();
    const newPhone = await device(d.id, 1, 'phone', 'Your new phone');
    const holders = [newPhone.info, d.second.info, d.agent.info];
    d.relay.pin(newPhone.info);
    const base = {
      dealId: d.id,
      slot: 'A' as const,
      holders,
      relay: d.relay,
      pinned: keyDirectory(holders),
      pub: d.pub,
      newIndex: 1,
      helpers: [2, 3],
      timeoutMs: 8_000,
    };
    const agent = new FrostHolder({
      index: 3,
      keys: d.agent.keys,
      dealId: d.id,
      slot: 'A',
      holders,
      relay: d.relay,
      cipher: xwingShareCipher,
      pinned: keyDirectory(holders),
      timeoutMs: 8_000,
    });
    const [share1] = await Promise.all([
      repairReceive({
        ...base,
        sessions: openerSessions(d.relay, holders),
        local: [{ index: 1, keys: newPhone.keys }],
      }),
      repairWithVault({
        ...base,
        sessions: d.relay.joiner(),
        local: [{ index: 2, keys: d.second.keys }],
        vault: d.secondVault,
      }),
      (async () =>
        agent.repairHelp(await d.relay.joiner()('repair'), {
          share: { ...d.agentShare, signingShare: d.agentShare.signingShare.slice() },
          pub: d.pub,
          helpers: [2, 3],
          newIndex: 1,
        }))(),
    ]);
    const msg = messageFor(d.pub, binding(d.deal, 'A'));
    expect(combines(d.pub, share1, d.clearShares[2] as KeyShare, msg)).toBe(true);
    expect(equalBytes(share1.signingShare, (d.clearShares[0] as KeyShare).signingShare)).toBe(true); // same share 1, rebuilt
    const vault = createVault({ role: 'alice', dbName: newPhone.dbName, deals: async () => d.deal });
    await vault.storeShares({ dealId: d.id, pub: d.pub, share1, share2: { mode: 'second-device' } });
    expect(await vault.list()).toMatchObject([{ hasShare1: true, mode: 'second-device' }]);
  });
});

describe('P4.7-04 recovery on a new phone: share 2 from the PRF backup plus the agent, repair, then refresh', () => {
  it('the new phone gets a fresh share 1; the old phone share with a new share does not combine', async () => {
    const id = dealId();
    const relay = new MemoryRelay();
    const prf = fakePrf();
    const phone = await device(id, 1, 'phone', 'Your phone');
    const key = party(2, 'second-authenticator', 'Your security key', `security-key-${id}`);
    const agent = party(3, 'recovery-agent', 'Recovery agent (Example Recovery Ltd)');
    const holders = [phone.info, key.info, agent.info];
    relay.pin(...holders);
    const base = { dealId: id, slot: 'A' as const, holders, relay, pinned: keyDirectory(holders), timeoutMs: 8_000 };
    // the phone runs holders 1 and 2 (the security key cannot run FROST: its share is locked under its PRF)
    const [p, a] = await Promise.all([
      runSlotDkg({
        ...base,
        sessions: openerSessions(relay, holders),
        local: [
          { index: 1, keys: phone.keys },
          { index: 2, keys: key.keys },
        ],
      }),
      runSlotDkg({ ...base, sessions: relay.joiner(), local: [{ index: 3, keys: agent.keys }] }),
    ]);
    if (!p.ready || !a.ready) throw new Error('DKG');
    const pub = p.pub;
    const deal = sealedDeal(pub, 'A');
    const oldShare1 = {
      ...(p.shares.get(1) as KeyShare),
      signingShare: (p.shares.get(1) as KeyShare).signingShare.slice(),
    };
    const agentShare = a.shares.get(3) as KeyShare;
    const oldPhone = createVault({ role: 'alice', dbName: phone.dbName, deals: async () => deal, prf: prf.source });
    const credential = (await prf.source.register('security-key', { id: new Uint8Array(16), name: 'alice' }))
      .credential;
    await oldPhone.storeShares({
      dealId: id,
      pub,
      share1: p.shares.get(1) as KeyShare,
      share2: { mode: 'security-key', credential, share: p.shares.get(2) as KeyShare },
    });
    const file = await oldPhone.backupShare2ToFile(id);

    // the phone is lost. The new phone restores share 2 with a tap of the same security key.
    const newDb = freshDb();
    const newPhone = createVault({ role: 'alice', dbName: newDb, deals: async () => deal, prf: prf.source });
    expect(await newPhone.restore(file)).toEqual({ needsShare1: true });
    await expect(newPhone.signFrost(id, binding(deal, 'A'))).rejects.toThrow('NO_SHARE_1');
    // new enrollment keys on the new phone for holders 1 and 2, pinned through the recovery (task 3.9)
    const n1 = await device(id, 1, 'phone', 'Your new phone');
    const n2 = party(2, 'second-authenticator', 'Your security key', `security-key-${id}`);
    const newHolders = [n1.info, n2.info, agent.info];
    relay.pin(n1.info, n2.info);
    const nb = {
      dealId: id,
      slot: 'A' as const,
      holders: newHolders,
      relay,
      pinned: keyDirectory(newHolders),
      timeoutMs: 8_000,
    };
    const agentH = new FrostHolder({
      index: 3,
      keys: agent.keys,
      dealId: id,
      slot: 'A',
      holders: newHolders,
      relay,
      cipher: xwingShareCipher,
      pinned: keyDirectory(newHolders),
      timeoutMs: 8_000,
    });
    await Promise.all([
      repairWithVault({
        ...nb,
        pub,
        newIndex: 1,
        helpers: [2, 3],
        sessions: openerSessions(relay, newHolders),
        local: [
          { index: 1, keys: n1.keys },
          { index: 2, keys: n2.keys },
        ],
        vault: newPhone,
      }),
      (async () =>
        agentH.repairHelp(await relay.joiner()('repair'), {
          share: { ...agentShare, signingShare: agentShare.signingShare.slice() },
          pub,
          helpers: [2, 3],
          newIndex: 1,
        }))(),
    ]);
    const req = binding(deal, 'A');
    const sig = await newPhone.signFrost(id, req);
    expect(verifyEd25519Strict(sig, messageFor(pub, req), slotPubkey(pub))).toBe(true);

    // then the refresh: holders 1 and 2 on the new phone, 3 the agent
    const joinRefresh = relay.joiner();
    const [, agentNew] = await Promise.all([
      refreshSlot({
        ...nb,
        sessions: openerSessions(relay, newHolders),
        local: [
          { index: 1, keys: n1.keys },
          { index: 2, keys: n2.keys },
        ],
        epoch: 1,
        vault: newPhone,
      }),
      (async () => {
        const sid = await joinRefresh('refresh');
        const out = await agentH.refresh(sid, { share: agentShare, pub, participants: [1, 2, 3], epoch: 1 });
        await agentH.signDeletion(sid, out.ctx, out.pub, 1);
        return out;
      })(),
    ]);
    const msg = messageFor(pub, binding(deal, 'A'));
    expect(combines(agentNew.pub, oldShare1, agentNew.share, msg)).toBe(false); // the old phone's share is useless with new ones
    expect(await newPhone.signFrost(id, binding(deal, 'A'))).toHaveLength(64);
    expect(prf.state.calls).toBeGreaterThan(2); // each use of share 2 was a tap
  });
});
