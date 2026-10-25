// I-28 / 4.10 isolation: the DKG runs inside the vault frame. Over a MessageChannel the app side sees only relay
// messages (signed, sealed), events and the public result; no share or key ever crosses, and the share is stored by
// the frame's own vault.

import type { SlotPublic } from '@legx/core/frost';
import { holderId } from '@legx/core/frost';
import { fromBase64Strict, mldsaVerify } from '@legx/core/pq';
import { ed25519 } from '@noble/curves/ed25519.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { vaultFrameHost } from '../../src/frame-host.ts';
import { xwingShareCipher } from '../../src/frost/cipher.ts';
import { type DkgEvent, type DkgResult, openerSessions, runSlotDkg } from '../../src/frost/dkg.ts';
import { FrostHolder } from '../../src/frost/holder.ts';
import { keyDirectory } from '../../src/frost/pinning.ts';
import { apiRequestMessage } from '../../src/pq/apiRequest.ts';
import { connectVault, serveVault } from '../../src/protocol.ts';
import { createVault } from '../../src/vault.ts';
import { dealId, freshDb } from '../helpers.ts';
import { MemoryRelay, party } from './world.ts';

async function world() {
  const id = dealId();
  const relay = new MemoryRelay();
  const second = party(2, 'second-authenticator', 'Your second device');
  const agent = party(3, 'recovery-agent', 'Recovery agent');
  const dbName = freshDb();
  const vault = createVault({ role: 'alice', dbName, deals: () => Promise.reject(new Error('no seal')) });
  const { port1, port2 } = new MessageChannel();
  serveVault(port2, vault, vaultFrameHost({ role: 'alice', dbName }));
  const app = connectVault(port1);
  // the frame makes the keys; the app pins the public halves it is told
  const pub = await app.enroll(id);
  const edPub = new Uint8Array([0xed, ...pub.ed25519]);
  const phone = {
    info: {
      identifier: holderId(1),
      keyId: `key-${id}`,
      role: 'phone' as const,
      edPub,
      pqPub: pub.mlDsa65,
      deviceId: 'phone',
      label: 'Your phone',
    },
  };
  const holders = [phone.info, second.info, agent.info];
  relay.pin(...holders);
  const others = () =>
    Promise.all(
      [second, agent].map((p) =>
        runSlotDkg({
          dealId: id,
          slot: 'A',
          holders,
          relay,
          sessions: relay.joiner(),
          pinned: keyDirectory(holders),
          local: [{ index: Number(p.info.identifier === holderId(2) ? 2 : 3), keys: p.keys }],
          timeoutMs: 8_000,
        }),
      ),
    );
  return { id, relay, phone, holders, vault, app, others, second, agent };
}

describe('the DKG runs in the vault frame', () => {
  it('stores share 1 inside the frame and returns only public data', async () => {
    const w = await world();
    const events: DkgEvent[] = [];
    const others = w.others();
    const res = await w.app.dkg(
      {
        dealId: w.id,
        slot: 'A',
        holders: w.holders,
        localIndex: 1,
        keyId: w.phone.info.keyId,
        share2: 'second-device',
        timeoutMs: 8_000,
      },
      { relay: w.relay, sessions: openerSessions(w.relay, w.holders), onEvent: (e) => events.push(e) },
    );
    await others;
    expect(res.ready).toBe(true);
    if (!res.ready) return;
    expect(res.pairs.every((p) => p.ok)).toBe(true);
    expect(events.some((e) => e.kind === 'ready')).toBe(true);
    expect((await w.vault.list()).map((e) => [e.dealId, e.hasShare1])).toEqual([[w.id, true]]);
    expect(Object.keys(res).sort()).toEqual(['pairs', 'pub', 'ready', 'record']);
  });

  it('refuses a ceremony when the frame has no ceremony host', async () => {
    const w = await world();
    const { port1, port2 } = new MessageChannel();
    serveVault(port2, w.vault);
    await expect(
      connectVault(port1).dkg(
        { dealId: w.id, slot: 'A', holders: w.holders, localIndex: 1, keyId: 'x', share2: 'second-device' },
        { relay: w.relay, sessions: openerSessions(w.relay, w.holders) },
      ),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });
});

describe('the frame signs API requests with its own keys', () => {
  it('returns an ApiAuth value that verifies; enrolling twice gives the same keys', async () => {
    const id = dealId();
    const dbName = freshDb();
    const { port1, port2 } = new MessageChannel();
    serveVault(
      port2,
      createVault({ role: 'bob', dbName, deals: () => Promise.reject(new Error('x')) }),
      vaultFrameHost({ role: 'bob', dbName }),
    );
    const app = connectVault(port1);
    const a = await app.enroll(id);
    expect(await app.enroll(id)).toEqual(a);
    const req = {
      dealId: id,
      pairId: 'pair-1',
      method: 'GET',
      path: '/deals/x?y=1',
      body: new Uint8Array(),
      ledgerIndex: 77,
    };
    const auth = await app.signApi(req);
    expect(auth.ledgerIndex).toBe(77);
    const msg = apiRequestMessage(req, hexToBytes(auth.nonce), 77);
    const [ed, pq] = auth.signatures.map((x) => fromBase64Strict(x.sig) as Uint8Array);
    expect(ed25519.verify(ed as Uint8Array, msg, a.ed25519, { zip215: false })).toBe(true);
    expect(mldsaVerify('ml-dsa-65', a.mlDsa65, msg, pq as Uint8Array, 'legx/api-request/v1' as never)).toBe(true);
  });
});

describe('refresh and repair run in the vault frame', () => {
  async function ready() {
    const w = await world();
    const others = w.others();
    const io = { relay: w.relay, sessions: openerSessions(w.relay, w.holders) };
    const dkg = await w.app.dkg(
      {
        dealId: w.id,
        slot: 'A',
        holders: w.holders,
        localIndex: 1,
        keyId: w.phone.info.keyId,
        share2: 'second-device',
        timeoutMs: 8_000,
      },
      io,
    );
    const [second, agent] = (await others) as (DkgResult & { ready: true })[];
    if (!dkg.ready || !second?.ready || !agent?.ready) throw new Error('dkg');
    return { w, io, pub: dkg.pub as unknown as SlotPublic, second, agent };
  }

  it('a refresh stores the new share in the frame, and only the public record comes back', async () => {
    const { w, io, pub, second, agent } = await ready();
    const mk = (index: number, p: ReturnType<typeof party>) =>
      new FrostHolder({
        index,
        keys: p.keys,
        dealId: w.id,
        slot: 'A',
        holders: w.holders,
        relay: w.relay,
        cipher: xwingShareCipher,
        pinned: keyDirectory(w.holders),
        timeoutMs: 8_000,
      });
    const remote = async (index: number, p: ReturnType<typeof party>, r: DkgResult & { ready: true }) => {
      const sid = await w.relay.joiner()('refresh');
      const h = mk(index, p);
      const o = await h.refresh(sid, { share: r.shares.get(index) as never, pub, participants: [1, 2, 3], epoch: 1 });
      await h.signDeletion(sid, o.ctx, o.pub, 1);
    };
    const others = Promise.all([remote(2, w.second, second), remote(3, w.agent, agent)]);
    const events: unknown[] = [];
    const record = await w.app.refresh(
      {
        dealId: w.id,
        slot: 'A',
        holders: w.holders,
        localIndex: 1,
        keyId: w.phone.info.keyId,
        epoch: 1,
        timeoutMs: 8_000,
      },
      { ...io, onEvent: (e) => events.push(e) },
    );
    await others;
    expect(record.status).toBe('COMPLETE');
    expect(events.some((e) => (e as { kind: string }).kind === 'refreshed')).toBe(true);
    expect((await w.vault.list()).map((e) => e.hasShare1)).toEqual([true]);
  });

  it('refuses refresh and repair when the frame has no ceremony host', async () => {
    const w = await world();
    const { port1, port2 } = new MessageChannel();
    serveVault(port2, w.vault);
    const app = connectVault(port1);
    const base = { dealId: w.id, slot: 'A' as const, holders: w.holders, localIndex: 1, keyId: 'x' };
    const io = { relay: w.relay, sessions: openerSessions(w.relay, w.holders) };
    await expect(app.refresh({ ...base, epoch: 1 }, io)).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      app.repair({ ...base, mode: 'helper', newIndex: 1, helpers: [2, 3], pub: { commitments: [] } as never }, io),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });
});

describe('OD-35 the frame lists the deals it holds keys for and remembers the key pair id', () => {
  it('lists each deal once, per role namespace, and signs without being told the pair id again', async () => {
    const dbName = freshDb();
    const ids = [dealId(), dealId()];
    const { port1, port2 } = new MessageChannel();
    serveVault(
      port2,
      createVault({ role: 'lawyerA', dbName, deals: () => Promise.reject(new Error('x')) }),
      vaultFrameHost({ role: 'lawyerA', dbName }),
    );
    const app = connectVault(port1);
    expect(await app.deals()).toEqual([]);
    await app.enroll(ids[0] as string, 'console-1');
    await app.enroll(ids[1] as string);
    await app.enroll(ids[0] as string);
    expect((await app.deals()).sort()).toEqual([...ids].sort());
    const auth = await app.signApi({
      dealId: ids[0] as string,
      method: 'GET',
      path: '/deals',
      body: new Uint8Array(),
      ledgerIndex: 5,
    });
    expect(auth.signatures.map((s) => s.keyid)).toEqual(['console-1#ed25519', 'console-1#ml-dsa-65']);
    // a deal enrolled without a pair id cannot sign until it has one
    await expect(
      app.signApi({ dealId: ids[1] as string, method: 'GET', path: '/deals', body: new Uint8Array(), ledgerIndex: 5 }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    // another role's namespace sees nothing
    const other = freshDb();
    const ch = new MessageChannel();
    serveVault(
      ch.port2,
      createVault({ role: 'lawyerB', dbName: other, deals: () => Promise.reject(new Error('x')) }),
      vaultFrameHost({ role: 'lawyerB', dbName: other }),
    );
    expect(await connectVault(ch.port1).deals()).toEqual([]);
  });
});
