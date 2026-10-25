// P4.9-03, 04, 06, 09, 10 and the "all directions" cases of the 2-of-3 post-quantum binding (Chromium and WebKit).
import { pqBindMsg } from '@legx/core/pq';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { PQ_BINDING_TEXT, pqBindingSession } from '../../src/pq/binding.ts';
import { pqKeys } from '../../src/pq/keys.ts';
import { createVault } from '../../src/vault.ts';
import { copy, freshDb } from '../helpers.ts';
import { bindingWorld } from './support.ts';

afterEach(() => {
  vi.restoreAllMocks();
});

type World = Awaited<ReturnType<typeof bindingWorld>>;
const session = (w: World, over: Partial<Parameters<typeof pqBindingSession>[0]> = {}) =>
  pqBindingSession({ slot: 'A', seal: w.seal, pinned: w.pinned, offer: w.offer, ...over });
const msgOf = (w: World) => pqBindMsg(w.seal.dealSeal, w.seal.slotPub, w.seal.pqKeyHash);

describe('P4.9-03 phone plus second holder plus slot cross-signature', () => {
  it('verifies in core verifyPqBinding and the pq.bound event appears', async () => {
    const w = await bindingWorld();
    const steps: string[] = [];
    const s = session(w, { onProgress: (p) => steps.push(p) });
    await s.signWith(w.phone);
    s.add(await w.second.sign(msgOf(w), 'legx/pq-binding/v1').then((sig) => ({ keyId: w.pinned[1].keyId, sig })));
    expect(s.status()).toBe('ready');
    const record = await s.finish(w.crossSign, w.server);
    expect(w.events).toEqual([{ kind: 'pq.bound', binding: record }]);
    expect(record.holder_sigs.map((h) => h.key_id)).toEqual(['phone#ml-dsa-65', 'second#ml-dsa-65']);
    expect(steps).toEqual(['signing', 'cross-signing', 'verifying', 'submitting']);
  });

  it('a lawyer slot uses the same package with the lawyer role', async () => {
    const keys = pqKeys({ role: 'lawyerA', dbName: freshDb() });
    const w = await bindingWorld();
    await keys.create(w.id);
    expect((await keys.publicKeys(w.id)).mlDsa65).toHaveLength(1952);
  });
});

describe('P4.9-09 only one holder signs', () => {
  it('is not accepted: the screen waits for a second holder and nothing is submitted', async () => {
    const w = await bindingWorld();
    const s = session(w);
    await s.signWith(w.phone);
    const taps = w.prf.state.calls;
    expect(s.status()).toBe('waiting-for-second-holder');
    expect(PQ_BINDING_TEXT.waiting).toBe('Waiting for a second holder');
    await expect(s.finish(w.crossSign, w.server)).rejects.toMatchObject({ code: 'BELOW_TWO_HOLDERS' });
    expect(w.prf.state.calls).toBe(taps); // no slot-key tap for a half-signed binding
    expect(w.server).not.toHaveBeenCalled();
  });

  it('the same holder twice still counts once', async () => {
    const w = await bindingWorld();
    const s = session(w);
    const mine = await s.signWith(w.phone);
    expect(() => s.add(mine)).toThrow('DUPLICATE_HOLDER');
    expect(s.status()).toBe('waiting-for-second-holder');
  });
});

describe('P4.9-10 the phone is lost', () => {
  it('the second authenticator and the recovery agent sign; the repaired phone cross-signs; it verifies', async () => {
    const w = await bindingWorld();
    // The new phone after repair: a fresh database with the slot's shares (task 4.7 repair puts share 1 there).
    const newPhone = createVault({ role: 'alice', dbName: freshDb(), prf: w.prf.source, deals: async () => w.deal });
    await newPhone.storeShares({
      dealId: w.id,
      pub: w.pub,
      share1: copy(w.shares[0]),
      share2: { mode: 'security-key', credential: { id: 'cred', transports: [] }, share: copy(w.shares[1]) },
    });
    const s = session(w);
    await s.signWith(w.second);
    s.add(w.agentSign(msgOf(w)));
    await s.finish((req) => newPhone.signFrost(w.id, req), w.server);
    expect(w.events).toHaveLength(1);
  });
});

describe('P4.9-04 the fields are computed on the device', () => {
  it('match the seal; pqKeyHash comes from the pinned keys in role order', async () => {
    const w = await bindingWorld();
    const s = session(w);
    expect(bytesToHex(s.fields.dealSeal)).toBe(bytesToHex(w.seal.dealSeal));
    expect(bytesToHex(s.fields.slotPub)).toBe(bytesToHex(w.seal.slotPub));
    expect(bytesToHex(s.fields.pqKeyHash)).toBe(bytesToHex(w.seal.pqKeyHash));
    const reordered = [w.pinned[1], w.pinned[0], w.pinned[2]] as const;
    expect(() => session(w, { pinned: reordered, offer: { ...w.offer, holders: reordered } })).toThrow('KEY_MISMATCH');
  });

  it('an offer for another deal seal or slot key refuses to sign', async () => {
    const w = await bindingWorld();
    const sign = vi.spyOn(w.phone, 'sign');
    expect(() => session(w, { offer: { ...w.offer, dealSeal: randomBytes(32) } })).toThrow('SEAL_MISMATCH');
    expect(() => session(w, { offer: { ...w.offer, slotPub: w.deal.slotPubs.B } })).toThrow('SEAL_MISMATCH');
    expect(sign).not.toHaveBeenCalled();
  });
});

describe('P4.9-06 a coordinator swaps one holder key', () => {
  it('the phone recomputes pqKeyHash from its pinned keys and shows "Key mismatch"', async () => {
    const w = await bindingWorld();
    const swapped = [w.pinned[0], w.pinned[1], { keyId: w.pinned[2].keyId, mlDsa65: randomBytes(1952) }];
    let shown = '';
    try {
      session(w, { offer: { ...w.offer, holders: swapped } });
    } catch (e) {
      shown = PQ_BINDING_TEXT.keyMismatch;
      expect(e).toMatchObject({ code: 'KEY_MISMATCH' });
    }
    expect(shown).toBe('Key mismatch');
    // A seal made over the swapped key set does not match the pinned keys either.
    expect(() => session(w, { seal: { ...w.seal, pqKeyHash: randomBytes(32) } })).toThrow('KEY_MISMATCH');
    expect(() => session(w, { offer: { ...w.offer, holders: w.pinned.slice(0, 2) } })).toThrow('KEY_MISMATCH');
  });
});

describe('all directions', () => {
  it('refuses an invalid signature, an unknown holder and a signature under another context', async () => {
    const w = await bindingWorld();
    const s = session(w);
    const good = w.agentSign(msgOf(w));
    const bad = good.sig.slice();
    bad[0] = (bad[0] ?? 0) ^ 1;
    expect(() => s.add({ keyId: good.keyId, sig: bad })).toThrow('HOLDER_SIG_INVALID');
    expect(() => s.add({ keyId: 'stranger#ml-dsa-65', sig: good.sig })).toThrow('HOLDER_KEY_UNKNOWN');
    const other = await w.second.sign(msgOf(w), 'legx/dsse/v1');
    expect(() => s.add({ keyId: w.pinned[1].keyId, sig: other })).toThrow('HOLDER_SIG_INVALID');
    expect(s.status()).toBe('waiting-for-second-holder');
  });

  it('a third holder signature is not added (the record carries exactly two)', async () => {
    const w = await bindingWorld();
    const s = session(w);
    await s.signWith(w.phone);
    await s.signWith(w.second);
    s.add(w.agentSign(msgOf(w)));
    const record = await s.finish(w.crossSign, w.server);
    expect(record.holder_sigs).toHaveLength(2);
  });

  it('a cancelled passkey tap during the cross-signature sends nothing; a retry completes', async () => {
    const w = await bindingWorld();
    const s = session(w);
    await s.signWith(w.phone);
    await s.signWith(w.second);
    w.prf.state.fail = true;
    await expect(s.finish(w.crossSign, w.server)).rejects.toMatchObject({ code: 'PASSKEY_REQUIRED' });
    expect(w.server).not.toHaveBeenCalled();
    w.prf.state.fail = false;
    await s.finish(w.crossSign, w.server);
    expect(w.events).toHaveLength(1);
  });

  it('a reload between the two signatures starts over: nothing half-signed is submitted', async () => {
    const w = await bindingWorld();
    await session(w).signWith(w.phone);
    // Reload: the session is memory only.
    const after = session(w);
    expect(after.status()).toBe('waiting-for-second-holder');
    await after.signWith(w.second);
    await expect(after.finish(w.crossSign, w.server)).rejects.toMatchObject({ code: 'BELOW_TWO_HOLDERS' });
    expect(w.server).not.toHaveBeenCalled();
  });

  it('a cross-signature by another key is refused before submit', async () => {
    const w = await bindingWorld();
    const s = session(w);
    await s.signWith(w.phone);
    await s.signWith(w.second);
    await expect(s.finish(async () => randomBytes(64), w.server)).rejects.toMatchObject({ code: 'CROSS_SIG_INVALID' });
    expect(w.server).not.toHaveBeenCalled();
  });

  it('the help text states that noble is not audited and not constant-time', () => {
    expect(PQ_BINDING_TEXT.help).toMatch(/not independently audited/);
    expect(PQ_BINDING_TEXT.help).toMatch(/constant-time/);
  });
});
