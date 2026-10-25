// P4.7-01, 02, 13, 14, 15: the slot DKG over an in-memory relay (Chromium and WebKit), every holder running the
// browser code. The screens over this are tested in apps/web/test/frost.
import { type FrostMsg, holderId, THRESHOLD } from '@legx/core/frost';
import { testSignCheck, testSignMessage } from '@legx/core/frostDkg';
import { serviceKeyListMessage } from '@legx/core/frostSetup';
import { ed25519, ed25519_FROST } from '@noble/curves/ed25519.js';
import { equalBytes } from '@noble/curves/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { deriveAddress } from 'xrpl';
import { xwingShareCipher } from '../../src/frost/cipher.ts';
import { type DkgEvent, type DkgResult, openerSessions, runSlotDkg } from '../../src/frost/dkg.ts';
import { FrostHolder } from '../../src/frost/holder.ts';
import {
  checkDevicePin,
  checkServiceKey,
  devicePinCode,
  fingerprint,
  KeyRefused,
  keyDirectory,
} from '../../src/frost/pinning.ts';
import { decodeSigned, type HolderInfo, indexOf, type Signed, signRelayMessage, toWire } from '../../src/frost/wire.ts';
import { clientSlot, type MemoryRelay, type Party, party } from './world.ts';

type Slot = ReturnType<typeof clientSlot>;
const DEAL = '0192f3a0-0000-7000-8000-000000000001';

function run(
  w: { relay: MemoryRelay; holders: HolderInfo[] },
  p: Party,
  opener: boolean,
  over: Partial<Parameters<typeof runSlotDkg>[0]> = {},
): Promise<DkgResult> {
  return runSlotDkg({
    dealId: DEAL,
    slot: 'A',
    holders: w.holders,
    relay: w.relay,
    sessions: opener ? openerSessions(w.relay, w.holders) : w.relay.joiner(),
    pinned: keyDirectory(w.holders),
    local: [{ index: indexOf(p.info.identifier), keys: p.keys }],
    timeoutMs: 8_000,
    ...over,
  });
}

describe('P4.7-01 client slot DKG through the relay', () => {
  it('all three holders get one group key, each its own share, three green pairs and the completed record', async () => {
    const w = clientSlot();
    const events: DkgEvent[] = [];
    const results = await Promise.all([
      run(w, w.phone, true, { onEvent: (e) => events.push(e) }),
      run(w, w.second, false),
      run(w, w.agent, false),
    ]);
    const ready = results.map((r) => {
      if (!r.ready) throw new Error('not ready');
      return r;
    });
    const keys = ready.map((r) => r.pub.commitments[0] as Uint8Array);
    expect(
      equalBytes(keys[0] as Uint8Array, keys[1] as Uint8Array) &&
        equalBytes(keys[1] as Uint8Array, keys[2] as Uint8Array),
    ).toBe(true);
    expect(ready.map((r) => [...r.shares.keys()])).toEqual([[1], [2], [3]]);
    expect(ready[0]?.record.testSignatures).toHaveLength(3);
    expect(events.filter((e) => e.kind === 'pair').map((e) => e.kind === 'pair' && e.result.ok)).toEqual([
      true,
      true,
      true,
    ]);
    const done = events.find((e) => e.kind === 'ready');
    expect(done?.kind === 'ready' && done.fingerprint).toMatch(/^[0-9a-f]{4}( [0-9a-f]{4}){3}$/);
  });
});

/** A dishonest holder: the browser holder with a tamper hook on its own outgoing messages. */
async function cheater(w: Slot, p: Party, tamper: (m: FrostMsg) => FrostMsg | Promise<FrostMsg>) {
  const h = new FrostHolder({
    index: indexOf(p.info.identifier),
    keys: p.keys,
    dealId: DEAL,
    slot: 'A',
    holders: w.holders,
    relay: w.relay,
    cipher: xwingShareCipher,
    pinned: keyDirectory(w.holders),
    timeoutMs: 8_000,
  });
  return h.dkg(await w.relay.joiner()('dkg'), { tamper });
}

const aborted = (events: DkgEvent[]) =>
  events.find((e) => e.kind === 'aborted') as Extract<DkgEvent, { kind: 'aborted' }>;

describe('P4.7-02 a bad round-1 proof or a bad round-2 share', () => {
  it('a bad proof of knowledge aborts and names the party; nobody gets a share', async () => {
    const w = clientSlot();
    const events: DkgEvent[] = [];
    const [phone, , agent] = await Promise.allSettled([
      run(w, w.phone, true, { onEvent: (e) => events.push(e) }),
      cheater(w, w.second, (m) =>
        m.kind === 'dkg-r1' ? { ...m, fields: m.fields.map((f, i) => (i === 2 ? randomBytes(64) : f)) } : m,
      ),
      run(w, w.agent, false),
    ]);
    expect(phone.status).toBe('rejected');
    expect(agent.status).toBe('rejected');
    expect((phone as PromiseRejectedResult).reason).toMatchObject({ code: 'POK_INVALID', culprit: 2 });
    expect(aborted(events).culprit).toBe('Your second device');
  });

  it('a share that fails its check gives a signed complaint, the DKG aborts naming the sender, no share is stored', async () => {
    const w = clientSlot();
    const events: DkgEvent[] = [];
    const [phone, , agent] = await Promise.allSettled([
      run(w, w.phone, true, { onEvent: (e) => events.push(e) }),
      cheater(w, w.second, (m) => {
        if (m.kind !== 'dkg-r2' || m.to !== 1) return m;
        const ct = (m.fields[0] as Uint8Array).slice();
        ct[ct.length - 1] = (ct[ct.length - 1] as number) ^ 1;
        return { ...m, fields: [ct] };
      }),
      run(w, w.agent, false),
    ]);
    expect((phone as PromiseRejectedResult).reason).toMatchObject({ code: 'DKG_COMPLAINT', culprit: 2 });
    expect(aborted(events)).toMatchObject({ complaint: true, culprit: 'Your second device' });
    // the agent judged the phone's complaint itself and blames the same sender
    expect((agent as PromiseRejectedResult).reason).toMatchObject({ code: 'DKG_COMPLAINT', culprit: 2 });
    const dkg = w.relay.sessions.find((s) => s.purpose === 'dkg');
    expect(w.relay.kinds(dkg?.id as string)).toContain('dkg.complaint');
  });
});

describe('P4.7-13 key pinning (T-U-29 in the browser)', () => {
  it('a key that was not scanned is refused before anything is sent, and the screen names it', async () => {
    const w = clientSlot();
    const events: DkgEvent[] = [];
    const pinned = keyDirectory([w.phone.info, w.agent.info]); // the second device was never scanned
    await expect(run(w, w.phone, true, { pinned, onEvent: (e) => events.push(e) })).rejects.toBeInstanceOf(KeyRefused);
    const refused = events.find((e) => e.kind === 'refused');
    expect(refused).toMatchObject({ label: 'Your second device', fingerprint: fingerprint(w.second.info.edPub) });
    expect(w.relay.sessions).toHaveLength(0);
  });

  it('the coordinator swaps in its own key for the recovery agent: refused, naming the recovery agent', async () => {
    const w = clientSlot();
    const swapped = party(3, 'recovery-agent', 'Recovery agent (Example Recovery Ltd)');
    w.relay.pin(swapped.info);
    const shown = [w.phone.info, w.second.info, swapped.info]; // what the coordinator presents
    const pinned = keyDirectory(w.holders);
    await expect(run({ relay: w.relay, holders: shown }, w.phone, true, { pinned })).rejects.toThrow(
      /Recovery agent .*not pinned/,
    );
  });

  it('the QR code between the two devices pins the right keys only, with the SAS', () => {
    const w = clientSlot();
    const { qr, sas } = devicePinCode(w.phone.info, w.second.info);
    expect(() => checkDevicePin(qr, w.phone.info, w.second.info, sas)).not.toThrow();
    const other = party(1, 'phone', 'Another phone');
    expect(() => checkDevicePin(qr, other.info, w.second.info, sas)).toThrow(/Another phone/);
    expect(() => checkDevicePin(qr, w.phone.info, w.second.info, '000000')).toThrow(KeyRefused);
    expect(() => checkDevicePin('{nonsense', w.phone.info, w.second.info, sas)).toThrow(KeyRefused);
  });

  it("the recovery agent's key must be in its anchored, signed list", () => {
    const w = clientSlot();
    const ops = ed25519.utils.randomSecretKey();
    const opsPub = new Uint8Array([0xed, ...ed25519.getPublicKey(ops)]);
    const listOf = (h: HolderInfo) =>
      new TextEncoder().encode(
        JSON.stringify({ keys: [{ holder: h.keyId, role: h.role, ed25519: bytesToHex(h.edPub).toUpperCase() }] }),
      );
    const bytes = listOf(w.agent.info);
    const list = { bytes, signerPub: opsPub, sig: ed25519.sign(serviceKeyListMessage(bytes), ops) };
    const service = { serviceAccount: 'rServiceAccount', opsAccount: deriveAddress(bytesToHex(opsPub).toUpperCase()) };
    const anchor = { account: service.serviceAccount, hash: sha256(bytes) };
    expect(() => checkServiceKey(w.agent.info, list, anchor, service)).not.toThrow();
    const other = party(3, 'recovery-agent', 'Recovery agent (Example Recovery Ltd)');
    expect(() => checkServiceKey(other.info, list, anchor, service)).toThrow(/not in the anchored key list/);
    expect(() => checkServiceKey(w.agent.info, list, { ...anchor, hash: randomBytes(32) }, service)).toThrow(
      /Recovery agent .*PIN_MISMATCH/,
    );
    const forged = {
      ...list,
      signerPub: new Uint8Array([0xed, ...ed25519.getPublicKey(ed25519.utils.randomSecretKey())]),
    };
    expect(() => checkServiceKey(w.agent.info, forged, anchor, service)).toThrow(/LIST_SIGNER_WRONG/);
  });
});

describe('P4.7-14 the transcript echo', () => {
  it('the relay shows the phone another round 1 than the others got: the DKG aborts before any share exists', async () => {
    const w = clientSlot();
    // The second device equivocates and the relay helps: a second, validly signed round 1 goes to the phone only.
    let alt: Signed | undefined;
    w.relay.deliver = (recipient, rows) =>
      recipient !== w.phone.info.identifier || !alt
        ? rows
        : rows.map((r) => {
            const m = decodeSigned(r.message).message;
            return m.kind === 'dkg.round1' && m.from === w.second.info.identifier
              ? { ...r, message: alt as Signed }
              : r;
          });
    const ctx = { dealId: DEAL, slot: 'A' as const, holders: w.holders };
    const [phone, second, agent] = await Promise.allSettled([
      run(w, w.phone, true),
      cheater(w, w.second, async (m) => {
        if (m.kind === 'dkg-r1') {
          const other = ed25519_FROST.DKG.round1(holderId(2), THRESHOLD);
          const fields = [...other.public.commitment, other.public.proofOfKnowledge, m.fields[3] as Uint8Array];
          alt = await signRelayMessage(toWire(ctx, { ...m, fields }), w.second.keys);
        }
        return m;
      }),
      run(w, w.agent, false),
    ]);
    expect((phone as PromiseRejectedResult).reason).toMatchObject({ code: 'TRANSCRIPT_MISMATCH' });
    for (const r of [second, agent]) expect(r.status).toBe('rejected');
    const dkg = w.relay.sessions.find((s) => s.purpose === 'dkg');
    expect(w.relay.kinds(dkg?.id as string)).not.toContain('dkg.round2');
  });
});

describe('P4.7-15 the slot test with all three pairs', () => {
  it('with one pair failing the slot is not ready, and the screen names the pair', async () => {
    const w = clientSlot();
    const events: DkgEvent[] = [];
    // The agent completes the DKG, then signs only with the second device (pair 2+3), never with the phone.
    const agent = (async () => {
      const h = new FrostHolder({
        index: 3,
        keys: w.agent.keys,
        dealId: DEAL,
        slot: 'A',
        holders: w.holders,
        relay: w.relay,
        cipher: xwingShareCipher,
        pinned: keyDirectory(w.holders),
      });
      const join = w.relay.joiner();
      const { key, ctx } = await h.dkg(await join('dkg'));
      const pair = [2, 3] as const;
      const sid = await join('sign', [w.second.info.identifier, w.agent.info.identifier]);
      await h.sign(sid, {
        msg: testSignMessage(ctx, key.public, pair),
        kind: 'tagged',
        share: key.secret,
        pub: key.public,
        check: testSignCheck(ctx, key.public, 3),
        pair,
      });
    })();
    const [phone] = await Promise.all([
      run(w, w.phone, true, { onEvent: (e) => events.push(e), timeoutMs: 2_500 }),
      run(w, w.second, false, { timeoutMs: 2_500 }),
      agent,
    ]);
    expect(phone.ready).toBe(false);
    expect(phone.pairs.map((p) => [p.names.join(' + '), p.ok])).toEqual([
      ['Your phone + Your second device', true],
      ['Your phone + Recovery agent (Example Recovery Ltd)', false],
      ['Your second device + Recovery agent (Example Recovery Ltd)', true],
    ]);
    expect('shares' in phone).toBe(false);
  });
});

describe('DKG under a misbehaving relay and a paused tab', () => {
  const allThree = (w: Slot, over: Partial<Parameters<typeof runSlotDkg>[0]> = {}) =>
    Promise.allSettled([run(w, w.phone, true, over), run(w, w.second, false, over), run(w, w.agent, false, over)]);

  it('reordered and repeated messages: the DKG still completes', async () => {
    const w = clientSlot();
    w.relay.deliver = (_to, rows) => [...rows, ...rows].reverse();
    const results = await allThree(w);
    expect(results.map((r) => r.status === 'fulfilled' && r.value.ready)).toEqual([true, true, true]);
  });

  it('a relay that drops every message to the phone: a timeout, an abort, and no shares anywhere', async () => {
    const w = clientSlot();
    w.relay.deliver = (to, rows) => (to === w.phone.info.identifier ? [] : rows);
    const results = await allThree(w, { timeoutMs: 1_500 });
    expect(results.map((r) => r.status)).toEqual(['rejected', 'rejected', 'rejected']);
    expect((results[0] as PromiseRejectedResult).reason).toMatchObject({ code: 'TIMEOUT' });
  });

  it('a tab paused in the background for a while (no deliveries) resumes and completes', async () => {
    const w = clientSlot();
    const resume = Date.now() + 1_500;
    w.relay.deliver = (to, rows) => (to === w.phone.info.identifier && Date.now() < resume ? [] : rows);
    const results = await allThree(w);
    expect(results.map((r) => r.status === 'fulfilled' && r.value.ready)).toEqual([true, true, true]);
  });
});
