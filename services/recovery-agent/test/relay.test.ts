// P3.9-02 to 06, 16, 17: the relay is a forwarder that refuses what it cannot authenticate, and the participants
// do not trust it either.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { FrostRelay, RelayStore } from '@legx/coordinator/frost/index';
import { decodeSigned, type RelayMessage } from '@legx/coordinator/frost/schema';
import { tupleHash } from '@legx/core/dealcore';
import { enrollmentSigned, FrostError, type FrostMsg, holderId, u32 } from '@legx/core/frost';
import { dkgStart, judgeComplaint } from '@legx/core/frostDkg';
import { openPackage } from '@legx/core/pq';
import { ed25519 } from '@noble/curves/ed25519.js';
import fc from 'fast-check';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { xwingShareCipher } from '../src/cipher.ts';
import { CeremonyError } from '../src/holder.ts';
import { openRelayed, type Signed, signRelayMessage, toWire } from '../src/wire.ts';
import { slotSetup } from './support/setup.ts';
import { TamperRelay } from './support/tamper.ts';
import { hex, type Member, makeMember, makeWorld, must, type World } from './support/world.ts';

let w: World;
beforeAll(async () => {
  w = await makeWorld();
});
afterAll(async () => {
  await w.close();
});

const header = (sessionId: string, from: string) => ({ session_id: sessionId, deal_id: w.dealId, slot: w.slot, from });
const newSession = () =>
  w.relay.openSession({ dealId: w.dealId, slot: w.slot, purpose: 'dkg', participants: w.participants() });
const echo = (sessionId: string, i: number): RelayMessage =>
  ({
    ...header(sessionId, holderId(i)),
    kind: 'dkg.echo',
    transcript_hash: hex(new Uint8Array(32).fill(7)),
  }) as RelayMessage;
const point = hex(new Uint8Array(32).fill(1));
const round1 = (sessionId: string, i: number): RelayMessage =>
  ({
    ...header(sessionId, holderId(i)),
    kind: 'dkg.round1',
    commitment: [point, point],
    proof_of_knowledge: '00'.repeat(64),
    kem_pub: Buffer.alloc(1216).toString('base64'),
  }) as RelayMessage;
const sendAs = (i: number, m: RelayMessage) => w.relay.send(signRelayMessage(m, (w.members[i - 1] as Member).keys));
const code = async (p: Promise<unknown>) => {
  try {
    await p;
    return 'sent';
  } catch (e) {
    return (e as { code?: string }).code ?? String(e);
  }
};

describe('the relay only forwards (P3.9-02)', () => {
  it('imports no signing, share or round function, and stores the exact bytes it was given', async () => {
    const dir = fileURLToPath(new URL('../../coordinator/src/frost/', import.meta.url));
    for (const f of ['relay.ts', 'store.ts', 'routes.ts', 'schema.ts', 'index.ts']) {
      const src = readFileSync(dir + f, 'utf8');
      expect(src, f).not.toMatch(
        /frostDkg|frostRefresh|frostRepair|frostRules|SigningSession|signShare|aggregate|dkgStart|mldsaSign|ed25519\.sign|sign\(/,
      );
    }
    const sessionId = await newSession();
    const signed = signRelayMessage(round1(sessionId, 1), (w.members[0] as Member).keys);
    await w.relay.send(signed);
    const [stored] = await w.relay.transcript(sessionId);
    expect(stored?.message).toEqual(signed);
  });
});

describe('enrollment signatures against pinned keys (P3.9-03)', () => {
  it('refuses a bad, missing, unpinned or mismatched key; nobody else sees the message', async () => {
    const sessionId = await newSession();
    const good = signRelayMessage(round1(sessionId, 1), (w.members[0] as Member).keys);
    const flip = (b64: string): never => {
      const b = Buffer.from(b64, 'base64');
      b[3] = (b[3] as number) ^ 1;
      return b.toString('base64') as never;
    };
    const [ed, pq] = good.signatures;
    expect(await code(w.relay.send({ ...good, signatures: [{ ...ed, sig: flip(ed.sig) }, pq] }))).toBe(
      'relay_bad_signature',
    );
    expect(await code(w.relay.send({ ...good, signatures: [ed, { ...pq, sig: flip(pq.sig) }] }))).toBe(
      'relay_bad_signature',
    );
    // missing: only one signature
    expect(await code(w.relay.send({ ...good, signatures: [ed] } as never))).not.toBe('sent');
    // payload changed after signing
    const payload = JSON.parse(Buffer.from(good.payload, 'base64').toString());
    payload.proof_of_knowledge = '11'.repeat(64);
    expect(
      await code(w.relay.send({ ...good, payload: Buffer.from(JSON.stringify(payload)).toString('base64') as never })),
    ).toBe('relay_bad_signature');
    // an unpinned key: a stranger names itself holder 1
    const stranger = makeMember(1, 'A', 'phone');
    expect(await code(w.relay.send(signRelayMessage(round1(sessionId, 1), stranger.keys)))).toBe('relay_key_mismatch');
    // a pinned key sends as another holder
    expect(await code(sendAs(2, round1(sessionId, 1)))).toBe('relay_key_mismatch');
    // wrong deal in the header
    expect(
      await code(
        sendAs(1, { ...round1(sessionId, 1), deal_id: '0190a000-0000-7000-8000-0000000000aa' } as RelayMessage),
      ),
    ).toBe('relay_wrong_deal_or_slot');
    // nothing was stored
    expect(await w.relay.transcript(sessionId)).toHaveLength(0);
    expect(await code(w.relay.send(good))).toBe('sent');
    expect((await w.relay.receive(sessionId, holderId(2), -1)).length).toBe(1);
    expect((await w.relay.receive(sessionId, holderId(1), -1)).length).toBe(0);
  });

  it('refuses a key that is not in enrollment_key even when it signs as a listed holder', async () => {
    const stranger = makeMember(1, 'A', 'phone');
    await expect(
      w.relay.openSession({
        dealId: w.dealId,
        slot: w.slot,
        purpose: 'dkg',
        participants: [
          { identifier: holderId(1), keyId: stranger.keys.keyId, role: 'phone' },
          ...w.participants().slice(1),
        ],
      }),
    ).rejects.toMatchObject({ code: 'relay_key_not_pinned' });
  });

  it('keeps the rounds in order and refuses duplicates and strangers', async () => {
    const sessionId = await newSession();
    expect(await code(sendAs(1, echo(sessionId, 1)))).toBe('relay_out_of_order');
    expect(await code(sendAs(1, round1(sessionId, 1)))).toBe('sent');
    expect(await code(sendAs(1, round1(sessionId, 1)))).toBe('relay_duplicate');
    expect(await code(sendAs(1, { ...round1(sessionId, 1), kind: 'sign.commit' } as never))).not.toBe('sent');
    expect(await w.relay.receive('00'.repeat(32) as never, holderId(1) as never, -1).catch((e) => e.code)).toBe(
      'relay_session_unknown',
    );
  });
});

describe('a hostile relay (P3.9-04)', () => {
  it('a single-byte change of any relayed message is detected by the receiver', async () => {
    const sessionId = await newSession();
    const signed = signRelayMessage(round1(sessionId, 1), (w.members[0] as Member).keys);
    const ctx = { dealId: w.dealId, slot: w.slot, holders: w.members.map((m) => m.info) };
    expect(() => openRelayed(ctx, signed)).not.toThrow();
    const pieces = (s: Signed): string[] => [s.payload, s.signatures[0].sig, s.signatures[1].sig];
    await fc.assert(
      fc.property(fc.integer({ min: 0, max: 2 }), fc.nat(), fc.integer({ min: 1, max: 255 }), (which, at, xor) => {
        const raw = Buffer.from(pieces(signed)[which] as string, 'base64');
        raw[at % raw.length] = (raw[at % raw.length] as number) ^ xor;
        const bad = { ...signed, signatures: [...signed.signatures] as Signed['signatures'] };
        if (which === 0) bad.payload = raw.toString('base64') as never;
        else bad.signatures[which - 1] = { ...bad.signatures[which - 1], sig: raw.toString('base64') } as never;
        try {
          openRelayed(ctx, bad);
        } catch (e) {
          return e instanceof FrostError || (e as Error).name === 'WireError';
        }
        return false;
      }),
      { numRuns: 60 },
    );
  });

  it('a message replayed into another session is refused by the relay and by the receiver', async () => {
    const a = await newSession();
    const b = await newSession();
    const signed = signRelayMessage(round1(a, 1), (w.members[0] as Member).keys);
    const ctx = { dealId: w.dealId, slot: w.slot, holders: w.members.map((m) => m.info) };
    const opened = openRelayed(ctx, signed);
    // the receiver of session b would hand the core a message of session a: its session id differs
    expect(() => w.holder(2).directory(Buffer.from(b, 'hex'))).not.toThrow();
    expect(Buffer.from(opened.core.session).toString('hex')).toBe(a);
    expect(Buffer.from(opened.core.session).toString('hex')).not.toBe(b);
    // the same bytes are accepted once by session a and cannot be forced into session b
    expect(await w.relay.send(signed).then(() => 'sent')).toBe('sent');
    expect(await w.relay.transcript(b)).toHaveLength(0);
  });

  it('a relay that drops a message stalls a holder (timeout), it does not make it proceed', async () => {
    const sessionId = await newSession();
    const h2 = w.holder(2, { timeoutMs: 150 });
    await sendAs(1, round1(sessionId, 1));
    await expect(h2.collect(sessionId, 'dkg.round1', 2)).rejects.toBeInstanceOf(CeremonyError);
  });
});

describe('DKG hardening', () => {
  it('P3.9-05 round-2 shares are sealed to the receiver: the relay cannot open them, the receiver does', async () => {
    const s = await slotSetup(w);
    const all = (await w.relay.transcript(s.sessionId)).map((r) => decodeSigned(r.message));
    const r2 = all.filter((d) => d.message.kind === 'dkg.round2');
    expect(r2).toHaveLength(6);
    const stored = JSON.stringify(await w.relay.transcript(s.sessionId));
    for (const k of s.keys) expect(stored).not.toContain(hex(k.secret.signingShare));
    // a box opens only with the receiver's session key: a holder-2 key does not open holder-1's box
    const toHolder1 = must(r2.find((d) => d.message.kind === 'dkg.round2' && d.message.to === holderId(1)));
    const box = (toHolder1.message as Extract<RelayMessage, { kind: 'dkg.round2' }>).box;
    const wrong = xwingShareCipher.keygen();
    const opened = await openPackage(
      'share',
      { suite: 'hpke-xwing-v1', enc: Buffer.from(box.enc, 'base64'), ct: Buffer.from(box.ciphertext, 'base64') },
      wrong.secretKey,
      new Uint8Array(),
    );
    expect(opened.ok).toBe(false);
    expect(Buffer.from(box.enc, 'base64')).toHaveLength(1120);
  });

  it('P3.9-16 a relay that shows one holder a different round-1 message makes the echoes differ; the DKG aborts, no share is sent', async () => {
    const w3 = await makeWorld();
    try {
      const session = await w3.relay.openSession({
        dealId: w3.dealId,
        slot: w3.slot,
        purpose: 'dkg',
        participants: w3.participants(),
      });
      const ctx = w3.holder(1).directory(Buffer.from(session, 'hex'));
      // holder 3 equivocates: a second, validly signed round-1 message with fresh randomness
      const alt = dkgStart(ctx, 3, {
        signer: { sign: (m) => ed25519.sign(m, (w3.members[2] as Member).keys.edSecret) },
        cipher: xwingShareCipher,
        pinned: w3.registry.check,
      });
      const altWire = signRelayMessage(
        toWire({ dealId: w3.dealId, slot: w3.slot, holders: w3.members.map((m) => m.info) }, alt.out[0] as FrostMsg),
        (w3.members[2] as Member).keys,
      );
      const lying = new TamperRelay(w3.relay, (recipient, r) =>
        recipient === holderId(1) &&
        decodeSigned(r.message).message.kind === 'dkg.round1' &&
        decodeSigned(r.message).message.from === holderId(3)
          ? { ...r, message: altWire }
          : r,
      );
      const results = await Promise.allSettled(
        [1, 2, 3].map((i) =>
          w3.holder(i, i === 1 ? { relay: lying, timeoutMs: 3000 } : { timeoutMs: 3000 }).dkg(session),
        ),
      );
      expect(results.every((r) => r.status === 'rejected')).toBe(true);
      const reasons = results.map((r) => String((r as PromiseRejectedResult).reason));
      expect(reasons.some((x) => /TRANSCRIPT_MISMATCH/.test(x))).toBe(true);
      const kinds = (await w3.relay.transcript(session)).map((m) => decodeSigned(m.message).message.kind);
      expect(kinds).not.toContain('dkg.round2');
      expect(reasons.join()).not.toMatch(/[0-9a-f]{64}/); // names no share or key
    } finally {
      await w3.close();
    }
  });

  it('P3.9-17 a bad round-2 share: the receiver complains, everyone sees the sender cheated, the DKG aborts', async () => {
    const w3 = await makeWorld();
    try {
      const session = await w3.relay.openSession({
        dealId: w3.dealId,
        slot: w3.slot,
        purpose: 'dkg',
        participants: w3.participants(),
      });
      const sid = Buffer.from(session, 'hex');
      const badShare = async (m: FrostMsg): Promise<FrostMsg> => {
        if (m.to !== 1) return m;
        const r1 = (await w3.relay.transcript(session))
          .map((r) => decodeSigned(r.message).message)
          .find((x) => x.kind === 'dkg.round1' && x.from === holderId(1)) as Extract<
          RelayMessage,
          { kind: 'dkg.round1' }
        >;
        const aad = tupleHash('legx/frost-dkg-r2/v1', [sid, u32(3), u32(1)]);
        const ct = await xwingShareCipher.seal(
          new Uint8Array(Buffer.from(r1.kem_pub, 'base64')),
          aad,
          new Uint8Array(32).fill(5),
        );
        return enrollmentSigned(
          { sign: (b) => ed25519.sign(b, (w3.members[2] as Member).keys.edSecret) },
          { session: m.session, kind: m.kind, from: m.from, to: m.to, fields: [ct] },
        );
      };
      const results = await Promise.allSettled(
        [1, 2, 3].map((i) =>
          w3.holder(i, { timeoutMs: 5000, complaintWindowMs: 1500 }).dkg(session, i === 3 ? { tamper: badShare } : {}),
        ),
      );
      expect(results.every((r) => r.status === 'rejected')).toBe(true);
      for (const r of results)
        expect((r as PromiseRejectedResult).reason).toMatchObject({ code: 'DKG_COMPLAINT', culprit: 3 });
      // an outside observer judges the published complaint from the relay transcript alone
      const msgs = (await w3.relay.transcript(session)).map(
        (r) =>
          openRelayed({ dealId: w3.dealId, slot: w3.slot, holders: w3.members.map((m) => m.info) }, r.message).core,
      );
      const verdict = await judgeComplaint(
        ctx(w3, sid),
        msgs.filter((m) => m.kind === 'dkg-r1'),
        msgs.find((m) => m.kind === 'dkg-complaint') as FrostMsg,
        xwingShareCipher,
      );
      expect(verdict.guilty).toBe(3);
    } finally {
      await w3.close();
    }
  });
});

const ctx = (w3: World, sid: Uint8Array) => w3.holder(1).directory(sid);

describe('stalls, crashes and restarts (P3.9-04 in all directions)', () => {
  /** A holder whose process dies on its Nth send. */
  const crashing = (inner: World['relay'], dieOnSend: number) => {
    let sends = 0;
    return {
      send: (m: Parameters<World['relay']['send']>[0]) =>
        sends++ >= dieOnSend ? Promise.reject(new Error('process killed')) : inner.send(m),
      receive: inner.receive.bind(inner),
    };
  };

  it.each([0, 1, 2, 3])(
    'a holder that dies on its send number %i: the others fail, a fresh DKG then succeeds',
    async (dieOnSend) => {
      const w3 = await makeWorld();
      try {
        const open = () =>
          w3.relay.openSession({ dealId: w3.dealId, slot: w3.slot, purpose: 'dkg', participants: w3.participants() });
        const first = await open();
        const results = await Promise.allSettled([
          w3.holder(1, { timeoutMs: 1500 }).dkg(first),
          w3.holder(2, { timeoutMs: 1500 }).dkg(first),
          w3.holder(3, { timeoutMs: 1500, relay: crashing(w3.relay, dieOnSend) as never }).dkg(first),
        ]);
        // before the last round-2 message nobody can finish; after it, a holder that already has all its shares may
        // return a key, but the dead holder never test-signs, so the slot is not set up (P3.9-18)
        if (dieOnSend < 3) expect(results.every((r) => r.status === 'rejected')).toBe(true);
        else expect(results.some((r) => r.status === 'rejected')).toBe(true);
        const kinds = (await w3.relay.transcript(first)).map((m) => decodeSigned(m.message).message.kind);
        if (dieOnSend < 3) expect(kinds).not.toContain('dkg.complaint');
        // the round restarts cleanly in a new session, with fresh randomness
        const second = await open();
        const runs = await Promise.all([1, 2, 3].map((i) => w3.holder(i).dkg(second)));
        expect(new Set(runs.map((r) => hex(r.key.public.commitments[0] as Uint8Array))).size).toBe(1);
      } finally {
        await w3.close();
      }
    },
  );

  it('a restarted relay (a new process over the same database) continues a session', async () => {
    const w3 = await makeWorld();
    try {
      const session = await w3.relay.openSession({
        dealId: w3.dealId,
        slot: w3.slot,
        purpose: 'dkg',
        participants: w3.participants(),
      });
      const run = w3
        .holder(1)
        .dkg(session)
        .catch(() => undefined);
      await new Promise((r) => setTimeout(r, 50));
      const restarted = new FrostRelay(w3.deps, new RelayStore(w3.deps.db));
      const before = await w3.relay.transcript(session);
      expect((await restarted.transcript(session)).map((m) => m.seq)).toEqual(before.map((m) => m.seq));
      const holders = [2, 3].map((i) => w3.holder(i, { relay: restarted }));
      const runs = await Promise.all([run, ...holders.map((h) => h.dkg(session))]);
      expect(runs.every((r) => r?.key)).toBe(true);
    } finally {
      await w3.close();
    }
  });
});
