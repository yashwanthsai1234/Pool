// P3.9-09 to 11, 20, 24 to 27 and the collusion refusals: the recovery agent as holder 3 of a client slot.
import { verifyEd25519Strict } from '@legx/core/frost';
import {
  MemoryNonceLedger,
  RecoveryError,
  type RecoveryState,
  recoveryCancelMessage,
  releaseShare,
} from '@legx/core/frostRules';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PgNonceLedger } from '../src/nonces.ts';
import { Refusal } from '../src/recovery.ts';
import { VaultError } from '../src/vault.ts';
import { type AgentWorld, HOUR, makeAgentWorld, T0 } from './support/agent.ts';
import { type Member, makeWorld, type World } from './support/world.ts';

let w: World;
let a: AgentWorld;
beforeAll(async () => {
  w = await makeWorld();
  a = await makeAgentWorld(w);
});
afterAll(async () => {
  await w.close();
});

const allow = () => ({ ok: true as const });
const ids = () => [2, 3].map((i) => (w.members[i - 1] as Member).info.identifier) as [string, string];

/** The second authenticator (holder 2) asks the agent for an exit signature; returns both outcomes. */
async function askAgent(msg: Uint8Array) {
  const session = await w.relay.openSession({
    dealId: w.dealId,
    slot: 'A',
    purpose: 'sign',
    participants: w.participants(),
    pair: ids(),
  });
  const client = w.holder(2, { timeoutMs: 4000 }).sign(session, {
    msg,
    kind: 'xrpl-multisign',
    share: a.setup.keys[1]?.secret as never,
    pub: a.setup.pub,
    pair: [2, 3],
    check: allow,
  });
  const agentSide = a.agent.sign(w.dealId, 'A', session, [2, 3]);
  const [c, g] = await Promise.allSettled([client, agentSide]);
  return { client: c, agent: g, session };
}
const reason = (r: PromiseSettledResult<unknown>) =>
  r.status === 'rejected' ? (r.reason as { code?: string }).code : 'ok';
const refusals = () => a.evidence.ofKind('frost.refused').map((e) => e.data.reason);

describe('agent state (P3.9-11)', () => {
  it('holds exactly one share per slot, encrypted at rest', async () => {
    expect(await a.vault.count(w.dealId, 'A')).toBe(1);
    const raw = await a.vault.raw(w.dealId, 'A');
    const stored = await a.vault.get(w.dealId, 'A');
    expect(raw).toBeDefined();
    expect(Buffer.from(raw as Uint8Array).toString('hex')).not.toContain(
      Buffer.from(stored?.share.signingShare as Uint8Array).toString('hex'),
    );
    // a second share of the same slot, and a share of another holder, are refused
    await expect(a.vault.insert(w.dealId, 'A', stored as never)).rejects.toMatchObject({ code: 'SLOT_TAKEN' });
    await expect(
      a.vault.insert(w.dealId, 'B', {
        ...(stored as never as object),
        share: { identifier: a.setup.keys[0]?.secret.identifier, signingShare: new Uint8Array(32) },
      } as never),
    ).rejects.toBeInstanceOf(VaultError);
    // a row moved to another slot or edited does not open
    await sql`update recovery_agent_share set slot = 'B' where deal_id = ${w.dealId}`.execute(w.db.kysely);
    await expect(a.vault.get(w.dealId, 'B')).rejects.toMatchObject({ code: 'TAMPERED' });
    await sql`update recovery_agent_share set slot = 'A' where deal_id = ${w.dealId}`.execute(w.db.kysely);
    expect((await a.vault.get(w.dealId, 'A'))?.epoch).toBe(0);
  });
});

describe('nonce marking (P3.9-20)', () => {
  it('two concurrent requests with one commitment id: exactly one gets a share; a crash after the mark leaves it used', async () => {
    const mk = (hash: string) => new PgNonceLedger(w.deps.db, { keyId: 'agent', dealId: w.dealId, messageHash: hash });
    const id = 'ab'.repeat(32);
    const results = await Promise.allSettled(
      [1, 2, 3, 4, 5].map(() => releaseShare(mk('00'.repeat(32)), id, () => new Uint8Array([1]))),
    );
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    // a crash between the mark and the release
    const crash = 'cd'.repeat(32);
    await expect(
      releaseShare(mk('11'.repeat(32)), crash, () => {
        throw new Error('crash');
      }),
    ).rejects.toThrow('crash');
    await expect(releaseShare(mk('11'.repeat(32)), crash, () => new Uint8Array([1]))).rejects.toMatchObject({
      code: 'NONCE_USED',
    });
    expect(MemoryNonceLedger).toBeDefined();
  });
});

describe('client recovery start (P3.9-24)', () => {
  it('starts only with a fresh proof, the onboarding identifier and a face match', async () => {
    const phone = await a.newPhone();
    const key = phone.keys.keyId;
    const start = (p: ReturnType<typeof a.proof>) =>
      a.recoveries.startClient({ dealId: w.dealId, slot: 'A', newKeyId: key, proof: p });
    const code = async (p: Promise<unknown>) => (await p.then(() => 'started').catch((e) => e.code)) as string;
    expect(await code(start(a.proof({ newKeyId: key, identifier: 'someone-else' })))).toBe('IDENTIFIER_MISMATCH');
    expect(await code(start(a.proof({ newKeyId: key, faceMatch: false })))).toBe('FACE_MATCH_MISSING');
    // a proof made from copied chip data: right identifier, no face match
    expect(await code(start(a.proof({ newKeyId: key, faceMatch: false, identifier: a.deal.onboardingId })))).toBe(
      'FACE_MATCH_MISSING',
    );
    expect(await code(start(a.proof({ newKeyId: key, ageMs: 11 * 60_000 })))).toBe('PROOF_STALE');
    // a proof bound to another key, and a result the verifier never recorded
    expect(await code(start(a.proof({ newKeyId: key, bound: '00'.repeat(32) })))).toBe('PROOF_NOT_BOUND');
    const forged = {
      ...a.proof({ newKeyId: key }),
      uniqueIdentifier: a.deal.onboardingId,
      proofSha256: 'ee'.repeat(32),
    };
    expect(await code(start(forged as never))).toBe('PROOF_NOT_VERIFIED');
    // an unpinned new key
    expect(
      await code(
        a.recoveries.startClient({
          dealId: w.dealId,
          slot: 'A',
          newKeyId: 'stranger',
          proof: a.proof({ newKeyId: 'stranger' }),
        }),
      ),
    ).toBe('NEW_KEY_NOT_PINNED');
    expect(a.evidence.ofKind('frost.recovery.requested')).toHaveLength(0);
    const ok = await a.recoveries.startClient({
      dealId: w.dealId,
      slot: 'A',
      newKeyId: key,
      proof: a.proof({ newKeyId: key }),
    });
    expect(ok.state).toBe('waiting');
    expect(a.evidence.ofKind('frost.recovery.requested')).toHaveLength(1);
    expect(a.notices.map((n) => n.to).sort()).toEqual(['lawyerA', 'lawyerB', 'old-device']);
    // one recovery at a time
    expect(await code(start(a.proof({ newKeyId: key })))).toBe('RECOVERY_IN_PROGRESS');
  });
});

describe('the 72-hour delay and the signature (P3.9-26, 09, 10)', () => {
  it('no share before hour 72; at hour 72 the agent signs an allowed exit and logs frost.signed', async () => {
    const { msg } = a.exit();
    a.clock.now += 71 * HOUR;
    const early = await askAgent(msg);
    expect(reason(early.agent)).toBe('RECOVERY_DELAY');
    expect(reason(early.client)).toBe('SESSION_ABORTED');
    expect(a.evidence.ofKind('frost.signed')).toHaveLength(0);
    expect(refusals()).toContain('RECOVERY_DELAY');
    a.clock.now += HOUR;
    const late = await askAgent(msg);
    expect(late.agent.status).toBe('fulfilled');
    expect(late.client.status).toBe('fulfilled');
    const sig = (late.agent as PromiseFulfilledResult<Uint8Array>).value;
    expect(verifyEd25519Strict(sig, msg, a.setup.groupKey)).toBe(true);
    const signed = a.evidence.ofKind('frost.signed');
    expect(signed).toHaveLength(1);
    expect(signed[0]?.data.signature).toBe(Buffer.from(sig).toString('hex'));
    expect(a.evidence.ofKind('frost.recovery.authorized')).toHaveLength(1);
    // I-E6: the recovery pair's signature is logged with the two holder roles that took part.
    const recSigned = a.evidence.ofKind('frost.recovery.signed');
    expect(recSigned).toHaveLength(1);
    const data = recSigned[0]?.data as { slot: string; recovery_id: string; holder_roles: string[] };
    expect(data.slot).toBe(a.evidence.ofKind('frost.signed')[0]?.data.slot);
    expect(data.recovery_id).toBe(a.evidence.ofKind('frost.recovery.authorized')[0]?.data.recovery_id);
    expect(data.holder_roles).toHaveLength(2);
    expect(data.holder_roles).toContain('recovery-agent');
    expect(a.notices.some((n) => n.kind === 'recovery.ready')).toBe(true);
  });

  it('refuses an exit to a destination that is not sealed, a tagged message, and a lawyer slot', async () => {
    const bad = await askAgent(a.exit('attacker').msg);
    expect(reason(bad.agent)).toBe('MESSAGE_REFUSED');
    expect(a.evidence.ofKind('frost.signed')).toHaveLength(1); // still only the first
    await expect(a.agent.sign(w.dealId, 'LA', 'aa'.repeat(32), [2, 3])).rejects.toMatchObject({ code: 'LAWYER_SLOT' });
    await expect(a.agent.sign(w.dealId, 'LB', 'aa'.repeat(32), [2, 3])).rejects.toMatchObject({ code: 'LAWYER_SLOT' });
    await expect(a.agent.sign(w.dealId, 'B', 'aa'.repeat(32), [2, 3])).rejects.toMatchObject({ code: 'NO_SHARE' });
    expect(refusals()).toEqual(expect.arrayContaining(['MESSAGE_REFUSED', 'LAWYER_SLOT', 'NO_SHARE']));
  });

  it('refuses when the deal is in a state that does not allow signing', async () => {
    a.deal.allows = false;
    const r = await askAgent(a.exit().msg);
    expect(reason(r.agent)).toBe('DEAL_STATE');
    a.deal.allows = true;
  });
});

describe('cancel (P3.9-27) and collusion', () => {
  it('the old device cancels during the delay: the recovery shares never sign; both lawyers are told', async () => {
    const w2 = await makeWorld();
    try {
      const a2 = await makeAgentWorld(w2);
      const phone = await a2.newPhone();
      const rec = await a2.recoveries.startClient({
        dealId: w2.dealId,
        slot: 'A',
        newKeyId: phone.keys.keyId,
        proof: a2.proof({ newKeyId: phone.keys.keyId }),
      });
      // the old device is holder 2 (the second authenticator's key stands in for the old phone's pinned key)
      const old = w2.members[1] as Member;
      const state = {
        recoveryId: rec.recoveryId,
        slot: 'A',
        status: 'pending',
        startedAt: a2.clock.now,
        records: [],
      } as RecoveryState;
      const sig = ed25519.sign(recoveryCancelMessage(state), old.keys.edSecret);
      a2.clock.now += 10 * HOUR;
      // a key that is not a pinned device is refused
      const stranger = ed25519.utils.randomSecretKey();
      await expect(
        a2.recoveries.cancel({
          recoveryId: rec.recoveryId,
          sig: ed25519.sign(recoveryCancelMessage(state), stranger),
          oldDevicePub: new Uint8Array([0xed, ...ed25519.getPublicKey(stranger)]),
        }),
      ).rejects.toMatchObject({ code: 'CANCEL_KEY_NOT_PINNED' });
      const view = await a2.recoveries.cancel({ recoveryId: rec.recoveryId, sig, oldDevicePub: old.info.edPub });
      expect(view.state).toBe('cancelled');
      expect(a2.evidence.ofKind('frost.recovery.cancelled')).toHaveLength(1);
      expect(a2.notices.filter((n) => n.kind === 'recovery.cancelled').map((n) => n.to)).toEqual(
        expect.arrayContaining(['lawyerA', 'lawyerB']),
      );
      a2.clock.now += 100 * HOUR;
      await expect(a2.recoveries.authorize(w2.dealId, 'A')).rejects.toBeInstanceOf(RecoveryError);
      // even after hour 72 the cancelled recovery signs nothing
      expect(await a2.recoveries.get(rec.recoveryId).then((v) => v.state)).toBe('cancelled');
    } finally {
      await w2.close();
    }
  });

  it('collusion: the agent operator and one client share cannot sign without a recovery', async () => {
    const w2 = await makeWorld();
    try {
      const a2 = await makeAgentWorld(w2);
      const pair = [1, 3].map((i) => (w2.members[i - 1] as Member).info.identifier) as [string, string];
      const attempt = async (msg: Uint8Array) => {
        const session = await w2.relay.openSession({
          dealId: w2.dealId,
          slot: 'A',
          purpose: 'sign',
          participants: w2.participants(),
          pair,
        });
        const colluder = w2.holder(1, { timeoutMs: 3000 }).sign(session, {
          msg,
          kind: 'xrpl-multisign',
          share: a2.setup.keys[0]?.secret as never,
          pub: a2.setup.pub,
          pair: [1, 3],
          check: allow,
        });
        const [c, g] = await Promise.allSettled([colluder, a2.agent.sign(w2.dealId, 'A', session, [1, 3])]);
        return { c, g };
      };
      const exit = a2.exit('attacker').msg;
      expect(reason((await attempt(exit)).g)).toBe('NO_RECOVERY');
      expect(a2.evidence.ofKind('frost.signed')).toHaveLength(0);
      const phone = await a2.newPhone();
      await a2.recoveries.startClient({
        dealId: w2.dealId,
        slot: 'A',
        newKeyId: phone.keys.keyId,
        proof: a2.proof({ newKeyId: phone.keys.keyId }),
      });
      expect(reason((await attempt(exit)).g)).toBe('RECOVERY_DELAY');
      a2.clock.now += 73 * HOUR;
      expect(reason((await attempt(exit)).g)).toBe('MESSAGE_REFUSED'); // not a sealed payout
      expect(a2.evidence.ofKind('frost.signed')).toHaveLength(0);
      expect(a2.evidence.ofKind('frost.refused').map((e) => e.data.reason)).toEqual([
        'NO_RECOVERY',
        'RECOVERY_DELAY',
        'MESSAGE_REFUSED',
      ]);
    } finally {
      await w2.close();
    }
  });
});

describe('a refusal needs a reason', () => {
  it('Refusal is a typed error', () => {
    expect(new Refusal('NO_RECOVERY').code).toBe('NO_RECOVERY');
  });
});

describe('T-U-31d at service level: the delay boundary and the cancel window', () => {
  it('72 h minus one second is refused, 72 h exactly is allowed; a cancel at the end of the delay is too late', async () => {
    const w2 = await makeWorld();
    try {
      const a2 = await makeAgentWorld(w2);
      const phone = await a2.newPhone();
      const rec = await a2.recoveries.startClient({
        dealId: w2.dealId,
        slot: 'A',
        newKeyId: phone.keys.keyId,
        proof: a2.proof({ newKeyId: phone.keys.keyId }),
      });
      a2.clock.now += 72 * HOUR - 1000;
      await expect(a2.recoveries.authorize(w2.dealId, 'A')).rejects.toMatchObject({ code: 'RECOVERY_DELAY' });
      expect((await a2.recoveries.get(rec.recoveryId)).state).toBe('waiting');
      a2.clock.now += 1000;
      expect((await a2.recoveries.authorize(w2.dealId, 'A')).state).toBe('ready');
      // a cancel after the delay is refused
      const old = w2.members[1] as Member;
      const sig = ed25519.sign(
        recoveryCancelMessage({ recoveryId: rec.recoveryId, slot: 'A', status: 'pending', startedAt: T0, records: [] }),
        old.keys.edSecret,
      );
      await expect(
        a2.recoveries.cancel({ recoveryId: rec.recoveryId, sig, oldDevicePub: old.info.edPub }),
      ).rejects.toBeInstanceOf(RecoveryError);
      // every step is an evidence record
      expect(a2.evidence.events.map((e) => e.kind)).toEqual(['frost.recovery.requested', 'frost.recovery.authorized']);
    } finally {
      await w2.close();
    }
  });
});
