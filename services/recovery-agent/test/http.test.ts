// The HTTP surfaces: the relay routes (frost.openSession, send, receive, status) and the agent's recovery routes,
// both behind the signed-request authentication of OD-5.

import { pinEnrollmentKey } from '@legx/coordinator/enroll';
import { register as registerRelay } from '@legx/coordinator/frost/index';
import { lawyerRecoveryMessage, recoveryCancelMessage } from '@legx/core/frostRules';
import { toBase64 } from '@legx/core/pq';
import { ed25519 } from '@noble/curves/ed25519.js';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { deriveAddress } from 'xrpl';
import { register as registerAgent } from '../src/index.ts';
import { buildKeyList, signKeyList } from '../src/keylist.ts';
import { signRelayMessage } from '../src/wire.ts';
import { type AgentWorld, HOUR, makeAgentWorld, T0 } from './support/agent.ts';
import { signedRequest } from './support/http.ts';
import { hex, type Member, makeMember, makeWorld, type World } from './support/world.ts';

let w: World;
let a: AgentWorld;
let app: FastifyInstance;
beforeAll(async () => {
  w = await makeWorld();
  a = await makeAgentWorld(w);
  app = Fastify();
  await registerRelay(app, w.deps, { signTimeoutMs: 30_000 });
  const accountKey = ed25519.utils.randomSecretKey();
  const list = signKeyList(buildKeyList([]), accountKey);
  await registerAgent(app, {
    auth: w.deps,
    recoveries: a.recoveries,
    keyList: () => ({ ...list, anchorTx: 'AB'.repeat(32) }),
  });
  await app.ready();
});
afterAll(async () => {
  await app.close();
  await w.close();
});

const m = (i: number) => w.members[i - 1] as Member;
// biome-ignore lint/suspicious/noExplicitAny: the JSON answer of the API under test, read freely
const json = (r: { body: string }) => JSON.parse(r.body) as Record<string, any>;

describe('relay routes', () => {
  it('open, send, receive and status work for the holders, and refuse everyone else', async () => {
    const open = await app.inject(
      signedRequest(m(1).keys, 'POST', `/deals/${w.dealId}/frost-sessions`, {
        slot: 'A',
        purpose: 'dkg',
        participants: w.participants(),
      }),
    );
    expect(open.statusCode, open.body).toBe(200);
    const sessionId = json(open).sessionId as string;
    const msg = signRelayMessage(
      {
        session_id: sessionId,
        deal_id: w.dealId,
        slot: 'A',
        from: m(1).info.identifier,
        kind: 'abort',
        reason: 'TEST',
      } as never,
      m(1).keys,
    );
    // no signature, a signature of a stranger, and a message signed by another holder are refused
    expect(
      (
        await app.inject(
          signedRequest(
            m(1).keys,
            'POST',
            `/frost/sessions/${sessionId}/messages`,
            { message: msg },
            { omitAuth: true },
          ),
        )
      ).statusCode,
    ).toBe(401);
    const stranger = { keyId: 'nobody', edSecret: ed25519.utils.randomSecretKey(), pqSecret: m(1).keys.pqSecret };
    expect(
      (await app.inject(signedRequest(stranger, 'POST', `/frost/sessions/${sessionId}/messages`, { message: msg })))
        .statusCode,
    ).toBe(401);
    expect(
      (await app.inject(signedRequest(m(2).keys, 'POST', `/frost/sessions/${sessionId}/messages`, { message: msg })))
        .statusCode,
    ).toBe(403);
    const sent = await app.inject(
      signedRequest(m(1).keys, 'POST', `/frost/sessions/${sessionId}/messages`, { message: msg }),
    );
    expect(sent.statusCode, sent.body).toBe(200);
    expect(json(sent).seq).toBe(0);
    // receive: only as yourself
    const url = (id: string, recipient: string) => `/frost/sessions/${id}/messages?recipient=${recipient}&afterSeq=-1`;
    const mine = await app.inject(signedRequest(m(2).keys, 'GET', url(sessionId, m(2).info.identifier)));
    expect(mine.statusCode, mine.body).toBe(200);
    expect(json(mine).messages).toHaveLength(1);
    expect(json(mine).messages[0].message).toEqual(msg);
    expect((await app.inject(signedRequest(m(1).keys, 'GET', url(sessionId, m(2).info.identifier)))).statusCode).toBe(
      403,
    );
    expect(
      (await app.inject(signedRequest(m(2).keys, 'GET', url('00'.repeat(32), m(2).info.identifier)))).statusCode,
    ).toBe(404);
    const st = await app.inject(signedRequest(m(3).keys, 'GET', `/frost/sessions/${sessionId}/status`));
    expect(json(st).status).toBe('aborted'); // the abort closed the session
    // a replayed request (same bytes, same nonce) is refused
    const again = signedRequest(m(2).keys, 'GET', url(sessionId, m(2).info.identifier));
    expect((await app.inject(again)).statusCode).toBe(200);
    expect((await app.inject(again)).statusCode).toBe(401);
  });

  it('a signing session takes the pair the opener names, and only two distinct participants (I-28)', async () => {
    const parts = w.participants();
    const open = (pair: unknown) =>
      app.inject(
        signedRequest(m(1).keys, 'POST', `/deals/${w.dealId}/frost-sessions`, {
          slot: 'A',
          purpose: 'sign',
          participants: parts,
          pair,
        }),
      );
    const ok = await open([parts[0]?.identifier, parts[2]?.identifier]);
    expect(ok.statusCode, ok.body).toBe(200);
    expect((await w.relay.status(json(ok).sessionId)).pair).toEqual([parts[0]?.identifier, parts[2]?.identifier]);
    expect((await open([parts[0]?.identifier, parts[0]?.identifier])).statusCode).toBe(400);
    expect((await open([parts[0]?.identifier, '09'.repeat(32)])).statusCode).toBe(400);
  });

  it('an opener who is not a holder of the session is refused', async () => {
    const outsider = await a.newPhone();
    const r = await app.inject(
      signedRequest(outsider.keys, 'POST', `/deals/${w.dealId}/frost-sessions`, {
        slot: 'A',
        purpose: 'dkg',
        participants: w.participants(),
      }),
    );
    expect(r.statusCode).toBe(403);
  });
});

describe('agent routes', () => {
  it('serves the key list and runs a client recovery start, get and cancel', async () => {
    const list = await app.inject({ method: 'GET', url: '/.well-known/legx/recovery-agent-keys.json' });
    expect(list.statusCode).toBe(200);
    expect(json(list).anchorTx).toBe('AB'.repeat(32));

    const phone = await a.newPhone();
    const key = phone.keys.keyId;
    const proof = a.proof({ newKeyId: key });
    const start = await app.inject(
      signedRequest(phone.keys, 'POST', `/deals/${w.dealId}/recoveries`, {
        kind: 'client',
        slot: 'A',
        newKeyId: key,
        proof,
      }),
    );
    expect(start.statusCode, start.body).toBe(200);
    const { recoveryId, readyAt, state } = json(start);
    expect(state).toBe('waiting');
    expect(readyAt).toBe(Math.floor((T0 + 72 * HOUR) / 1000) - 946_684_800);
    // another key may not start a recovery for this new key
    const other = await a.newPhone();
    const bad = await app.inject(
      signedRequest(other.keys, 'POST', `/deals/${w.dealId}/recoveries`, {
        kind: 'client',
        slot: 'A',
        newKeyId: key,
        proof,
      }),
    );
    expect(bad.statusCode).toBe(403);
    const get = await app.inject(signedRequest(phone.keys, 'GET', `/recoveries/${recoveryId}?dealId=${w.dealId}`));
    expect(json(get).state).toBe('waiting');
    // the old device cancels
    const old = m(2);
    const cancelSig = hex(
      ed25519.sign(
        recoveryCancelMessage({ recoveryId, slot: 'A', status: 'pending', startedAt: T0, records: [] }),
        old.keys.edSecret,
      ),
    );
    const cancelBody = { dealId: w.dealId, cancelSig, oldDevicePub: hex(old.info.edPub).toUpperCase() };
    const wrong = await app.inject(
      signedRequest(old.keys, 'POST', `/recoveries/${recoveryId}/cancel`, {
        ...cancelBody,
        cancelSig: '00'.repeat(64),
      }),
    );
    expect(wrong.statusCode, wrong.body).toBe(422);
    const ok = await app.inject(signedRequest(old.keys, 'POST', `/recoveries/${recoveryId}/cancel`, cancelBody));
    expect(ok.statusCode, ok.body).toBe(200);
    expect(json(ok).state).toBe('cancelled');
  });

  // I-3.7-f: authenticate before parsing, and take the deal from the recovery itself (the contract path has no dealId).
  it('an unsigned request is 401 before any body check, and get needs no dealId query', async () => {
    const phone = await a.newPhone();
    const start = await app.inject(
      signedRequest(phone.keys, 'POST', `/deals/${w.dealId}/recoveries`, {
        kind: 'client',
        slot: 'A',
        newKeyId: phone.keys.keyId,
        proof: a.proof({ newKeyId: phone.keys.keyId }),
      }),
    );
    const { recoveryId } = json(start);
    const garbage = { method: 'POST' as const, url: `/recoveries/${recoveryId}/cancel`, payload: 'not json' };
    const unsigned = await app.inject({ ...garbage, headers: { 'content-type': 'application/json' } });
    expect(unsigned.statusCode, unsigned.body).toBe(401);
    const get = await app.inject(signedRequest(phone.keys, 'GET', `/recoveries/${recoveryId}`));
    expect(get.statusCode, get.body).toBe(200);
    expect(json(get).state).toBe('waiting');
    const stranger = await app.inject({ method: 'GET', url: `/recoveries/${recoveryId}` });
    expect(stranger.statusCode).toBe(401);
  });

  // I-S-F1: the operations account signs a message bound to the deal, the slot, the new key and the ledger index,
  // outside the body. Source: DESIGN 6.4 "Lawyer recovery"; contracts LAWYER_RECOVERY_TAG.
  it('a lawyer recovery starts only with an operations signature over this deal, slot, new key and ledger', async () => {
    const consoleKey = makeMember(1, 'LA', 'console');
    await pinEnrollmentKey(w.deps, w.dealId, {
      key_id: consoleKey.keys.keyId,
      slot: 'LA',
      holder_role: 'console',
      ed25519_pub: hex(consoleKey.info.edPub.slice(1)),
      mldsa65_pub: toBase64(consoleKey.info.pqPub),
      valid_from: 0,
    } as never);
    const opsSecret = ed25519.utils.randomSecretKey();
    const opsPub = `ED${hex(ed25519.getPublicKey(opsSecret)).toUpperCase()}`;
    a.deal.opsAccount.LA = deriveAddress(opsPub);
    const newKeyId = consoleKey.keys.keyId;
    const start = (sig: Uint8Array, ledgerIndex = 1000) =>
      app.inject(
        signedRequest(consoleKey.keys, 'POST', `/deals/${w.dealId}/recoveries`, {
          kind: 'lawyer',
          slot: 'LA',
          newKeyId,
          ledgerIndex,
          opsSig: { opsPub, sig: hex(sig) },
        }),
      );
    const unrelated = ed25519.sign(new TextEncoder().encode('some unrelated message the firm signed'), opsSecret);
    expect((await start(unrelated)).statusCode).toBe(422);
    const otherDeal = lawyerRecoveryMessage('0192f0c8-3c4e-7a2b-8c3d-4e5f6a7b8c9d', 'LA', newKeyId, 1000);
    expect((await start(ed25519.sign(otherDeal, opsSecret))).statusCode).toBe(422);
    const stale = lawyerRecoveryMessage(w.dealId, 'LA', newKeyId, 900);
    expect((await start(ed25519.sign(stale, opsSecret), 900)).statusCode).toBe(401);
    const good = await start(ed25519.sign(lawyerRecoveryMessage(w.dealId, 'LA', newKeyId, 1000), opsSecret));
    expect(good.statusCode, good.body).toBe(200);
    expect(json(good).state).toBe('waiting');
  });
});
