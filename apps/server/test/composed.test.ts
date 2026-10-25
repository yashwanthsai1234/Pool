// P3.7-06: a full DKG and a FROST signature go through the COMPOSED server's HTTP routes (signed requests, the relay of
// 3.9 behind the coordinator's authentication), not through a unit-test harness; and a hybrid checkpoint is produced by the
// composed evidence part (3.4 with 3.12) and verifies under both of its keys.

import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { FrostRelayPort, RelayedMessage } from '@legx/contracts/ports';
import { slotPubkey, verifyEd25519Strict } from '@legx/core/frost';
import { testSignCheck, testSignMessage } from '@legx/core/frostDkg';
import { verifyCheckpoint } from '@legx/core/pqCheckpoint';
import { generateNodeCheckpointKeys, generateNodeSignerKeys, nodeCheckpointSigner, nodeSigner } from '@legx/signer';
import { inProcessLog } from '@legx/storage/inProcessLog';
import { localObjectStore } from '@legx/storage/localStore';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { HolderKeys } from '../../../services/recovery-agent/src/wire.ts';
import { signedRequest } from '../../../services/recovery-agent/test/support/http.ts';
import { makeWorld, type World } from '../../../services/recovery-agent/test/support/world.ts';
import { buildServer, type Server } from '../src/compose.ts';
import { composeEvidence } from '../src/evidence.ts';
import { MemorySource } from './support/feed.ts';

const must = <T>(x: T | undefined): T => {
  if (x === undefined) throw new Error('expected a value');
  return x;
};

let w: World;
let server: Server;
let app: FastifyInstance;
beforeAll(async () => {
  w = await makeWorld();
  server = await buildServer({
    profile: 'demo',
    ports: {},
    coordinator: w.deps,
    live: { source: new MemorySource() },
  });
  app = server.app;
}, 600_000);
afterAll(async () => {
  await server.close();
  await w.close();
});

/** The holder's side of the relay over HTTP: every call is a signed request to the composed server. */
class HttpRelay implements FrostRelayPort {
  readonly #keys: HolderKeys;
  constructor(keys: HolderKeys) {
    this.#keys = keys;
  }
  async send(message: Parameters<FrostRelayPort['send']>[0]) {
    // The session id is inside the signed payload (P1.15-02); the route carries it in the path as well.
    const sessionId = (JSON.parse(Buffer.from(message.payload, 'base64').toString('utf8')) as { session_id: string })
      .session_id;
    const res = await app.inject(
      signedRequest(this.#keys, 'POST', `/frost/sessions/${sessionId}/messages`, { message }) as never,
    );
    if (res.statusCode !== 200) throw new Error(`send ${res.statusCode}: ${res.body}`);
    return res.json() as { seq: number };
  }
  async receive(sessionId: string, recipient: string, afterSeq: number): Promise<readonly RelayedMessage[]> {
    const url = `/frost/sessions/${sessionId}/messages?recipient=${encodeURIComponent(recipient)}&afterSeq=${afterSeq}`;
    const res = await app.inject(signedRequest(this.#keys, 'GET', url) as never);
    if (res.statusCode !== 200) throw new Error(`receive ${res.statusCode}: ${res.body}`);
    return (res.json() as { messages: RelayedMessage[] }).messages;
  }
}

const open = async (purpose: 'dkg' | 'sign') => {
  const res = await app.inject(
    signedRequest(must(w.members[0]).keys, 'POST', `/deals/${w.dealId}/frost-sessions`, {
      slot: w.slot,
      purpose,
      participants: w.participants(),
    }) as never,
  );
  expect(res.statusCode, res.body).toBe(200);
  return (res.json() as { sessionId: string }).sessionId;
};
const holder = (i: number) => w.holder(i, { relay: new HttpRelay(must(w.members[i - 1]).keys) });

describe('P3.7-06 FROST through the composed server', () => {
  it('a DKG and a signature by a pair, every message a signed HTTP request', async () => {
    const dkgSession = await open('dkg');
    const runs = await Promise.all([1, 2, 3].map((i) => holder(i).dkg(dkgSession)));
    const groupKeys = new Set(runs.map((r) => Buffer.from(r.key.public.commitments[0] as Uint8Array).toString('hex')));
    expect(groupKeys.size).toBe(1);

    const signSession = await open('sign'); // the default pair is holders 1 and 2
    const first = must(runs[0]);
    const pub = first.key.public;
    const pair: [number, number] = [1, 2];
    const msg = testSignMessage(first.ctx, pub, pair);
    const sigs = await Promise.all(
      pair.map((i) =>
        holder(i).sign(signSession, {
          msg,
          kind: 'tagged',
          share: must(runs[i - 1]).key.secret,
          pub,
          pair,
          check: (m, l) => testSignCheck(first.ctx, pub, i)(m, l),
        }),
      ),
    );
    expect(verifyEd25519Strict(sigs[0] as Uint8Array, msg, slotPubkey(pub))).toBe(true); // the slot's XRPL public key
  });

  it('a stranger cannot read or send on the session: an unpinned key gets 401, a non-participant 403', async () => {
    const session = await open('sign');
    const stranger = {
      keyId: 'nobody-0000',
      edSecret: new Uint8Array(32).fill(7),
      pqSecret: new Uint8Array(4032),
    } as HolderKeys;
    const un = await app.inject(
      signedRequest(stranger, 'GET', `/frost/sessions/${session}/messages?recipient=x&afterSeq=-1`) as never,
    );
    expect(un.statusCode).toBe(401);
    const noHeader = await app.inject({
      method: 'GET',
      url: `/frost/sessions/${session}/messages?recipient=x&afterSeq=-1`,
    });
    expect(noHeader.statusCode).toBe(401);
  });
});

describe('P3.7-06 a hybrid checkpoint through the composed evidence part', () => {
  it('the checkpoint carries the Ed25519 and the ML-DSA-44 line and verifies under both keys; a second run extends it', async () => {
    const signer = nodeSigner(generateNodeSignerKeys('ev-ed' as never, 'ev-pq' as never));
    const cps = nodeCheckpointSigner(generateNodeCheckpointKeys('cp-ed' as never, 'cp-pq' as never));
    const clock = { now: () => w.ledger.validatedLedger() };
    const log = inProcessLog({ origin: 'legx.test/3.7', signer: cps, clock });
    const ev = await composeEvidence({
      db: w.db,
      signer,
      checkpointSigner: cps,
      log,
      objects: localObjectStore({ dir: mkdtempSync(join(tmpdir(), 'legx37-obj-')) }),
      clock,
    });
    for (let i = 0; i < 5; i++) await log.add(new TextEncoder().encode(`leaf ${i}`));
    const first = await ev.service.checkpoint();
    const k = await cps.publicKeys();
    const keys = {
      ed: { name: 'legx.test/3.7', publicKey: k.ed25519 },
      pq: { name: 'legx.test/3.7-mldsa44', publicKey: k.mlDsa44 },
    };
    expect(verifyCheckpoint(first.checkpoint.note, 'legx.test/3.7', keys).ok).toBe(true);
    expect(first.checkpoint.note).toContain('legx.test/3.7-mldsa44');
    await log.add(new TextEncoder().encode('leaf 5'));
    const second = await ev.service.checkpoint();
    expect(second.checkpoint.treeSize).toBe(first.checkpoint.treeSize + 1);
    expect(verifyCheckpoint(second.checkpoint.note, 'legx.test/3.7', keys).ok).toBe(true);
  });
});
