// Task 4.6: the relay for the phone's sealed bundle. Unit cases on a bare Fastify, then an end to end run: the simulated
// sender posts to the COMPOSED server over real HTTP and the console receiver opens what it polls.
import { createSession, receiveChip, simSend } from '@legx/chip-link';
import { presenceMsg } from '@legx/core/attest';
import { passportCommitment } from '@legx/core/dealcore';
import { passportRecord } from '@legx/core/passport/passiveAuth';
import { makePassport, makeTestPki } from '@legx/fixtures';
import { base64urlnopad } from '@scure/base';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { makeWorld, type World } from '../../../services/recovery-agent/test/support/world.ts';
import { registerChipLink } from '../src/chipLink.ts';
import { buildServer, type Server } from '../src/compose.ts';
import { MemorySource } from './support/feed.ts';

const SID = 'ab'.repeat(16);
const body = { sessionId: SID, enc: 'AAEC', ct: 'AwQF' };
const bare = async (opts = {}): Promise<FastifyInstance> => {
  const app = Fastify();
  app.addContentTypeParser('application/json', { parseAs: 'buffer' }, (_r, b, done) => done(null, b));
  registerChipLink(app, opts);
  return app;
};
const post = (app: FastifyInstance, id: string, b: unknown) =>
  app.inject({
    method: 'POST',
    url: `/chip-link/${id}`,
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify(b),
  });

describe('chip-link relay', () => {
  it('relays a bundle once to the console, then forgets it', async () => {
    const app = await bare();
    expect((await app.inject({ method: 'PUT', url: `/chip-link/${SID}` })).statusCode).toBe(204);
    expect((await app.inject({ url: `/chip-link/${SID}` })).statusCode).toBe(204);
    expect((await post(app, SID, body)).statusCode).toBe(204);
    const got = await app.inject({ url: `/chip-link/${SID}` });
    expect(got.json()).toEqual(body);
    expect((await app.inject({ url: `/chip-link/${SID}` })).statusCode).toBe(404);
  });
  it('refuses a session the console never opened, and a path/body mismatch', async () => {
    const app = await bare();
    expect((await post(app, SID, body)).statusCode).toBe(404);
    await app.inject({ method: 'PUT', url: `/chip-link/${SID}` });
    expect((await post(app, SID, { ...body, sessionId: 'cd'.repeat(16) })).statusCode).toBe(400);
    expect((await post(app, SID, { ...body, enc: 'not base64!' })).statusCode).toBe(400);
    expect((await post(app, 'zz', body)).statusCode).toBe(400);
  });
  it('refuses a replayed post, even with different bytes', async () => {
    const app = await bare();
    await app.inject({ method: 'PUT', url: `/chip-link/${SID}` });
    expect((await post(app, SID, body)).statusCode).toBe(204);
    expect((await post(app, SID, { ...body, ct: 'BBBB' })).statusCode).toBe(409);
    expect((await app.inject({ url: `/chip-link/${SID}` })).json()).toEqual(body);
  });
  it('expires after the TTL and bounds the number of sessions', async () => {
    let t = 0;
    const app = await bare({ ttlMs: 1000, maxSessions: 1, now: () => t });
    await app.inject({ method: 'PUT', url: `/chip-link/${SID}` });
    expect((await app.inject({ method: 'PUT', url: `/chip-link/${'cd'.repeat(16)}` })).statusCode).toBe(429);
    t = 1001;
    expect((await post(app, SID, body)).statusCode).toBe(404);
  });
});

const RIPPLE_EPOCH = 946_684_800;
const MRZ = {
  documentNumber: 'L898902C3',
  surname: 'ERIKSSON',
  givenNames: 'ANNA MARIA',
  dateOfBirth: '740812',
  sex: 'F',
  dateOfExpiry: '340415',
} as const;

describe('chip-link end to end over the composed server', () => {
  let w: World;
  let server: Server;
  let base: string;
  beforeAll(async () => {
    w = await makeWorld();
    server = await buildServer({
      profile: 'demo',
      ports: {},
      coordinator: w.deps,
      live: { source: new MemorySource() },
    });
    base = await server.app.listen({ port: 0, host: '127.0.0.1' });
  }, 600_000);
  afterAll(async () => {
    await server.close();
    await w.close();
  });

  it('simSend posts; the server sees only ciphertext; the console opens it and the checks pass', async () => {
    const seed = new Uint8Array(32).fill(9);
    const pki = makeTestPki({ seed });
    const passport = makePassport({ pki, mrz: MRZ, seed });
    const salt = new Uint8Array(32).fill(0x5a);
    const msg = presenceMsg(new Uint8Array(32).fill(1), 'A', new Uint8Array(32).fill(2), new Uint8Array(32).fill(3));
    const session = await createSession(msg);
    const id = Buffer.from(session.sessionId).toString('hex');
    expect((await fetch(`${base}/chip-link/${id}`, { method: 'PUT' })).status).toBe(204);

    const sealed = await simSend(session.qr, { passport, aaKey: passport.aaKey });
    const wire = { sessionId: id, enc: base64urlnopad.encode(sealed.enc), ct: base64urlnopad.encode(sealed.ct) };
    const send = () =>
      fetch(`${base}/chip-link/${id}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(wire),
      });
    expect((await send()).status).toBe(204);
    expect((await send()).status).toBe(409); // replay

    const got = (await (await fetch(`${base}/chip-link/${id}`)).json()) as typeof wire;
    // No plaintext on the wire: the DG1 bytes (which hold the MRZ) appear in neither field.
    const mrzBytes = Buffer.from(passport.dg1).toString('base64url');
    expect(JSON.stringify(got)).not.toContain(mrzBytes.slice(8, 30));
    const r = await receiveChip(
      session,
      { enc: base64urlnopad.decode(got.enc), ct: base64urlnopad.decode(got.ct) },
      {
        trustList: [pki.csca.cert],
        atTime: Date.parse('2027-06-01T12:00:00Z') / 1000 - RIPPLE_EPOCH,
        salt,
        commitment: passportCommitment(passportRecord(passport.dg1, passport.sod), salt),
        presenceMsg: msg,
      },
    );
    expect(r.ok).toBe(true);
  });
});
