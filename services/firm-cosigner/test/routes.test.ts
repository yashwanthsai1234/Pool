// The HSM's signing route `firmHsm.sign` (I-26, I-28): only the slot's own lawyer asks, the body must match the
// contract, and the cosigner's own checks (operations signature, seal, pair) decide and are logged.
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { signedRequest } from '../../recovery-agent/test/support/http.ts';
import type { Member } from '../../recovery-agent/test/support/world.ts';
import { register } from '../src/index.ts';
import { type FirmWorld, makeFirmWorld } from './support/firm.ts';

let fw: FirmWorld;
let app: FastifyInstance;
const errors: unknown[] = [];
beforeAll(async () => {
  fw = await makeFirmWorld();
  app = Fastify();
  await register(app, {
    auth: fw.w.deps,
    recoveries: fw.recoveries,
    keyList: () => ({ bytes: new Uint8Array(), signerPub: new Uint8Array(), sig: new Uint8Array() }),
    cosigner: fw.cos,
    onError: (e) => errors.push(e),
  });
  await app.ready();
}, 120_000);
afterAll(async () => {
  await app.close();
  await fw.w.close();
});

const m = (i: number) => fw.w.members[i - 1] as Member;
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

async function ask(by: Member, over: Record<string, unknown> = {}) {
  const sessionId = await fw.sessionFor([1, 2]);
  const op = fw.operator(sessionId, [1, 2]);
  const body = {
    slot: 'LA',
    sessionId,
    pair: [1, 2],
    seal: fw.seal,
    operator: { opsPub: hex(op.opsPub).toUpperCase(), sig: hex(op.sig) },
    ...over,
  };
  return await app.inject(signedRequest(by.keys, 'POST', `/deals/${fw.w.dealId}/firm-hsm/sign`, body));
}

describe('firmHsm.sign', () => {
  it('refuses every caller but the console of the slot, and a body that does not match the contract', async () => {
    expect((await ask(m(3))).statusCode).toBe(403); // the partner holds a share, but is not the lawyer
    expect((await ask(m(2))).statusCode).toBe(403); // nor is the HSM itself
    expect((await ask(m(1), { pair: [1, 4] })).statusCode).toBe(400);
    expect((await ask(m(1), { message: 'ab'.repeat(32) })).statusCode).toBe(400); // a message without its request
  });

  it("starts the HSM's side; a forged operations signature is refused by the cosigner and logged", async () => {
    const before = (await fw.audit.entries(fw.w.dealId)).length;
    const r = await ask(m(1), { operator: { opsPub: `ED${'11'.repeat(32)}`, sig: '22'.repeat(64) } });
    expect(r.statusCode, r.body).toBe(200);
    expect(JSON.parse(r.body)).toEqual({ status: 'started' });
    await expect.poll(async () => (await fw.audit.entries(fw.w.dealId)).length).toBe(before + 1);
    expect((await fw.audit.entries(fw.w.dealId)).at(-1)?.decision).toBe('refused');
    expect(errors.length).toBeGreaterThan(0);
  });
});
